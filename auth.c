#include "config.h"

#ifdef HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "event.h"
#include "auth.h"
#include "log.h"
#include "constants.h"
#include "common.h"
#include "lcp.h"


/* Send response ACK=2, NAK=3 */
void sendauthresp(PPPSession *pppSession, uint8_t id, uint8_t resp, char *message)
{
	uint8_t b[MAXETHER];
	uint8_t *p = pppoe_makeppp(b, sizeof(b), NULL, 0, pppSession, PPP_PAP, 0, 0, 0);
	if (!p) return;

	*p=resp;
	p[1] = id;
	*(uint16_t *) (p + 2) = htons(5);	// length
	p[4] = 0;				// no message
	pppoe_sess_send(pppSession->pppoeSession, b, 5 + (p - b));
}

/* Process PAP packet - pack points the PPP payload */
void processpap(PPPSession *pppSession, uint8_t *p, int l)
{
	char user[MAXUSER];
	char pass[MAXPASS];
	uint16_t hl;
	uint16_t r;

	LOG_HEX(5, pppSession->pppoeSession, "PAP", p, l);
	if (l < 4)
	{
		LOG(1, pppSession->pppoeSession, "Short PAP %u bytes\n", l);
		sessionshutdown(pppSession, 1, "Short PAP packet.");
		return;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, pppSession->pppoeSession, "Length mismatch PAP %u/%u\n", hl, l);
		sessionshutdown(pppSession, 1, "PAP length mismatch.");
		return;
	}
	l = hl;

	if (pppSession->flags & SESSION_CLIENT) {
		if (*p != 2 && *p != 3)
		{
			LOG(1, pppSession->pppoeSession, "Unexpected PAP code %d\n", *p);
			sessionshutdown(pppSession, 1, "Unexpected PAP code.");
			return;
		}
		if (*p == 2) {
			LOG(3, pppSession->pppoeSession, "Authentication succeeded\n");
			pppSession->flags |= SESSION_AUTHOK;
			(*pppSession->cb)(pppSession, PPPCBACT_AUTHOK);
			pppSession->lcp_authtype=0; // Signal auth complete
			lcp_open(pppSession);
		} else {
			LOG(3, pppSession->pppoeSession, "Authentication failed\n");
			pppSession->flags &= ~SESSION_GOTAUTH;
			pppSession->user[0]='\0';
			pppSession->pass[0]='\0';
			(*pppSession->cb)(pppSession, PPPCBACT_AUTHOK);
		}
		return;
	} else {
		if (*p != 1)
		{
			LOG(1, pppSession->pppoeSession, "Unexpected PAP code %d\n", *p);
			sessionshutdown(pppSession, 1, "Unexpected PAP code.");
			return;
		}

		if (pppSession->ppp.phase != Authenticate)
		{
			LOG(2, pppSession->pppoeSession, "PAP ignored in %s phase\n", ppp_phase(pppSession->ppp.phase));
			return;
		}

		{
			uint8_t *b = p;
			b += 4;
			user[0] = pass[0] = 0;
			if (*b && *b < sizeof(user))
			{
				memcpy(user, b + 1, *b);
				user[*b] = 0;
				b += 1 + *b;
				if (*b && *b < sizeof(pass))
				{
					memcpy(pass, b + 1, *b);
					pass[*b] = 0;
				}
			}
			LOG(3, pppSession->pppoeSession, "PAP login %s/%s\n", user, pass);
			if ((pppSession->flags & SESSION_AUTHOK)==0) {
				/* Not authenticated yet */
				if ((pppSession->flags & SESSION_GOTAUTH)==0) {
					strcpy(pppSession->user, user);
					strcpy(pppSession->pass, pass);
					pppSession->flags |= SESSION_GOTAUTH;
				}
				if ((strcmp(pppSession->user, user)==0 && strcmp(pppSession->pass, pass)==0)) {
					LOG(3, pppSession->pppoeSession, "Waiting for auth (from elsewhere)\n");
					(*pppSession->cb)(pppSession, PPPCBACT_AUTHREQ);
				}
				return; // Silently ignore
			} else if (strcmp(pppSession->user, user) || strcmp(pppSession->pass, pass)) {
				/* Auth failed */
				LOG(3, pppSession->pppoeSession, "Authentication failed\n");
				sendauthresp(pppSession, p[1], 3, "Auth Failed");
				return;
			} else {
				LOG(3, pppSession->pppoeSession, "Authentication succeeded\n");
				sendauthresp(pppSession, p[1], 2, "Auth Suceeded");
				pppSession->lcp_authtype=0; // Signal auth complete
				lcp_open(pppSession);
				return;
			}
		}
	}
	// Shouldn't get here
	return;

	// TODO - improve this hack
	pppSession->ip_remote=htonl(0x01010102);
	if (pppSession->ip_remote /* || !(r = radiusnew(s)) */)
	{
		// respond now, either no RADIUS available or already authenticated
		uint8_t b[MAXETHER];
		uint8_t id = p[1];
		uint8_t *p = pppoe_makeppp(b, sizeof(b), NULL, 0, pppSession, PPP_PAP, 0, 0, 0);
		if (!p) return;

		if (pppSession->ip_remote)
			*p = 2;				// ACK
		else
			*p = 3;				// cant authorise
		p[1] = id;
		*(uint16_t *) (p + 2) = htons(5);	// length
		p[4] = 0;				// no message
		pppoe_sess_send(pppSession->pppoeSession, b, 5 + (p - b));

		if (pppSession->ip_remote)
		{
			LOG(3, pppSession->pppoeSession, "Already an IP allocated: %s\n",
				fmtaddr(htonl(pppSession->ip_remote), 0));
		}
#if 0
		else
		{
			LOG(1, pppSession->pppoeSession, "No RADIUS session available to authenticate session...\n");
			sessionshutdown(pppSession, "No free RADIUS sessions.");
		}
#endif
	}
#if 0
	else
	{
		// Run PRE_AUTH plugins
		struct param_pre_auth packet = { &tunnel[t], &session[s], strdup(user), strdup(pass), PPPPAP, 1 };
		run_plugins(PLUGIN_PRE_AUTH, &packet);
		if (!packet.continue_auth)
		{
			LOG(3, s, t, "A plugin rejected PRE_AUTH\n");
			if (packet.username) free(packet.username);
			if (packet.password) free(packet.password);
			return;
		}

		strncpy(session[s].user, packet.username, sizeof(session[s].user) - 1);
		strncpy(radius[r].pass, packet.password, sizeof(radius[r].pass) - 1);

		free(packet.username);
		free(packet.password);

		radius[r].id = p[1];
		LOG(3, s, t, "Sending login for %s/%s to RADIUS\n", user, pass);
		if ((session[s].mrru) && (!first_session_in_bundle(s)))
			radiussend(r, RADIUSJUSTAUTH);
		else
			radiussend(r, RADIUSAUTH);
	}
#endif
}

/* Process CHAP packet - pack points the PPP payload */
void processchap(PPPSession *pppSession, uint8_t *p, int l)
{
}

// send a CHAP challenge
void sendchap(PPPSession *pppSession)
{
	uint8_t b[MAXETHER];
	uint16_t r;
	uint8_t *q;

#if 0
	CSTAT(sendchap);

	r = radiusnew(s);
	if (!r)
	{
		LOG(1, s, t, "No RADIUS to send challenge\n");
		STAT(tunnel_tx_errors);
		return;
	}

	LOG(1, s, t, "Send CHAP challenge\n");

	radius[r].chap = 1;		// CHAP not PAP
	radius[r].id++;
	if (radius[r].state != RADIUSCHAP)
		radius[r].try = 0;

	radius[r].state = RADIUSCHAP;
	radius[r].retry = backoff(radius[r].try++);
	if (radius[r].try > 5)
	{
		sessionshutdown(s, 1, "CHAP timeout.", CDN_ADMIN_DISC, TERM_REAUTHENTICATION_FAILURE);
		STAT(tunnel_tx_errors);
		return ;
	}
	q = makeppp(b, sizeof(b), 0, 0, s, t, PPPCHAP, 0, 0, 0);
	if (!q) return;

	*q = 1;					// challenge
	q[1] = radius[r].id;			// ID
	q[4] = 16;				// value size (size of challenge)
	memcpy(q + 5, radius[r].auth, 16);	// challenge
	strcpy((char *) q + 21, config->multi_n_hostname[tunnel[t].indexudp][0]?config->multi_n_hostname[tunnel[t].indexudp]:hostname);	// our name
	*(uint16_t *) (q + 2) = htons(strlen(config->multi_n_hostname[tunnel[t].indexudp][0]?config->multi_n_hostname[tunnel[t].indexudp]:hostname) + 21); // length
	tunnelsend(b, strlen(config->multi_n_hostname[tunnel[t].indexudp][0]?config->multi_n_hostname[tunnel[t].indexudp]:hostname) + 21 + (q - b), t); // send it
#endif
}

// send a PAP auth
void sendpap(PPPSession *pppSession)
{
	uint8_t b[MAXETHER];
	uint8_t *q, *p;

	if (strlen(pppSession->user)==0) {
		LOG(3, pppSession->pppoeSession, "No PAP auth available (yet)\n");
		return;
	}

	LOG(1, pppSession->pppoeSession, "Send PAP auth: %s/%s\n", pppSession->user, pppSession->pass);
	q = pppoe_makeppp(b, sizeof(b), NULL, 0, pppSession, PPP_PAP, 0, 0, 0);
	if (!q) return;

	*q = 1;					// auth request
	q[1] = 1;				// ID
	p=q+4;
	*p = strlen(pppSession->user);		// size of peer-id (username)
	memcpy(p + 1, pppSession->user, strlen(pppSession->user)); // peer-id
	p+=strlen(pppSession->user)+1;
	*p = strlen(pppSession->pass);		// size of peer-id (username)
	memcpy(p + 1, pppSession->pass, strlen(pppSession->pass)); // peer-id
	p+=strlen(pppSession->pass)+1;
	*(uint16_t *) (q + 2) = htons(p-q); // length
	pppoe_sess_send(pppSession->pppoeSession, b, p-b);
}

/* Signal that the client can now authenticate */
void set_auth(PPPSession *pppSession)
{
	LOG(3, pppSession->pppoeSession, "LCP: state %s, phase %s\n", ppp_state(pppSession->ppp.lcp), ppp_phase(pppSession->ppp.phase));
	if (pppSession->ppp.phase == Authenticate) {
		if ((pppSession->flags & SESSION_GOTAUTH)==0) {
			do_auth(pppSession);
		}
	} else {
		LOG(3, pppSession->pppoeSession, "LCP: Skip set_auth, not in Authentication phase\n");
	}
}

void do_auth(PPPSession *pppSession)
{
	LOG(3, pppSession->pppoeSession, "LCP: state %s, phase %s\n", ppp_state(pppSession->ppp.lcp), ppp_phase(pppSession->ppp.phase));
	restart_timer(pppSession, lcp);
	if (pppSession->ppp.phase == Authenticate) {
		// Fetch username/password if required
		(*pppSession->cb)(pppSession, PPPCBACT_AUTHREQ);
		if (pppSession->flags & SESSION_CLIENT) {
			if (pppSession->lcp_authtype == AUTHPAP) {
				sendpap(pppSession);
			}
		} else {
			if (pppSession->lcp_authtype == AUTHCHAP)
				sendchap(pppSession);
		}
	} else {
		LOG(3, pppSession->pppoeSession, "LCP: Skip auth, not in Authentication phase\n");
	}
}
