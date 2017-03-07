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


/* Process PAP packet - pack points the PPP payload */
void processpap(PPPSession *pppSession, uint8_t *p, int l)
{
	char user[MAXUSER];
	char pass[MAXPASS];
	uint16_t hl;
	uint16_t r;

	LOG_HEX(5, "PAP", p, l);
	if (l < 4)
	{
		LOG(1, "Short PAP %u bytes\n", l);
		sessionshutdown(pppSession, "Short PAP packet.");
		return;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, "Length mismatch PAP %u/%u\n", hl, l);
		sessionshutdown(pppSession, "PAP length mismatch.");
		return;
	}
	l = hl;

	if (*p != 1)
	{
		LOG(1, "Unexpected PAP code %d\n", *p);
		sessionshutdown(pppSession, "Unexpected PAP code.");
		return;
	}

	if (pppSession->ppp.phase != Authenticate)
	{
	    	LOG(2, "PAP ignored in %s phase\n", ppp_phase(pppSession->ppp.phase));
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
		LOG(3, "PAP login %s/%s\n", user, pass);
	}

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
			LOG(3, "Already an IP allocated: %s\n",
				fmtaddr(htonl(pppSession->ip_remote), 0));
		}
		else
		{
			LOG(1, "No RADIUS session available to authenticate session...\n");
			sessionshutdown(pppSession, "No free RADIUS sessions.");
		}
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
		sessionshutdown(s, "CHAP timeout.", CDN_ADMIN_DISC, TERM_REAUTHENTICATION_FAILURE);
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


