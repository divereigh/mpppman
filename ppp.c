#include "config.h"

#ifdef HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "common.h"
#include "log.h"
#include "ppp.h"
#include "lcp.h"
#include "constants.h"
#include "event.h"
#include "auth.h"
#include "ip.h"
#include "ipv6.h"

PPPSession ppp_sessions[MAX_PPP_SESSION];
int ppp_restart_time=5;
int ppp_max_failure=5;
int ppp_max_configure=10;
int radius_authtypes=AUTHPAP;
int radius_authprefer=AUTHPAP;
int MRU=1462;

/* Find a session that has the given session id, 0 will find a free session
*/
PPPSession *ppp_find_free_session()
{
	int i;

	for (i=0; i<MAX_PPP_SESSION; i++) {
		if (ppp_sessions[i].pppoeSession==NULL) {
			return(&ppp_sessions[i]);
		}
	}
	return(NULL);
}

static void ppp_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	struct cpStruct *cp=(struct cpStruct *) arg;
	PPPSession *pppSession=cp->pppSession;
	if (cp==&pppSession->lcp) {
		int next_state = pppSession->ppp.lcp;
		LOG(3, pppSession->pppoeSession, "Got a timeout event for LCP\n");
		switch (pppSession->ppp.lcp)
		{
		case RequestSent:
		case AckReceived:
			next_state = RequestSent;

		case AckSent:
			if (pppSession->lcp.conf_sent < ppp_max_configure)
			{
				LOG(3, pppSession->pppoeSession, "No ACK for LCP ConfigReq... resending\n");
				sendLCPConfigReq(pppSession);
				change_state(pppSession, lcp, next_state);
			}
			else
			{
				sessionshutdown(pppSession, 1, "No response to LCP ConfigReq.");
			}
			break;

		case Closing:
			LOG(3, pppSession->pppoeSession, "Timer expired on close - kill the session\n");
			sessionkill(pppSession);
			break;
		}

	} else if (cp==&pppSession->ipcp) {
		LOG(3, pppSession->pppoeSession, "Got a timeout event for IPCP\n");
	} else if (cp==&pppSession->ipv6cp) {
		LOG(3, pppSession->pppoeSession, "Got a timeout event for IPV6CP\n");
	} else if (cp==&pppSession->ccp) {
		LOG(3, pppSession->pppoeSession, "Got a timeout event for CCP\n");
	} else {
		LOG(3, pppSession->pppoeSession, "Got an unknown timeout event\n");
	}
}

/* Allocate and fill new session - returns PPPSession */
PPPSession * ppp_new_session(const PPPoESession *pppoeSession, uint8_t flags)
{
	uint16_t sid;
	int i;
	PPPSession *pppSession;

	if ((pppSession=ppp_find_free_session()) == NULL) {
		LOG(0, pppoeSession, "No free PPPSession available\n");
	}
	
	pppSession->pppoeSession=pppoeSession;

	// session[sid].opened = time_now;
	// session[sid].last_packet = session[sid].last_data = time_now;

	//strncpy(session[sid].called, called, sizeof(session[sid].called) - 1);
	//strncpy(session[sid].calling, calling, sizeof(session[sid].calling) - 1);

	pppSession->ppp.phase = Establish;
	pppSession->ppp.lcp = Starting;

	pppSession->magic = time_now; // set magic number
	pppSession->mru = PPPoE_MRU; // default
	pppSession->flags = flags;

	// start LCP - prefer PAP
	pppSession->lcp_authtype = AUTHPAP;
	// TODO - Need to calculate this properly
	pppSession->ppp_mru = PPPoE_MRU; // Should be MRU;

	if ((pppSession->flags & SESSION_CLIENT)) {
		// Set multilink options before sending initial LCP packet
		pppSession->mp_mrru = 1614;
		// pppSession->mp_epdis = ntohl(config->iftun_address ? config->iftun_address : my_address);
		pppSession->mp_epdis = htonl(0x01010101);
	}

	// sendlcp(pppSession);
	// change_state(pppSession, lcp, RequestSent);

	/* Put links back to the main session so that
	** we can find the main session when handed a '??cp' address
	*/
	pppSession->lcp.pppSession=pppSession;
	pppSession->ipcp.pppSession=pppSession;
	pppSession->ipv6cp.pppSession=pppSession;
	pppSession->ccp.pppSession=pppSession;

	pppSession->lcp.timerEvent=newTimer(ppp_timer_cb, &pppSession->lcp);
	pppSession->ipcp.timerEvent=newTimer(ppp_timer_cb, &pppSession->ipcp);
	pppSession->ipv6cp.timerEvent=newTimer(ppp_timer_cb, &pppSession->ipv6cp);
	pppSession->ccp.timerEvent=newTimer(ppp_timer_cb, &pppSession->ccp);
	return(pppSession);
}

// fill in a PPPOE message with a PPP frame,
// returns start of PPP frame
uint8_t *pppoe_makeppp(uint8_t *b, int size, uint8_t *p, int l, const PPPSession *pppSession,
						uint16_t mtype, uint8_t prio, int bid, uint8_t mp_bits)
{
	uint16_t type = mtype;
	uint8_t *start = b;
	uint8_t *pppoe_hdr = b + ETH_HLEN;
	//struct pppoe_hdr *hdr = (struct pppoe_hdr *)(b + ETH_HLEN);

	if (size < 28) // Need more space than this!!
	{
		LOG(0, pppSession->pppoeSession, "pppoe_makeppp buffer too small for pppoe header (size=%d)\n", size);
		return NULL;
	}

	// 14 bytes ethernet Header + 6 bytes header pppoe
	b= pppoe_session_header(b, pppSession->pppoeSession);

	// Check whether this session is part of multilink
#if 0
	if (bid)
	{
		if (bundle[bid].num_of_links > 1)
			type = PPPMP; // Change PPP message type to the PPPMP
		else
			bid = 0;
	}
#endif

	*(uint16_t *) b = htons(type);
	b += 2;
	pppoe_incr_header_length(pppoe_hdr, 2);

#if 0
	if (bid)
	{
		// Set the sequence number and (B)egin (E)nd flags
		if (session[s].mssf)
		{
			// Set the multilink bits
			uint16_t bits_send = mp_bits;
			*(uint16_t *) b = htons((bundle[bid].seq_num_t & 0x0FFF)|bits_send);
			b += 2;
			pppoe_incr_header_length(pppoe_hdr, 2);
		}
		else
		{
			*(uint32_t *) b = htonl(bundle[bid].seq_num_t);
			// Set the multilink bits
			*b = mp_bits;
			b += 4;
			pppoe_incr_header_length(pppoe_hdr, 4);
		}

		bundle[bid].seq_num_t++;

		// Add the message type if this fragment has the begin bit set
		if (mp_bits & MP_BEGIN)
		{
			//*b++ = mtype; // The next two lines are instead of this 
			*(uint16_t *) b = htons(mtype); // Message type
			b += 2;
			pppoe_incr_header_length(pppoe_hdr, 2);
		}
	}
#endif

	if ((b - start) + l > size)
	{
		LOG(0, pppSession->pppoeSession, "pppoe_makeppp would overflow buffer (size=%d, header+payload=%td)\n", size, (b - start) + l);
		return NULL;
	}

	// Copy the payload
	if (p && l)
	{
		memcpy(b, p, l);
		pppoe_incr_header_length(pppoe_hdr, l);
	}

	return b;
}


/* Process CCP packet - pack points the PPP payload */
void processccp(PPPSession *pppSession, uint8_t *pack, int size)
{
}

/* Process MP packet - pack points the PPP payload */
void processmp(PPPSession *pppSession, uint8_t *pack, int size)
{
}

void protoreject(PPPSession *pppSession, uint8_t *pack, int size, uint16_t proto)
{
}

/* Process PPP packet - pack points the PPP payload */
void processPPP(PPPSession *pppSession, uint8_t *pack, int size)
{
	uint16_t proto;
	
	if (size > 2 && pack[0] == 0xFF && pack[1] == 0x03)
	{	// HDLC address header, discard
		LOG(5, pppSession->pppoeSession, "processSession: HDLC address header, discard\n");
		pack += 2;
		size -= 2;
	}

	if (size < 2)
	{
		LOG(3, pppSession->pppoeSession, "Error process_pppoe_sess: Short ppp length %d\n", size);
		return;
	}
	if (*pack & 1)
	{
		/* No idea what this is - DAI */
		proto = *pack++;
		size--;
	}
	else
	{
		proto = ntohs(*(uint16_t *) pack);
		pack += 2;
		size -= 2;
	}

	if (proto == PPP_PAP)
	{
		pppSession->last_packet = time_now;
		processpap(pppSession, pack, size);
	}
	else if (proto == PPP_CHAP)
	{
		pppSession->last_packet = time_now;
		processchap(pppSession, pack, size);
	}
	else if (proto == PPP_LCP)
	{
		pppSession->last_packet = time_now;
		processlcp(pppSession, pack, size);
	}
	else if (proto == PPP_IPCP)
	{
		pppSession->last_packet = time_now;
		processipcp(pppSession, pack, size);
	}
	else if (proto == PPP_IPV6CP)
	{
		pppSession->last_packet = time_now;
		processipv6cp(pppSession, pack, size);
	}
	else if (proto == PPP_CCP)
	{
		pppSession->last_packet = time_now;
		processccp(pppSession, pack, size);
	}
	else if (proto == PPP_IP)
	{
		pppSession->last_packet = pppSession->last_data = time_now;
		processip(pppSession, pack, size);
	}
	else if (proto == PPP_MP)
	{
		pppSession->last_packet = pppSession->last_data = time_now;
		processmp(pppSession, pack, size);
	}
	else if (proto == PPP_IPV6)
	{
		pppSession->last_packet = pppSession->last_data = time_now;
		processipv6(pppSession, pack, size);
	}
	else if (pppSession->ppp.lcp == Opened)
	{
		pppSession->last_packet = time_now;
		protoreject(pppSession, pack, size, proto);
	}
	else
	{
		LOG(3, pppSession->pppoeSession, "processPPP: Unknown PPP protocol 0x%04X received in LCP %s state\n",
			proto, ppp_state(pppSession->ppp.lcp));
	}
}

// start tidy shutdown of session, if initiate==1 then will send a TerminateReq
// Will set the status to 'Closing' and will initiate a timer to complete the kill
// If we get a TerminateAck then we will proceed to the kill immediately
// Probably should live in lcp.c
void sessionshutdown(PPPSession *pppSession, int initiate, char const *reason)
{
#if 0
	int walled_garden = session[s].walled_garden;
	bundleidt b = session[s].bundle;
	//delete routes only for last session in bundle (in case of MPPP)
	int del_routes = !b || (bundle[b].num_of_links == 1);

	CSTAT(sessionshutdown);

	if (!session[s].opened)
	{
		LOG(3, s, session[s].tunnel, "Called sessionshutdown on an unopened session.\n");
		return;                   // not a live session
	}

	if (!session[s].die)
	{
		struct param_kill_session data = { &tunnel[session[s].tunnel], &session[s] };
		LOG(2, s, session[s].tunnel, "Shutting down session %u: %s\n", s, reason);
		run_plugins(PLUGIN_KILL_SESSION, &data);
	}

	if (session[s].ip && !walled_garden && !session[s].die)
	{
		// RADIUS Stop message
		uint16_t r = radiusnew(s);
		if (r)
		{
			// stop, if not already trying
			if (radius[r].state != RADIUSSTOP)
			{
				radius[r].term_cause = term_cause;
				radius[r].term_msg = reason;
				radiussend(r, RADIUSSTOP);
			}
		}
		else
			LOG(1, s, session[s].tunnel, "No free RADIUS sessions for Stop message\n");

	    	// Save counters to dump to accounting file
		if (*config->accounting_dir && shut_acct_n < sizeof(shut_acct) / sizeof(*shut_acct))
			memcpy(&shut_acct[shut_acct_n++], &session[s], sizeof(session[s]));
	}

	if (!session[s].die)
		session[s].die = TIME + 150; // Clean up in 15 seconds

	if (session[s].ip)
	{                          // IP allocated, clear and unroute
		int r;
		int routed = 0;
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip >> (32-session[s].route[r].prefixlen)) ==
			    (session[s].route[r].ip >> (32-session[s].route[r].prefixlen)))
				routed++;

			if (del_routes) routeset(s, session[s].route[r].ip, session[s].route[r].prefixlen, 0, 0);
			session[s].route[r].ip = 0;
		}

		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed && del_routes) routeset(s, session[s].ip, 0, 0, 0);
			session[s].ip = 0;
		}
		else
			free_ip_address(s);

		// unroute IPv6, if setup
		for (r = 0; r < MAXROUTE6 && session[s].route6[r].ipv6route.s6_addr[0] && session[s].route6[r].ipv6prefixlen; r++)
		{
			if (del_routes) route6set(s, session[s].route6[r].ipv6route, session[s].route6[r].ipv6prefixlen, 0);
			memset(&session[s].route6[r], 0, sizeof(session[s].route6[r]));
		}

		if (session[s].ipv6address.s6_addr[0] && del_routes)
		{
			route6set(s, session[s].ipv6address, 128, 0);
		}

		if (b)
		{
			uint8_t mem_num = 0;
			uint8_t ml;
			// Find out which member number we are
			for(ml = 0; ml<bundle[b].num_of_links; ml++)
			{
				if(bundle[b].members[ml] == s)
				{
					mem_num = ml;
					break;
				}
			}

			// Only do this if we are actually in the bundle
			if (ml < bundle[b].num_of_links) {
				// This session was part of a bundle
				bundle[b].num_of_links--;
				LOG(3, s, session[s].tunnel, "MPPP: Dropping member link: %d from bundle %d (remaining links: %d)\n",s,b,bundle[b].num_of_links);
				if(bundle[b].num_of_links == 0)
				{
					bundleclear(b);
					LOG(3, s, session[s].tunnel, "MPPP: Kill bundle: %d (No remaining member links)\n",b);
				}
				else 
				{
					// Adjust the members array to accomodate the new change
					// It should be here num_of_links instead of num_of_links-1 (previous instruction "num_of_links--")
					if(bundle[b].members[bundle[b].num_of_links] != s)
					{
						bundle[b].members[mem_num] = bundle[b].members[bundle[b].num_of_links];
						LOG(3, s, session[s].tunnel, "MPPP: Adjusted member links array\n");

						// If the killed session is the first of the bundle,
						// the new first session must be stored in the cache_ipmap
						// else the function sessionbyip return 0 and the sending not work any more (processipout).
						if (mem_num == 0)
						{
							sessionidt new_s = bundle[b].members[0];

							routed = 0;
							// Add the route for this session.
							for (r = 0; r < MAXROUTE && session[new_s].route[r].ip; r++)
							{
								int i, prefixlen;
								in_addr_t ip;

								prefixlen = session[new_s].route[r].prefixlen;
								ip = session[new_s].route[r].ip;

								if (!prefixlen) prefixlen = 32;
								ip &= 0xffffffff << (32 - prefixlen);	// Force the ip to be the first one in the route.

								for (i = ip; i < ip+(1<<(32-prefixlen)) ; ++i)
									cache_ipmap(i, new_s);
							}
							cache_ipmap(session[new_s].ip, new_s);

							// IPV6 route
							for (r = 0; r < MAXROUTE6 && session[new_s].route6[r].ipv6prefixlen; r++)
							{
								cache_ipv6map(session[new_s].route6[r].ipv6route, session[new_s].route6[r].ipv6prefixlen, new_s);
							}

							if (session[new_s].ipv6address.s6_addr[0])
							{
								cache_ipv6map(session[new_s].ipv6address, 128, new_s);
							}
						}
					}
				}

				cluster_send_bundle(b);
			}
        	}
	}

#endif

	if (initiate) {
		sendLCPTerminateReq(pppSession, reason);
		
	}

	// clear PPP state
	memset(&pppSession->ppp, 0, sizeof(pppSession->ppp));
	pppSession->lcp.restart = 0;
	pppSession->ipcp.restart = 0;
	pppSession->ipv6cp.restart = 0;
	pppSession->ccp.restart = 0;

	start_close_timer(pppSession, lcp);

	(*pppSession->cb)(pppSession, 4);
}

void sessionkill(PPPSession *pppSession)
{
	LOG(3, pppSession->pppoeSession, "LCP: Kill Session\n");
	change_state(pppSession, lcp, Closed);
	pppoe_sessionkill(pppSession->pppoeSession);
	memset(pppSession, 0, sizeof(pppSession));
}

PPPSession *pppServer(PPPoESession *pppoeSession, ppp_cb_func cb)
{
	pppoeSession->pppSession=ppp_new_session(pppoeSession, 0);
	pppoeSession->pppSession->cb=cb;
	sendLCPConfigReq(pppoeSession->pppSession);
	change_state(pppoeSession->pppSession, lcp, RequestSent);
	return(pppoeSession->pppSession);
}

PPPSession *pppClient(PPPoESession *pppoeSession, ppp_cb_func cb)
{
	pppoeSession->pppSession=ppp_new_session(pppoeSession, SESSION_CLIENT);
	pppoeSession->pppSession->cb=cb;
	sendLCPConfigReq(pppoeSession->pppSession);
	change_state(pppoeSession->pppSession, lcp, RequestSent);
	return(pppoeSession->pppSession);
}

int sessionsetup(PPPSession *pppSession)
{
#if 0
	// A session now exists, set it up
	in_addr_t ip;
	char *user;
	sessionidt i;
	int r;

	CSTAT(sessionsetup);

	LOG(3, s, t, "Doing session setup for session\n");

	// Join a bundle if the MRRU option is accepted
	if(session[s].mrru > 0 && session[s].bundle == 0)
	{
		LOG(3, s, t, "This session can be part of multilink bundle\n");
		if (join_bundle(s) > 0)
			cluster_send_bundle(session[s].bundle);
		else
		{
			LOG(0, s, t, "MPPP: Unable to join bundle\n");
			sessionshutdown(s, "Unable to join bundle", CDN_NONE, TERM_SERVICE_UNAVAILABLE);
			return 0;
		}
	}

	session[s].ip_local= config->peer_address ? config->peer_address :
			 config->iftun_n_address[tunnel[t].indexudp] ? config->iftun_n_address[tunnel[t].indexudp] :
			 my_address; // send my IP

	if (!session[s].ip)
	{
		assign_ip_address(s);
		if (!session[s].ip)
		{
			LOG(0, s, t, "   No IP allocated.  The IP address pool is FULL!\n");
			sessionshutdown(s, "No IP addresses available.", CDN_TRY_ANOTHER, TERM_SERVICE_UNAVAILABLE);
			return 0;
		}
		LOG(3, s, t, "   No IP allocated.  Assigned %s from pool\n",
			fmtaddr(htonl(session[s].ip), 0));
	}

	// Make sure this is right
	session[s].tunnel = t;

	// zap old sessions with same IP and/or username
	// Don't kill gardened sessions - doing so leads to a DoS
	// from someone who doesn't need to know the password
	{
		ip = session[s].ip;
		user = session[s].user;
		for (i = 1; i <= config->cluster_highest_sessionid; i++)
		{
			if (i == s) continue;
			if (!session[s].opened) break;
			// Allow duplicate sessions for multilink ones of the same bundle.
			if (session[s].bundle && session[i].bundle && session[s].bundle == session[i].bundle) continue;

			if (ip == session[i].ip)
			{
				sessionshutdown(i, "Duplicate IP address", CDN_ADMIN_DISC, TERM_ADMIN_RESET);  // close radius/routes, etc.
				continue;
			}

			if (config->allow_duplicate_users) continue;
			if (session[s].walled_garden || session[i].walled_garden) continue;
			// Guest change
			int found = 0;
			int gu;
			for (gu = 0; gu < guest_accounts_num; gu++)
			{
				if (!strcasecmp(user, guest_users[gu]))
				{
					found = 1;
					break;
				}
			}
			if (found) continue;

			// Drop the new session in case of duplicate sessionss, not the old one.
			if (!strcasecmp(user, session[i].user))
				sessionshutdown(i, "Duplicate session for users", CDN_ADMIN_DISC, TERM_ADMIN_RESET);  // close radius/routes, etc.
		}
	}

	// no need to set a route for the same IP address of the bundle
	if (!session[s].bundle || (bundle[session[s].bundle].num_of_links == 1))
	{
		int routed = 0;

		// Add the route for this session.
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip >> (32-session[s].route[r].prefixlen)) ==
			    (session[s].route[r].ip >> (32-session[s].route[r].prefixlen)))
				routed++;

			routeset(s, session[s].route[r].ip, session[s].route[r].prefixlen, 0, 1);
		}

		// Static IPs need to be routed if not already
		// convered by a Framed-Route.  Anything else is part
		// of the IP address pool and is already routed, it
		// just needs to be added to the IP cache.
		// IPv6 route setup is done in ppp.c, when IPV6CP is acked.
		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed) routeset(s, session[s].ip, 0, 0, 1);
		}
		else
			cache_ipmap(session[s].ip, s);
	}

	sess_local[s].lcp_authtype = 0; // RADIUS authentication complete
	lcp_open(s, t); // transition to Network phase and send initial IPCP

	// Run the plugin's against this new session.
	{
		struct param_new_session data = { &tunnel[t], &session[s] };
		run_plugins(PLUGIN_NEW_SESSION, &data);
	}

	// Allocate TBFs if throttled
	if (session[s].throttle_in || session[s].throttle_out)
		throttle_session(s, session[s].throttle_in, session[s].throttle_out);

	session[s].last_packet = session[s].last_data = time_now;

	LOG(2, s, t, "Login by %s at %s from %s (%s)\n", session[s].user,
		fmtaddr(htonl(session[s].ip), 0),
		fmtaddr(htonl(tunnel[t].ip), 1), tunnel[t].hostname);

	cluster_send_session(s);	// Mark it as dirty, and needing to the flooded to the cluster.

	return 1;       // RADIUS OK and IP allocated, done...
#endif
	return 0;
}

int sessionsetup_client(PPPSession *pppSession)
{
#if 0
	// A session now exists, set it up
	int r;

	LOG(3, s, t, "Doing client session setup for session\n");

	// Join a bundle if the MRRU option is accepted
	if(session[s].mrru > 0 && session[s].bundle == 0)
	{
		LOG(3, s, t, "This session can be part of multilink bundle\n");
		if (join_bundle(s) > 0)
			cluster_send_bundle(session[s].bundle);
		else
		{
			LOG(0, s, t, "MPPP: Unable to join bundle\n");
			sessionshutdown(s, "Unable to join bundle", CDN_NONE, TERM_SERVICE_UNAVAILABLE);
			return 0;
		}
	}

	// Make sure this is right
	session[s].tunnel = t;

	// no need to set a route for the same IP address of the bundle
	if (!session[s].bundle || (bundle[session[s].bundle].num_of_links == 1))
	{
		int routed = 0;

		// Add the route for this session.
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip >> (32-session[s].route[r].prefixlen)) ==
			    (session[s].route[r].ip >> (32-session[s].route[r].prefixlen)))
				routed++;

			routeset(s, session[s].route[r].ip, session[s].route[r].prefixlen, 0, 1);
		}

		// Static IPs need to be routed if not already
		// convered by a Framed-Route.  Anything else is part
		// of the IP address pool and is already routed, it
		// just needs to be added to the IP cache.
		// IPv6 route setup is done in ppp.c, when IPV6CP is acked.
		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed) routeset(s, session[s].ip, 0, 0, 1);
		}
		else
			cache_ipmap(session[s].ip, s);
	}

	// Run the plugin's against this new session.
	{
		struct param_new_session data = { &tunnel[t], &session[s] };
		run_plugins(PLUGIN_NEW_SESSION, &data);
	}

	// Allocate TBFs if throttled
	if (session[s].throttle_in || session[s].throttle_out)
		throttle_session(s, session[s].throttle_in, session[s].throttle_out);

	session[s].last_packet = session[s].last_data = time_now;

	LOG(2, s, t, "Login by %s at %s from %s (%s)\n", session[s].user,
		fmtaddr(htonl(session[s].ip), 0),
		fmtaddr(htonl(tunnel[t].ip), 1), tunnel[t].hostname);

	cluster_send_session(s);	// Mark it as dirty, and needing to the flooded to the cluster.

	return 1;       // RADIUS OK and IP allocated, done...
#endif
	return 0;
}

void ppp_code_rej(PPPSession *pppSession, uint16_t proto,
	char *pname, uint8_t *p, uint16_t l, uint8_t *buf, size_t size)
{
	uint8_t *q;
	int mru = pppSession->mru;
	if (mru < MINMTU) mru = MINMTU;
	if (mru > size) mru = size;

	l += 4;
	if (l > mru) l = mru;

	q = pppoe_makeppp(buf, size, 0, 0, pppSession, proto, 0, 0, 0);
	if (!q) return;

	*q = CodeRej;
	*(q + 1) = ++pppSession->lcp_ident;
	*(uint16_t *)(q + 2) = htons(l);
	memcpy(q + 4, p, l - 4);

	LOG(2, pppSession->pppoeSession, "Unexpected %s code %s\n", pname, ppp_code(*p));
	LOG(3, pppSession->pppoeSession, "%s: send %s\n", pname, ppp_code(*q));
	if (debuglevel > 3) dumplcp(pppSession->pppoeSession, q, l);

	pppoe_sess_send(pppSession->pppoeSession, buf, l + (q - buf));
}

uint8_t *ppp_conf_nak(PPPSession *pppSession, uint8_t *buf, size_t blen, uint16_t mtype,
	uint8_t **response, uint8_t *queued, uint8_t *packet, uint8_t *option,
	uint8_t *value, size_t vlen)
{
    	int *nak_sent;
	switch (mtype)
	{
	case PPP_LCP:	nak_sent = &pppSession->lcp.nak_sent;    break;
	case PPP_IPCP:	nak_sent = &pppSession->ipcp.nak_sent;   break;
	case PPP_IPV6CP:	nak_sent = &pppSession->ipv6cp.nak_sent; break;
	default:	return 0; // ?
	}

	if (*response && **response != ConfigNak)
	{
	    	if (*nak_sent < ppp_max_failure) // reject queued
			return queued;

		return ppp_conf_rej(pppSession, buf, blen, mtype, response, 0, packet, option);
	}

	if (!*response)
	{
	    	if (*nak_sent >= ppp_max_failure)
			return ppp_conf_rej(pppSession, buf, blen, mtype, response, 0, packet, option);

		queued = *response = pppoe_makeppp(buf, blen, packet, 2, pppSession, mtype, 0, 0, 0);
		if (!queued)
			return 0;

		(*nak_sent)++;
		*queued = ConfigNak;
		queued += 4;
	}

	if ((queued - buf + vlen + 2) > blen)
	{
		LOG(2, pppSession->pppoeSession, "PPP overflow for ConfigNak (proto %u, option %u).\n", mtype, *option);
		return 0;
	}

	*queued++ = *option;
	*queued++ = vlen + 2;
	memcpy(queued, value, vlen);
	return queued + vlen;
}

uint8_t *ppp_conf_rej(PPPSession *pppSession, uint8_t *buf, size_t blen, uint16_t mtype,
	uint8_t **response, uint8_t *queued, uint8_t *packet, uint8_t *option)
{
	if (!*response || **response != ConfigRej)
	{
		queued = *response = pppoe_makeppp(buf, blen, packet, 2, pppSession, mtype, 0, 0, 0);
		if (!queued)
			return 0;

		*queued = ConfigRej;
		queued += 4;
	}

	if ((queued - buf + option[1]) > blen)
	{
		LOG(2, pppSession->pppoeSession, "PPP overflow for ConfigRej (proto %u, option %u).\n", mtype, *option);
		return 0;
	}

	memcpy(queued, option, option[1]);
	return queued + option[1];
}


