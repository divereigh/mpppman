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
		LOG(3, "Got a timeout event for LCP\n");
		switch (pppSession->ppp.lcp)
		{
		case RequestSent:
		case AckReceived:
			next_state = RequestSent;

		case AckSent:
			if (pppSession->lcp.conf_sent < ppp_max_configure)
			{
				LOG(3, "No ACK for LCP ConfigReq... resending\n");
				sendLCPConfigReq(pppSession);
				change_state(pppSession, lcp, next_state);
			}
			else
			{
				sessionshutdown(pppSession, "No response to LCP ConfigReq.");
			}
		}

	} else if (cp==&pppSession->ipcp) {
		LOG(3, "Got a timeout event for IPCP\n");
	} else if (cp==&pppSession->ipv6cp) {
		LOG(3, "Got a timeout event for IPV6CP\n");
	} else if (cp==&pppSession->ccp) {
		LOG(3, "Got a timeout event for CCP\n");
	} else {
		LOG(3, "Got an unknown timeout event\n");
	}
}

/* Allocate and fill new session - returns PPPSession */
PPPSession * ppp_new_session(const PPPoESession *pppoeSession)
{
	uint16_t sid;
	int i;
	PPPSession *pppSession;

	if ((pppSession=ppp_find_free_session()) == NULL) {
		LOG(0, "No free PPPSession available\n");
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

	// start LCP - prefer PAP
	pppSession->lcp_authtype = AUTHPAP;
	// TODO - Need to calculate this properly
	pppSession->ppp_mru = PPPoE_MRU; // Should be MRU;

	// Set multilink options before sending initial LCP packet
	pppSession->mp_mrru = 1614;
	// pppSession->mp_epdis = ntohl(config->iftun_address ? config->iftun_address : my_address);
	pppSession->mp_epdis = htonl(0x01010101);

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
		LOG(0, "pppoe_makeppp buffer too small for pppoe header (size=%d)\n", size);
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
		LOG(0, "pppoe_makeppp would overflow buffer (size=%d, header+payload=%td)\n", size, (b - start) + l);
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
		LOG(5, "processSession: HDLC address header, discard\n");
		pack += 2;
		size -= 2;
	}

	if (size < 2)
	{
		LOG(3, "Error process_pppoe_sess: Short ppp length %d\n", size);
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
		LOG(3, "processPPP: Unknown PPP protocol 0x%04X received in LCP %s state\n",
			proto, ppp_state(pppSession->ppp.lcp));
	}
}

// start tidy shutdown of session
void sessionshutdown(PPPSession *pppSession, char const *reason)
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

	if (session[s].throttle_in || session[s].throttle_out) // Unthrottle if throttled.
		throttle_session(s, 0, 0);

	if (cdn_result)
	{
		if (session[s].tunnel == TUNNEL_ID_PPPOE)
		{
			pppoe_shutdown_session(s);
		}
		else
		{
			// Send CDN
			controlt *c = controlnew(14); // sending CDN
			if (cdn_error)
			{
				uint16_t buf[2];
				buf[0] = htons(cdn_result);
				buf[1] = htons(cdn_error);
				controlb(c, 1, (uint8_t *)buf, 4, 1);
			}
			else
				control16(c, 1, cdn_result, 1);

			control16(c, 14, s, 1);   // assigned session (our end)
			controladd(c, session[s].far, session[s].tunnel); // send the message
		}
	}

	// update filter refcounts
	if (session[s].filter_in) ip_filters[session[s].filter_in - 1].used--;
	if (session[s].filter_out) ip_filters[session[s].filter_out - 1].used--;

	// clear PPP state
	memset(&session[s].ppp, 0, sizeof(session[s].ppp));
	sess_local[s].lcp.restart = 0;
	sess_local[s].ipcp.restart = 0;
	sess_local[s].ipv6cp.restart = 0;
	sess_local[s].ccp.restart = 0;

	cluster_send_session(s);
#endif
}

