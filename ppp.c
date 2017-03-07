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
#include "constants.h"

PPPSession ppp_sessions[MAX_PPP_SESSION];
int ppp_restart_time=5;

static void dumplcp(uint8_t *p, int l)
{
	int x = l - 4;
	uint8_t *o = (p + 4);

	LOG_HEX(5, "PPP LCP Packet", p, l);
	LOG(4, "PPP LCP Packet type %d (%s len %d)\n", *p, ppp_code((int)*p), ntohs( ((uint16_t *) p)[1]) );
	LOG(4, "Length: %d\n", l);
	if (*p != LCP_CONFREQ && *p != LCP_CONFREJ && *p != LCP_CONFACK)
		return;

	while (x > 2)
	{
		int type = o[0];
		int length = o[1];
		if (length < 2)
		{
			LOG(4, "	Option length is %d...\n", length);
			break;
		}
		if (type == 0)
		{
			LOG(4, "	Option type is 0...\n");
			x -= length;
			o += length;
			continue;
		}
		switch (type)
		{
			case 1: // Maximum-Receive-Unit
				if (length == 4)
					LOG(4, "    %s %d\n", ppp_lcp_option(type), ntohs(*(uint16_t *)(o + 2)));
				else
					LOG(4, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 2: // Async-Control-Character-Map
				if (length == 6)
				{
					uint32_t asyncmap = ntohl(*(uint32_t *)(o + 2));
					LOG(4, "    %s %x\n", ppp_lcp_option(type), asyncmap);
				}
				else
					LOG(4, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 3: // Authentication-Protocol
				if (length == 4)
				{
					int proto = ntohs(*(uint16_t *)(o + 2));
					LOG(4, "    %s 0x%x (%s)\n", ppp_lcp_option(type), proto,
						proto == AUTHPAP  ? "PAP"  : "UNSUPPORTED");
				}
				else if (length == 5)
				{
					int proto = ntohs(*(uint16_t *)(o + 2));
					int algo = *(o + 4);
					LOG(4, "    %s 0x%x 0x%x (%s)\n", ppp_lcp_option(type), proto, algo,
						(proto == AUTHCHAP && algo == 5) ? "CHAP MD5"  : "UNSUPPORTED");
				}
				else
					LOG(4, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 4: // Quality-Protocol
				{
					uint32_t qp = ntohl(*(uint32_t *)(o + 2));
					LOG(4, "    %s %x\n", ppp_lcp_option(type), qp);
				}
				break;
			case 5: // Magic-Number
				if (length == 6)
				{
					uint32_t magicno = ntohl(*(uint32_t *)(o + 2));
					LOG(4, "    %s %x\n", ppp_lcp_option(type), magicno);
				}
				else
					LOG(4, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 7: // Protocol-Field-Compression
			case 8: // Address-And-Control-Field-Compression
				LOG(4, "    %s\n", ppp_lcp_option(type));
				break;
			case 17: // Multilink Max-Receive-Reconstructed-Unit
				{
					int mrru = ntohs(*(uint16_t *)(o + 2));
					LOG(4, "    %s %d\n", ppp_lcp_option(type), mrru);
				}
				break;
			case 19: // Multilink Max-Receive-Reconstructed-Unit
				{
					int ep_type=o[2];
					if (ep_type==IPADDR) {
						struct in_addr *ipaddr = (struct in_addr *)(o + 3);
						LOG(4, "    %s ipaddr: %s\n", ppp_lcp_option(type), inet_ntoa(*ipaddr));
					} else {
						LOG(4, "    %s unknown: %d\n", ppp_lcp_option(type), ep_type);
					}
				}
				break;
			default:
				LOG(2, "    Unknown PPP LCP Option type %d\n", type);
				break;
		}
		x -= length;
		o += length;
	}
}

static int add_lcp_auth(uint8_t *b, int size, int authtype)
{
	int len = 0;
	if ((authtype == AUTHCHAP && size < 5) || size < 4)
		return 0;

	*b++ = 3; // Authentication-Protocol
	if (authtype == AUTHCHAP)
	{
		len = *b++ = 5; // length
		*(uint16_t *) b = htons(AUTHCHAP); b += 2;
		*b++ = 5; // MD5
	}
	else if (authtype == AUTHPAP)
	{
		len = *b++ = 4; // length
		*(uint16_t *) b = htons(AUTHPAP); b += 2;
	}
	else
	{
		LOG(0, "add_lcp_auth called with unsupported auth type %d\n", authtype);
	}

	return len;
}

// Send LCP LCP_CONFREQ for MRU, authentication type and magic no
void sendlcp(PPPSession *pppSession)
{
	uint8_t b[500], *q, *l;
	int authtype = pppSession->lcp_authtype;

        if (!(q = pppoe_makeppp(b, sizeof(b), NULL, 0, pppSession, PPP_LCP, 0, 0, 0)))
		return;

        LOG(3, "LCP: send LCP_CONFREQ%s%s%s including MP options\n",
	    authtype ? " (" : "",
	    authtype ? (authtype == AUTHCHAP ? "CHAP" : "PAP") : "",
	    authtype ? ")" : "");

	l = q;
	*l++ = LCP_CONFREQ;
	*l++ = ++pppSession->lcp_ident; // ID

	l += 2; //Save space for length

	if (pppSession->ppp_mru)
	{
		*l++ = 1; *l++ = 4; // Maximum-Receive-Unit (length 4)
		*(uint16_t *) l = htons(pppSession->ppp_mru); l += 2;
	}

	if (authtype)
		l += add_lcp_auth(l, sizeof(b) - (l - b), authtype);

	if (pppSession->magic)
	{
		*l++ = 5; *l++ = 6; // Magic-Number (length 6)
		*(uint32_t *) l = htonl(pppSession->magic);
		l += 4;
	}

        if (pppSession->mp_mrru)
        {
		*l++ = 17; *l++ = 4; // Multilink Max-Receive-Reconstructed-Unit (length 4)
		*(uint16_t *) l = htons(pppSession->mp_mrru); l += 2;
	}

        if (pppSession->mp_epdis)
        {
		*l++ = 19; *l++ = 7;	// Multilink Endpoint Discriminator (length 7)
		*l++ = IPADDR;	// Endpoint Discriminator class
		*(uint32_t *) l = htonl(pppSession->mp_epdis);
		l += 4;
	}

	*(uint16_t *)(q + 2) = htons(l - q); // Length

	LOG_HEX(5, "PPPLCP", q, l - q);
	if (debuglevel > 3) dumplcp(q, l - q);

	pppoe_sess_send(pppSession->pppoeSession, b, (l - b));
	restart_timer(pppSession, lcp);
}

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
	pppSession->mp_epdis = ntohl(0x01010101);

	// sendlcp(pppSession);
	// change_state(pppSession, lcp, RequestSent);

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

