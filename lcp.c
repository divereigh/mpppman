#include "config.h"

#ifdef HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "event.h"
#include "lcp.h"
#include "log.h"
#include "constants.h"
#include "common.h"
#include "auth.h"
#include "ip.h"

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
						proto == PPP_PAP  ? "PAP"  : "UNSUPPORTED");
				}
				else if (length == 5)
				{
					int proto = ntohs(*(uint16_t *)(o + 2));
					int algo = *(o + 4);
					LOG(4, "    %s 0x%x 0x%x (%s)\n", ppp_lcp_option(type), proto, algo,
						(proto == PPP_CHAP && algo == 5) ? "CHAP MD5"  : "UNSUPPORTED");
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
		*(uint16_t *) b = htons(PPP_CHAP); b += 2;
		*b++ = 5; // MD5
	}
	else if (authtype == AUTHPAP)
	{
		len = *b++ = 4; // length
		*(uint16_t *) b = htons(PPP_PAP); b += 2;
	}
	else
	{
		LOG(0, "add_lcp_auth called with unsupported auth type %d\n", authtype);
	}

	return len;
}

// Send LCP LCP_CONFREQ for MRU, authentication type and magic no
void sendLCPConfigReq(PPPSession *pppSession)
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

	LOG_HEX(5, "PPP_LCP", q, l - q);
	if (debuglevel > 3) dumplcp(q, l - q);

	pppoe_sess_send(pppSession->pppoeSession, b, (l - b));
	restart_timer(pppSession, lcp);
}

void lcp_open(PPPSession *pppSession)
{
	// transition to Authentication or Network phase: 
	pppSession->ppp.phase = pppSession->lcp_authtype ? Authenticate : Network;

	LOG(3, "LCP: Opened, phase %s\n", ppp_phase(pppSession->ppp.phase));

	// LCP now Opened
	change_state(pppSession, lcp, Opened);

	if (pppSession->ppp.phase == Authenticate)
	{
#if 0
// Todo client stuff
		if (pppSession->flags & SESSION_CLIENT) {
			if (pppSession->lcp_authtype == AUTHPAP) {
				sendpap();
			}
		} else {
#endif
			if (pppSession->lcp_authtype == AUTHCHAP)
				sendchap(pppSession);
#if 0
		}
#endif
	}
	else
	{
#if 0
// TODO Bundle
		if(session[s].bundle == 0 || bundle[session[s].bundle].num_of_links == 1)
		{
#endif
			// This-Layer-Up
			sendipcp(pppSession);
			change_state(pppSession, ipcp, RequestSent);
			// move to passive state for IPv6 (if configured), CCP
#if 0
			if (config->ipv6_prefix.s6_addr[0])
				change_state(pppSession, ipv6cp, Stopped);
			else
#endif
				change_state(pppSession, ipv6cp, Closed);

			change_state(pppSession, ccp, Stopped);
#if 0
		}
		else
		{
			sessionidt first_ses = bundle[session[s].bundle].members[0];
			LOG(3, "MPPP: Skipping IPCP negotiation for session:%d, first session of bundle is:%d\n",s,first_ses);
			ipcp_open(s, t);
                }
#endif
	}
}

void lcp_restart(PPPSession *pppSession)
{
	pppSession->ppp.phase = Establish;
	// This-Layer-Down
	change_state(pppSession, ipcp, Initial);
	change_state(pppSession, ipv6cp, Initial);
	change_state(pppSession, ccp, Initial);
}

static uint8_t *ppp_conf_rej(PPPSession *pppSession, uint8_t *buf, size_t blen, uint16_t mtype,
	uint8_t **response, uint8_t *queued, uint8_t *packet, uint8_t *option)
{
	if (!*response || **response != LCP_CONFREJ)
	{
		queued = *response = pppoe_makeppp(buf, blen, packet, 2, pppSession, mtype, 0, 0, 0);
		if (!queued)
			return 0;

		*queued = LCP_CONFREJ;
		queued += 4;
	}

	if ((queued - buf + option[1]) > blen)
	{
		LOG(2, "PPP overflow for LCP_CONFREJ (proto %u, option %u).\n", mtype, *option);
		return 0;
	}

	memcpy(queued, option, option[1]);
	return queued + option[1];
}

static uint8_t *ppp_conf_nak(PPPSession *pppSession, uint8_t *buf, size_t blen, uint16_t mtype,
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

	if (*response && **response != LCP_CONFNAK)
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
		*queued = LCP_CONFNAK;
		queued += 4;
	}

	if ((queued - buf + vlen + 2) > blen)
	{
		LOG(2, "PPP overflow for LCP_CONFNAK (proto %u, option %u).\n", mtype, *option);
		return 0;
	}

	*queued++ = *option;
	*queued++ = vlen + 2;
	memcpy(queued, value, vlen);
	return queued + vlen;
}

static void ppp_code_rej(PPPSession *pppSession, uint16_t proto,
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

	*q = LCP_CONFREJ;
	*(q + 1) = ++pppSession->lcp_ident;
	*(uint16_t *)(q + 2) = htons(l);
	memcpy(q + 4, p, l - 4);

	LOG(2, "Unexpected %s code %s\n", pname, ppp_code(*p));
	LOG(3, "%s: send %s\n", pname, ppp_code(*q));
	if (debuglevel > 3) dumplcp(q, l);

	pppoe_sess_send(pppSession->pppoeSession, buf, l + (q - buf));
}

// Process LCP messages
void processlcp(PPPSession *pppSession, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXETHER];
	uint8_t *q = NULL;
	uint16_t hl;

	LOG_HEX(5, "LCP", p, l);
	if (l < 4)
	{
		LOG(1, "Short LCP %d bytes\n", l);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, "Length mismatch LCP %u/%u\n", hl, l);
		return ;
	}
	l = hl;

	if (pppSession->die) // going down...
		return;

	LOG(((*p == LCP_ECHOREQ || *p == LCP_ECHOREPLY) ? 4 : 3), 
		"LCP: recv %s\n", ppp_code(*p));

	if (debuglevel > 3) dumplcp(p, l);

	if (*p == LCP_CONFACK)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		int authtype = 0;

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(uint16_t *)(o + 2));
						if (proto == PPP_PAP)
							authtype = AUTHPAP;
						else if (proto == PPP_CHAP && *(o + 4) == 5)
							authtype = AUTHCHAP;
					}

					break;
			}
			x -= length;
			o += length;
		}

		if (!pppSession->ip_remote && authtype)
			pppSession->lcp_authtype = authtype;

		switch (pppSession->ppp.lcp)
		{
		case RequestSent:
		    	initialise_restart_count(pppSession, lcp);
			change_state(pppSession, lcp, AckReceived);
			break;

		case AckReceived:
		case Opened:
		    	LOG(2, "LCP: LCP_CONFACK in state %s?  Sending LCP_CONFREQ\n", ppp_state(pppSession->ppp.lcp));
			if (pppSession->ppp.lcp == Opened)
				lcp_restart(pppSession);

			sendLCPConfigReq(pppSession);
			change_state(pppSession, lcp, RequestSent);
			break;

		case AckSent:
			lcp_open(pppSession);
			break;

		default:
		    	LOG(2, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.lcp));
		}
	}
	else if (*p == LCP_CONFREQ)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		uint8_t *response = 0;
		static uint8_t asyncmap[4] = { 0, 0, 0, 0 }; // all zero
		static uint8_t authproto[5];
		int changed = 0;

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					{
						uint16_t mru = ntohs(*(uint16_t *)(o + 2));
						if (mru >= MINMTU)
						{
							pppSession->mru = mru;
							changed++;
							break;
						}

						LOG(3, "    Remote requesting MRU of %u.  Rejecting.\n", mru);
						mru = htons(MRU);
						q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_LCP, &response, q, p, o, (uint8_t *) &mru, sizeof(mru));
					}
					break;

				case 2: // Async-Control-Character-Map
					if (!ntohl(*(uint32_t *)(o + 2))) // all bits zero is OK
						break;

					LOG(3, "    Remote requesting asyncmap.  Rejecting.\n");
					q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_LCP, &response, q, p, o, asyncmap, sizeof(asyncmap));
					break;

				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(uint16_t *)(o + 2));
						char proto_name[] = "0x0000";
						int alen;

						if (proto == PPP_PAP)
						{
							if (radius_authtypes & AUTHPAP)
							{
								pppSession->lcp_authtype = AUTHPAP;
								break;
							}

							strcpy(proto_name, "PAP");
						}
						else if (proto == PPP_CHAP)
						{
							if (radius_authtypes & AUTHCHAP
							    && *(o + 4) == 5) // MD5
							{
								pppSession->lcp_authtype = AUTHCHAP;
								break;
							}

							strcpy(proto_name, "CHAP");
						}
						else
							sprintf(proto_name, "%#4.4x", proto);

						LOG(3, "    Remote requesting %s authentication.  Rejecting.\n", proto_name);

						alen = add_lcp_auth(authproto, sizeof(authproto), radius_authprefer);
						if (alen < 2) break; // paranoia

						q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_LCP, &response, q, p, o, authproto + 2, alen - 2);
						if (q && *response == LCP_CONFNAK &&
							radius_authtypes != radius_authprefer)
						{
							// alternate type
						    	alen = add_lcp_auth(authproto, sizeof(authproto), radius_authtypes & ~radius_authprefer);
							if (alen < 2) break;
							q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_LCP, &response, q, p, o, authproto + 2, alen - 2);
						}

						break;
					}
					break;

				case 4: // Quality-Protocol
				case 5: // Magic-Number
				case 7: // Protocol-Field-Compression
				case 8: // Address-And-Control-Field-Compression
					break;

				case 17: // Multilink Max-Receive-Reconstructed-Unit
					{
						uint16_t mrru = ntohs(*(uint16_t *)(o + 2));
						pppSession->mrru = mrru;
						changed++;
						LOG(3, "    Received PPP LCP option MRRU: %d\n",mrru);
					}
					break;
					
				case 18: // Multilink Short Sequence Number Header Format
					{
						pppSession->mssf = 1;
						changed++;
						LOG(3, "    Received PPP LCP option MSSN format\n");
					}
					break;
					
				case 19: // Multilink Endpoint Discriminator
					{
						uint8_t epdis_class = o[2];
						int addr;

						pppSession->epdis.addr_class = epdis_class;
						pppSession->epdis.length = length - 3;
						if (pppSession->epdis.length > 20)
						{
							LOG(1, "Error: received EndDis Address Length more than 20: %d\n", pppSession->epdis.length);
							pppSession->epdis.length = 20;
						}

						for (addr = 0; addr < pppSession->epdis.length; addr++)
							pppSession->epdis.address[addr] = o[3+addr];

						changed++;

						switch (epdis_class)
						{
						case LOCALADDR:
							LOG(3, "    Received PPP LCP option Multilink EndDis Local Address Class: %d\n",epdis_class);
							break;
						case IPADDR:
							LOG(3, "    Received PPP LCP option Multilink EndDis IP Address Class: %d\n",epdis_class);
							break;
						case IEEEMACADDR:
							LOG(3, "    Received PPP LCP option Multilink EndDis IEEE MAC Address Class: %d\n",epdis_class);
							break;
						case PPPMAGIC:
							LOG(3, "    Received PPP LCP option Multilink EndDis PPP Magic No Class: %d\n",epdis_class);
							break;
						case PSNDN:
							LOG(3, "    Received PPP LCP option Multilink EndDis PSND No Class: %d\n",epdis_class);
							break;
						default:
							LOG(3, "    Received PPP LCP option Multilink EndDis NULL Class %d\n",epdis_class);
						}
					}
					break;

				default: // Reject any unknown options
					LOG(3, "    Rejecting unknown PPP LCP option %d\n", type);
					q = ppp_conf_rej(pppSession, b, sizeof(b), PPP_LCP, &response, q, p, o);
			}
			x -= length;
			o += length;
		}

		if (response)
		{
			l = q - response; // LCP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else
		{
			// Send packet back as LCP_CONFACK
			response = pppoe_makeppp(b, sizeof(b), p, l, pppSession, PPP_LCP, 0, 0, 0);
			if (!response) return;
			*response = LCP_CONFACK;
		}

		switch (pppSession->ppp.lcp)
		{
		case Closed:
			response = pppoe_makeppp(b, sizeof(b), p, 2, pppSession, PPP_LCP, 0, 0, 0);
			if (!response) return;
			*response = LCP_TERMACK;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(pppSession, lcp);
			sendLCPConfigReq(pppSession);
			if (*response == LCP_CONFACK)
				change_state(pppSession, lcp, AckSent);
			else
				change_state(pppSession, lcp, RequestSent);

			break;

		case RequestSent:
			if (*response == LCP_CONFACK)
				change_state(pppSession, lcp, AckSent);

			break;

		case AckReceived:
			if (*response == LCP_CONFACK)
				lcp_open(pppSession);

			break;

		case Opened:
		    	lcp_restart(pppSession);
			sendLCPConfigReq(pppSession);
			/* fallthrough */

		case AckSent:
			if (*response == LCP_CONFACK)
				change_state(pppSession, lcp, AckSent);
			else
				change_state(pppSession, lcp, RequestSent);

			break;

		case Closing:
			sessionshutdown(pppSession, "LCP: LCP_CONFREQ in state Closing. This should not happen. Killing session.");
			break;

		default:
		    	LOG(2, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.lcp));
			return;
		}

		LOG(3, "LCP: send %s\n", ppp_code(*response));
		if (debuglevel > 3) dumplcp(response, l);

		pppoe_sess_send(pppSession->pppoeSession, b, l + (response - b));
	}
	else if (*p == LCP_CONFNAK || *p == LCP_CONFREJ)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		int authtype = -1;

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					if (*p == LCP_CONFNAK)
					{
						if (length < 4) break;
						pppSession->ppp_mru = ntohs(*(uint16_t *)(o + 2));
						LOG(3, "    Remote requested MRU of %u\n", pppSession->ppp_mru);
					}
					else
					{
						pppSession->ppp_mru = 0;
						LOG(3, "    Remote rejected MRU negotiation\n");
					}

					break;

				case 3: // Authentication-Protocol
					if (authtype > 0)
						break;

					if (*p == LCP_CONFNAK)
					{
						int proto;

						if (length < 4) break;
						proto = ntohs(*(uint16_t *)(o + 2));

						if (proto == PPP_PAP)
						{
							authtype = radius_authtypes & AUTHPAP;
							LOG(3, "    Remote requested PAP authentication...%sing\n",
								authtype ? "accept" : "reject");
						}
						else if (proto == PPP_CHAP && length > 4 && *(o + 4) == 5)
						{
							authtype = radius_authtypes & AUTHCHAP;
							LOG(3, "    Remote requested CHAP authentication...%sing\n",
								authtype ? "accept" : "reject");
						}
						else
						{
							LOG(3, "    Rejecting unsupported authentication %#4x\n",
								proto);
						}
					}
					else
					{
						LOG(2, "LCP: remote rejected auth negotiation\n");
					    	authtype = 0; // shutdown
					}

					break;

				case 5: // Magic-Number
					pppSession->magic = 0;
					if (*p == LCP_CONFNAK)
					{
						if (length < 6) break;
						pppSession->magic = ntohl(*(uint32_t *)(o + 2));
					}

					if (pppSession->magic)
						LOG(3, "    Remote requested magic-no %x\n", pppSession->magic);
					else
						LOG(3, "    Remote rejected magic-no\n");

					break;

				case 17: // Multilink Max-Receive-Reconstructed-Unit
				{
					if (*p == LCP_CONFNAK)
					{
						pppSession->mp_mrru = ntohs(*(uint16_t *)(o + 2));
						LOG(3, "    Remote requested MRRU of %u\n", pppSession->mp_mrru);
					}
					else
					{
						pppSession->mp_mrru = 0;
						LOG(3, "    Remote rejected MRRU negotiation\n");
					}
				}
				break;

				case 18: // Multilink Short Sequence Number Header Format
				{
					if (*p == LCP_CONFNAK)
					{
						pppSession->mp_mssf = 0;
						LOG(3, "    Remote requested Naked mssf\n");
					}
					else
					{
						pppSession->mp_mssf = 0;
						LOG(3, "    Remote rejected mssf\n");
					}
				}
				break;

				case 19: // Multilink Endpoint Discriminator
				{
					if (*p == LCP_CONFNAK)
					{
						LOG(2, "    Remote should not configNak Endpoint Dis!\n");
					}
					else
					{
						pppSession->mp_epdis = 0;
						LOG(3, "    Remote rejected Endpoint Discriminator\n");
					}
				}
				break;

				default:
				    	LOG(2, "LCP: remote sent %s for type %u?\n", ppp_code(*p), type);
					sessionshutdown(pppSession, "Unable to negotiate LCP.");
					return;
			}
			x -= length;
			o += length;
		}

		if (!authtype)
		{
			sessionshutdown(pppSession, "Unsupported authentication.");
			return;
		}

		if (authtype > 0)
			pppSession->lcp_authtype = authtype;

		switch (pppSession->ppp.lcp)
		{
		case Closed:
		case Stopped:
		    	{
				uint8_t *response = pppoe_makeppp(b, sizeof(b), p, 2, pppSession, PPP_LCP, 0, 0, 0);
				if (!response) return;
				*response = LCP_TERMACK;
				*((uint16_t *) (response + 2)) = htons(l = 4);

				LOG(3, "LCP: send %s\n", ppp_code(*response));
				if (debuglevel > 3) dumplcp(response, l);

				pppoe_sess_send(pppSession->pppoeSession, b, l + (response - b));
			}
			break;

		case RequestSent:
		case AckSent:
		    	initialise_restart_count(pppSession, lcp);
			sendLCPConfigReq(pppSession);
			break;

		case AckReceived:
		    	LOG(2, "LCP: LCP_CONFNAK in state %s?  Sending LCP_CONFREQ\n", ppp_state(pppSession->ppp.lcp));
			sendLCPConfigReq(pppSession);
			break;

		case Opened:
		    	lcp_restart(pppSession);
			sendLCPConfigReq(pppSession);
			break;

		default:
		    	LOG(2, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.lcp));
			return;
		}
	}
	else if (*p == LCP_TERMREQ)
	{
		switch (pppSession->ppp.lcp)
		{
		case Closed:
		case Stopped:
		case Closing:
		case Stopping:
		case RequestSent:
		case AckReceived:
		case AckSent:
		    	break;

		case Opened:
		    	lcp_restart(pppSession);
		    	zero_restart_count(pppSession, lcp);
			change_state(pppSession, lcp, Closing);
			break;

		default:
		    	LOG(2, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.lcp));
			return;
		}

		*p = LCP_TERMACK;	// send ack
		q = pppoe_makeppp(b, sizeof(b),  p, l, pppSession, PPP_LCP, 0, 0, 0);
		if (!q) return;

		LOG(3, "LCP: send %s\n", ppp_code(*q));
		if (debuglevel > 3) dumplcp(q, l);

		pppoe_sess_send(pppSession->pppoeSession, b, l + (q - b));
	}
	else if (*p == LCP_PROTOCOLREJ)
	{
	    	uint16_t proto = 0;

		if (l > 4)
		{
			proto = *(p+4);
			if (l > 5 && !(proto & 1))
			{
				proto <<= 8;
				proto |= *(p+5);
			}
		}

		if (proto == PPP_IPV6CP)
		{
			LOG(3, "IPv6 rejected\n");
			change_state(pppSession, ipv6cp, Closed);
		}
		else
		{
			LOG(3, "LCP protocol reject: 0x%04X\n", proto);
		}
	}
	else if (*p == LCP_ECHOREQ)
	{
		*p = LCP_ECHOREPLY;		// reply
		*(uint32_t *) (p + 4) = htonl(pppSession->magic); // our magic number
		q = pppoe_makeppp(b, sizeof(b), p, l, pppSession, PPP_LCP, 0, 0, 0);
		if (!q) return;

		LOG(4, "LCP: send %s\n", ppp_code(*q));
		if (debuglevel > 3) dumplcp(q, l);

		pppoe_sess_send(pppSession->pppoeSession, b, l + (q - b));

#if 0
// TODO - IPv6
		if (pppSession->ppp.phase == Network && pppSession->ppp.ipv6cp == Opened)
			send_ipv6_ra(pppSession, NULL); // send a RA
#endif
	}
	else if (*p == LCP_ECHOREPLY)
	{
		// Ignore it, last_packet time is set earlier than this.
	}
	else if (*p != LCP_CODEREJ)
	{
		ppp_code_rej(pppSession, PPP_LCP, "LCP", p, l, b, sizeof(b));
	}
}


