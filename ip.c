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
#include "ip.h"
#include "ppp.h"

#define MIN_IP_SIZE	0x19
uint32_t last_id = 0;

// send an IPCP Config Request challenge
void sendipcp(PPPSession *pppSession)
{
	uint8_t buf[MAXETHER];
	uint8_t *q;

	if ((pppSession->flags & SESSION_CLIENT)==0 && (pppSession->ip_remote==0 || pppSession->ip_local==0)) {
		LOG(3, pppSession->pppoeSession, "IPCP: skip ConfigReq - no IP (yet)\n");
		return;
	}

	LOG(3, pppSession->pppoeSession, "IPCP: send ConfigReq\n");

	if (!pppSession->unique_id)
	{
		if (!++last_id) ++last_id; // skip zero
		pppSession->unique_id = last_id;
	}

        q = pppoe_makeppp(buf, sizeof(buf), NULL, 0, pppSession, PPP_IPCP, 0, 0, 0);
	if (!q) return;

	*q = ConfigReq;
	q[1] = pppSession->unique_id & 0xf;	// ID, dont care, we only send one type of request
	*(uint16_t *) (q + 2) = htons(10);	// packet length
	q[4] = 3;				// ip address option
	q[5] = 6;				// option length
	*(in_addr_t *) (q + 6) = pppSession->ip_local;

	pppoe_sess_send(pppSession->pppoeSession, buf, 10 + (q - buf)); // send it
	restart_timer(pppSession, ipcp);
}

static void ipcp_open(PPPSession *pppSession)
{
	LOG(3, pppSession->pppoeSession, "IPCP: Opened, session is now active\n");

	change_state(pppSession, ipcp, Opened);

	(*pppSession->cb)(pppSession, PPPCBACT_IPCPOK);
#if 0

	// start IPv6 if configured and still in passive state
	if (session[s].ppp.ipv6cp == Stopped)
	{
		sendipv6cp(s, t);
		change_state(pppSession, ipv6cp, RequestSent);
	}
#endif
}

/* Process IPCP packet - pack points the PPP payload */
void processipcp(PPPSession *pppSession, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXETHER];
	uint8_t *q = 0;
	uint16_t hl;

	LOG_HEX(5, pppSession->pppoeSession, "IPCP", p, l);
	if (l < 4)
	{
		LOG(1, pppSession->pppoeSession, "Short IPCP %d bytes\n", l);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, pppSession->pppoeSession, "Length mismatch IPCP %u/%u\n", hl, l);
		return ;
	}
	l = hl;

	if (pppSession->ppp.phase < Network)
	{
	    	LOG(2, pppSession->pppoeSession, "IPCP %s ignored in %s phase\n", ppp_code(*p), ppp_phase(pppSession->ppp.phase));
		return;
	}

	LOG(3, pppSession->pppoeSession, "IPCP: recv %s, IPCP state: %s\n", ppp_code(*p), ppp_state(pppSession->ppp.ipcp));

	if ((pppSession->flags & SESSION_CLIENT)==0 && (pppSession->ip_remote==0 || pppSession->ip_local==0)) {
		LOG(3, pppSession->pppoeSession, "IPCP: ignore - no IP (yet)\n");
		return;
	}

	if (*p == ConfigAck)
	{
		switch (pppSession->ppp.ipcp)
		{
		case RequestSent:
		    	initialise_restart_count(pppSession, ipcp);
			change_state(pppSession, ipcp, AckReceived);
			break;

		case AckReceived:
		case Opened:
		    	LOG(2, pppSession->pppoeSession, "IPCP: ConfigAck in state %s?  Sending ConfigReq\n", ppp_state(pppSession->ppp.ipcp));
			sendipcp(pppSession);
			change_state(pppSession, ipcp, RequestSent);
			break;

		case AckSent:
			if (pppSession->flags & SESSION_CLIENT) {
				sessionsetup_client(pppSession);
			}
			ipcp_open(pppSession);
			break;

		default:
		    	LOG(2, pppSession->pppoeSession, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.ipcp));
		}
	}
	else if (*p == ConfigNak && (pppSession->flags & SESSION_CLIENT))
	{
		uint8_t *response = 0;
		uint8_t *o = p + 4;
		int length = l - 4;
		int gotip = 0;
		in_addr_t addr;

		while (length > 2)
		{
			if (!o[1] || o[1] > length) return;

			switch (*o)
			{
			case 3: // ip address
				gotip++; // seen address
				if (o[1] != 6) return;

				// We accept the remote address
				memcpy(&addr, o + 2, (sizeof addr));
				pppSession->ip_local=addr;

				break;

			case 129: // primary DNS
				if (o[1] != 6) return;

				addr = htonl(pppSession->dns1);
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			case 131: // secondary DNS
				if (o[1] != 6) return;

				addr = htonl(pppSession->dns2);
				if (memcmp(o + 2, &addr, sizeof(addr)))
				{
					q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			default:
				LOG(2, pppSession->pppoeSession, "    Rejecting PPP IPCP Option type %d\n", *o);
				q = ppp_conf_rej(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o);
				if (!q) return;
			}

			length -= o[1];
			o += o[1];
		}

		if (response)
		{
			l = q - response; // IPCP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else if (gotip)
		{
			// Send packet back as ConfigReq
			response = pppoe_makeppp(b, sizeof(b), p, l, pppSession, PPP_IPCP, 0, 0, 0);
			if (!response) return;
			*response = ConfigReq;
		}
		else
		{
			LOG(1, pppSession->pppoeSession, "No IP in IPCP request\n");
			return;
		}

#if 0
		switch (pppSession->ppp.ipcp)
		{
		case Closed:
			response = pppoe_makeppp(b, sizeof(b), p, 2, pppSession, PPP_IPCP, 0, 0, 0);
			if (!response) return;
			*response = TerminateAck;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(pppSession, ipcp);
			sendipcp(pppSession);
			if (*response == ConfigAck)
				change_state(pppSession, ipcp, AckSent);
			else
				change_state(pppSession, ipcp, RequestSent);

			break;

		case RequestSent:
			if (*response == ConfigAck)
				change_state(pppSession, ipcp, AckSent);

			break;

		case AckReceived:
			if (*response == ConfigAck)
				ipcp_open(pppSession);

			break;

		case Opened:
		    	initialise_restart_count(pppSession, ipcp);
			sendipcp(pppSession);
			/* fallthrough */

		case AckSent:
			if (*response == ConfigAck)
				change_state(pppSession, ipcp, AckSent);
			else
				change_state(pppSession, ipcp, RequestSent);

			break;

		default:
		    	LOG(2, pppSession->pppoeSession, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.ipcp));
			return;
		}
#endif

		LOG(3, pppSession->pppoeSession, "IPCP: send %s\n", ppp_code(*response));
		pppoe_sess_send(pppSession->pppoeSession, b, l + (response - b));
	}
	else if (*p == ConfigReq)
	{
		uint8_t *response = 0;
		uint8_t *o = p + 4;
		int length = l - 4;
		int gotip = 0;
		in_addr_t addr;

		while (length > 2)
		{
			if (!o[1] || o[1] > length) return;

			switch (*o)
			{
			case 3: // ip address
				gotip++; // seen address
				if (o[1] != 6) return;

				if (pppSession->flags & SESSION_CLIENT) {
					// We accept the remote address
					memcpy(&addr, o + 2, (sizeof addr));
					pppSession->ip_remote=addr;
				}

				addr = pppSession->ip_remote;
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					uint8_t *oq = q;
					q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q || (q != oq && *response == ConfigRej))
					{
						sessionshutdown(pppSession, 1, "Can't negotiate IPCP.");
						return;
					}
				}

				break;

			case 129: // primary DNS
				if (o[1] != 6) return;

				addr = htonl(pppSession->dns1);
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			case 131: // secondary DNS
				if (o[1] != 6) return;

				addr = htonl(pppSession->dns2);
				if (memcmp(o + 2, &addr, sizeof(addr)))
				{
					q = ppp_conf_nak(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			default:
				LOG(2, pppSession->pppoeSession, "    Rejecting PPP IPCP Option type %d\n", *o);
				q = ppp_conf_rej(pppSession, b, sizeof(b), PPP_IPCP, &response, q, p, o);
				if (!q) return;
			}

			length -= o[1];
			o += o[1];
		}

		if (response)
		{
			l = q - response; // IPCP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else if (gotip)
		{
			// Send packet back as ConfigAck
			response = pppoe_makeppp(b, sizeof(b), p, l, pppSession, PPP_IPCP, 0, 0, 0);
			if (!response) return;
			*response = ConfigAck;
		}
		else
		{
			LOG(1, pppSession->pppoeSession, "No IP in IPCP request\n");
			return;
		}

		switch (pppSession->ppp.ipcp)
		{
		case Closed:
			response = pppoe_makeppp(b, sizeof(b), p, 2, pppSession, PPP_IPCP, 0, 0, 0);
			if (!response) return;
			*response = TerminateAck;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(pppSession, ipcp);
			sendipcp(pppSession);
			if (*response == ConfigAck)
				change_state(pppSession, ipcp, AckSent);
			else
				change_state(pppSession, ipcp, RequestSent);

			break;

		case RequestSent:
			if (*response == ConfigAck)
				change_state(pppSession, ipcp, AckSent);

			break;

		case AckReceived:
			if (*response == ConfigAck)
				ipcp_open(pppSession);

			break;

		case Opened:
		    	initialise_restart_count(pppSession, ipcp);
			sendipcp(pppSession);
			/* fallthrough */

		case AckSent:
			if (*response == ConfigAck)
				change_state(pppSession, ipcp, AckSent);
			else
				change_state(pppSession, ipcp, RequestSent);

			break;

		default:
		    	LOG(2, pppSession->pppoeSession, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.ipcp));
			return;
		}

		LOG(3, pppSession->pppoeSession, "IPCP: send %s\n", ppp_code(*response));
		pppoe_sess_send(pppSession->pppoeSession, b, l + (response - b));
	}
	else if (*p == TerminateReq)
	{
		switch (pppSession->ppp.ipcp)
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
		    	zero_restart_count(pppSession, ipcp);
			change_state(pppSession, ipcp, Closing);
			break;

		default:
		    	LOG(2, pppSession->pppoeSession, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(pppSession->ppp.ipcp));
			return;
		}

		*p = TerminateAck;	// send ack
		q = pppoe_makeppp(b, sizeof(b), p, l, pppSession, PPP_IPCP, 0, 0, 0);
		if (!q) return;

		LOG(3, pppSession->pppoeSession, "IPCP: send %s\n", ppp_code(*q));
		pppoe_sess_send(pppSession->pppoeSession, b, l + (q - b));
	}
	else if (*p != CodeRej)
	{
		ppp_code_rej(pppSession, PPP_IPCP, "IPCP", p, l, b, sizeof(b));
	}
}

// process outgoing IP
//
// (i.e. this routine writes to data[-8]).
void processip_out(PPPSession *pppSession, uint8_t *buf, int len)
{
	uint8_t etherbuf[MAXETHER];
	uint8_t *q;
	uint8_t *data = buf;	// Keep a copy of the originals.
	int size = len;

	uint8_t fragbuf[MAXETHER + 20];

	if (len < MIN_IP_SIZE)
	{
		LOG(1, pppSession->pppoeSession, "Short IP, %d bytes\n", len);
		return;
	}
	if (len >= MAXETHER)
	{
		LOG(1, pppSession->pppoeSession, "Oversize IP packet %d bytes\n", len);
		return;
	}

	if (len > pppSession->mru || (pppSession->mrru && len > pppSession->mrru))
	{
		LOG(3, pppSession->pppoeSession, "Packet size more than session MRU\n");
		return;
	}

#if 0
	// DoS prevention: enforce a maximum number of packets per 0.1s for a session
	if (config->max_packets > 0)
	{
		if (sess_local[s].last_packet_out == TIME)
		{
			int max = config->max_packets;

			// All packets for throttled sessions are handled by the
			// master, so further limit by using the throttle rate.
			// A bit of a kludge, since throttle rate is in kbps,
			// but should still be generous given our average DSL
			// packet size is 200 bytes: a limit of 28kbps equates
			// to around 180 packets per second.
			if (!config->cluster_iam_master && sp->throttle_out && sp->throttle_out < max)
				max = sp->throttle_out;

			if (++sess_local[s].packets_out > max)
			{
				sess_local[s].packets_dropped++;
				return;
			}
		}
		else
		{
			if (sess_local[s].packets_dropped)
			{
				INC_STAT(tun_rx_dropped, sess_local[s].packets_dropped);
				LOG(3, s, t, "Dropped %u/%u packets to %s for %suser %s\n",
					sess_local[s].packets_dropped, sess_local[s].packets_out,
					fmtaddr(ip, 0), sp->throttle_out ? "throttled " : "",
					sp->user);
			}

			sess_local[s].last_packet_out = TIME;
			sess_local[s].packets_out = 1;
			sess_local[s].packets_dropped = 0;
		}
	}

	// adjust MSS on SYN and SYN,ACK packets with options
	if ((ntohs(*(uint16_t *) (buf + 6)) & 0x1fff) == 0 && buf[9] == IPPROTO_TCP) // first tcp fragment
	{
		int ihl = (buf[0] & 0xf) * 4; // length of IP header
		if (len >= ihl + 20 && (buf[ihl + 13] & TCP_FLAG_SYN) && ((buf[ihl + 12] >> 4) > 5))
			adjust_tcp_mss(s, t, buf, len, buf + ihl);
	}

	if (sp->tbf_out)
	{
		if (!config->no_throttle_local_IP || !sessionbyip(ip_src))
		{
			// Are we throttling this session?
			if (config->cluster_iam_master)
				tbf_queue_packet(sp->tbf_out, data, size);
			else
				master_throttle_packet(sp->tbf_out, data, size);
			return;
		}
	}

	if (sp->walled_garden && !config->cluster_iam_master)
	{
		// We are walled-gardening this
		master_garden_packet(s, data, size);
		return;
	}

#endif
	if(pppSession->bundle != NULL && pppSession->bundle->num_of_links > 1)
	{
		PPPSession *members[MAXBUNDLESES];
		PPPBundle *b = pppSession->bundle;
		uint32_t num_of_links, nb_opened;
		int i;

		num_of_links = b->num_of_links;
		nb_opened = 0;
		for (i = 0;i < num_of_links;i++)
		{
			PPPSession *pS = b->members[i];
			if (pS->ppp.lcp == Opened)
			{
				members[nb_opened] = pS;
				nb_opened++;
			}
		}

		if (nb_opened < 1)
		{
			LOG(3, pppSession->pppoeSession, "MPPP: PROCESSIPOUT ERROR, no session opened in bundle:%d\n", b->id);
			return;
		}

		num_of_links = nb_opened;
		b->current_ses = (b->current_ses + 1) % num_of_links;
		pppSession = members[b->current_ses];
		// sp = &session[s];
		LOG(4, pppSession->pppoeSession, "MPPP: (BEGIN) Session number becomes: %d\n", pppSession->id);

		if (num_of_links > 1)
		{
			if(len > MINFRAGLEN)
			{
				//for rotate traffic among the member links
				uint32_t divisor = num_of_links;
				if (divisor > 2)
					divisor = divisor/2 + (divisor & 1);

				// Partition the packet to "num_of_links" fragments
				uint32_t fraglen = len / divisor;
				uint32_t last_fraglen = fraglen + len % divisor;
				uint32_t remain = len;

				// send the first packet
				uint8_t *p = pppoe_makeppp(fragbuf, sizeof(fragbuf), buf, fraglen, pppSession, PPP_IP, 0, b, MP_BEGIN);
				if (!p) return;
				pppoe_sess_send(pppSession->pppoeSession, fragbuf, fraglen + (p-fragbuf)); // send it...

				// statistics
				// update_session_out_stat(s, sp, fraglen);

				remain -= fraglen;
				while (remain > last_fraglen)
				{
					b->current_ses = (b->current_ses + 1) % num_of_links;
					pppSession = members[b->current_ses];
					// sp = &session[s];
					LOG(4, pppSession->pppoeSession, "MPPP: (MIDDLE) Session number becomes: %d\n", pppSession->id);
					p = pppoe_makeppp(fragbuf, sizeof(fragbuf), buf+(len - remain), fraglen, pppSession, PPP_IP, 0, b, 0);
					if (!p) return;
					pppoe_sess_send(pppSession->pppoeSession, fragbuf, fraglen + (p-fragbuf)); // send it...
					// update_session_out_stat(s, sp, fraglen);
					remain -= fraglen;
				}
				// send the last fragment
				b->current_ses = (b->current_ses + 1) % num_of_links;
				pppSession = members[b->current_ses];
				// sp = &session[s];
				LOG(4, pppSession->pppoeSession, "MPPP: (END) Session number becomes: %d\n", pppSession->id);
				p = pppoe_makeppp(fragbuf, sizeof(fragbuf), buf+(len - remain), remain, pppSession, PPP_IP, 0, b, MP_END);
				if (!p) return;
				pppoe_sess_send(pppSession->pppoeSession, fragbuf, remain + (p-fragbuf)); // send it...
				// update_session_out_stat(s, sp, remain);
				if (remain != last_fraglen)
					LOG(3, pppSession->pppoeSession, "PROCESSIPOUT ERROR REMAIN != LAST_FRAGLEN, %d != %d\n", remain, last_fraglen);
			}
			else
			{
				// Send it as one frame
				uint8_t *p = pppoe_makeppp(fragbuf, sizeof(fragbuf), buf, len, pppSession, PPP_IP, 0, b, MP_BOTH_BITS);
				if (!p) return;
				pppoe_sess_send(pppSession->pppoeSession, fragbuf, len + (p-fragbuf)); // send it...
				LOG(4, pppSession->pppoeSession, "MPPP: packet sent as one frame\n");
				// update_session_out_stat(s, sp, len);
			}
		}
		else
		{
			// Send it as one frame (NO MPPP Frame)
			// uint8_t *p = opt_makeppp(buf, len, s, t, PPP_IP, 0, 0, 0);
			// tunnelsend(p, len + (buf-p), t); // send it...
			// update_session_out_stat(s, sp, len);

			/* Make a new packet for the moment */
        		q = pppoe_makeppp(etherbuf, sizeof(etherbuf), buf, len, pppSession, PPP_IP, 0, 0, 0);
			pppoe_sess_send(pppSession->pppoeSession, etherbuf, len + (q - etherbuf)); // send it
		}
	}
	else
	{
		// uint8_t *p = opt_makeppp(buf, len, s, t, PPP_IP, 0, 0, 0);
		// tunnelsend(p, len + (buf-p), t); // send it...
		// update_session_out_stat(s, sp, len);
		/* Make a new packet for the moment */
        	q = pppoe_makeppp(etherbuf, sizeof(etherbuf), buf, len, pppSession, PPP_IP, 0, 0, 0);
		pppoe_sess_send(pppSession->pppoeSession, etherbuf, len + (q - etherbuf)); // send it
	}
}

/* Process IP packet - pack points the PPP payload */
void processip_in(PPPSession *pppSession, uint8_t *pack, int size)
{
	uint8_t buf[MAXETHER];
	uint8_t *q;
	LOG(3, pppSession->pppoeSession, "Recv IP Packet\n");

	if (pppSession->ppp.phase != Network || pppSession->ppp.ipcp != Opened)
                return;
	if (pppSession->link) {
		if (pppSession->link->ppp.phase != Network || pppSession->link->ppp.ipcp != Opened)
			return;

		processip_out(pppSession->link, pack, size);
#if 0
		if (pppSession->link->pppoeSession) {
        		q = pppoe_makeppp(buf, sizeof(buf), pack, size, pppSession->link, PPP_IP, 0, 0, 0);
			pppoe_sess_send(pppSession->link->pppoeSession, buf, size + (q - buf)); // send it
		}
#endif
	}
}

