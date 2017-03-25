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

/* Process IP packet - pack points the PPP payload */
void processip(PPPSession *pppSession, uint8_t *pack, int size)
{
	uint8_t buf[MAXETHER];
	uint8_t *q;
	LOG(3, pppSession->pppoeSession, "Recv IP Packet\n");

	if (pppSession->ppp.phase != Network || pppSession->ppp.ipcp != Opened)
                return;
	if (pppSession->link) {
		if (pppSession->link->ppp.phase != Network || pppSession->link->ppp.ipcp != Opened)
			return;

		if (pppSession->link->pppoeSession) {
        		q = pppoe_makeppp(buf, sizeof(buf), pack, size, pppSession->link, PPP_IP, 0, 0, 0);
			pppoe_sess_send(pppSession->link->pppoeSession, buf, size + (q - buf)); // send it
		}
	}
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


