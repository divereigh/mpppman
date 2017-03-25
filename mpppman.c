#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#elif defined(HAVE_LINUX_IF_PACKET_H)
#include <linux/if_packet.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif

#include "log.h"
#include "pppoe.h"
#include "event.h"
#include "ppp.h"
#include "lcp.h"
#include "auth.h"
#include "ip.h"

#define INTERFACE "vlan50"
int debuglevel=4;
time_t time_now = 0;

void cb_func(evutil_socket_t fd, short what, void *arg)
{
	const char *data = arg;
	printf("Got an event on socket %d:%s%s%s%s [%s]\n",
		(int) fd,
		(what&EV_TIMEOUT) ? " timeout" : "",
		(what&EV_READ)    ? " read" : "",
		(what&EV_WRITE)   ? " write" : "",
		(what&EV_SIGNAL)  ? " signal" : "",
		data);
}

PPPoESession *downstream=NULL;
PPPoESession *upstream=NULL;

/* Stages of sessions are:
Downstream
- pppoe accepted set trigger (1)
- LCP negotiated (with PAP Auth)
- Recieve PAP auth attempt, set trigger (2)
- Trigger (3) Send auth response
- Trigger (4) Negotiate IPCP, set trigger (5)
- Link sessions

Upstream
- Trigger (1): Initiate PPPoE
- LCP Negotiate
- Trigger (2): Send auth request
- (Expect an LCP renegotiate here)
- Wait for Auth response set trigger (3)
- IPCP Negotiate trigger (4)
- Trigger (5) Link sessions
*/
void ppp_cb(PPPSession *pppSession, int action)
{
	LOG(3, pppSession->pppoeSession, "ppp_cb called: action=%d\n", action);
	if (((pppSession->flags & SESSION_CLIENT)==0) && pppSession->pppoeSession == downstream) {
		// Downstream
		if (action==PPPCBACT_AUTHREQ) {
			if (upstream && upstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "We have downstream auth info - trigger upstream auth\n");
				// strcpy(upstream->pppSession->user, downstream->pppSession->user);
				// strcpy(upstream->pppSession->pass, downstream->pppSession->pass);
				// upstream->pppSession->flags |= SESSION_GOTAUTH;
				// downstream->pppSession->flags |= SESSION_GOTAUTH;
				set_auth(upstream->pppSession);
			}
		} else if (action==PPPCBACT_IPCPOK) {
			if (upstream && upstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "Link sessions\n");
				upstream->pppSession->link=downstream->pppSession;
				downstream->pppSession->link=upstream->pppSession;
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			downstream->closing=1;
			if (upstream && upstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "Un-link sessions and shutdown upstream\n");
				upstream->pppSession->link=NULL;
				downstream->pppSession->link=NULL;
				sessionshutdown(upstream->pppSession, 1, "Local terminate request");
			}
		}
	} else if (((pppSession->flags & SESSION_CLIENT)) && pppSession->pppoeSession == upstream) {
		// Upstream
		if (action==PPPCBACT_AUTHREQ) {
			if (downstream && downstream->pppSession && (downstream->pppSession->flags & SESSION_GOTAUTH)) {
				LOG(3, pppSession->pppoeSession, "Fetch auth info from downstream\n");
				strcpy(upstream->pppSession->user, downstream->pppSession->user);
				strcpy(upstream->pppSession->pass, downstream->pppSession->pass);
				upstream->pppSession->flags |= SESSION_GOTAUTH;
			}
		} else if (action==PPPCBACT_AUTHOK) {
			if (downstream && downstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "We have authok, flag this with downstream\n");
				LOG(3, pppSession->pppoeSession, "trigger downstream auth\n");
				downstream->pppSession->flags |= SESSION_AUTHOK;
				upstream->pppSession->flags |= SESSION_AUTHOK;
				// Wait for next auth request from downstream
			}
		} else if (action==PPPCBACT_IPCPOK) {
			if (downstream && downstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "trigger downstream IPCP\n");
				if (downstream->pppSession->ip_local != upstream->pppSession->ip_remote
					|| downstream->pppSession->ip_remote != upstream->pppSession->ip_local) {
					// Different (or new) IP addresses from upstream
					downstream->pppSession->ip_local=upstream->pppSession->ip_remote;
					downstream->pppSession->ip_remote=upstream->pppSession->ip_local;
					sendipcp(downstream->pppSession);
				} else {
					// Just link the sessions back together
					LOG(3, pppSession->pppoeSession, "Link sessions\n");
					upstream->pppSession->link=downstream->pppSession;
					downstream->pppSession->link=upstream->pppSession;
				}
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			upstream->closing=1;
			if (downstream && downstream->pppSession && downstream->closing==0) {
				LOG(3, pppSession->pppoeSession, "Unlink and restart upstream session\n");
				upstream->pppSession->link=NULL;
				downstream->pppSession->link=NULL;
				discoveryClient((PPPoEInterface *) pppSession->pppoeSession->iface, NULL, NULL, 10); // Lose the const
			}
		}
	}
}

void discovery_cb(PPPoESession *pppoeSession, int action)
{
	if (action) {
		if (pppoeSession->server) {
			LOG(3, pppoeSession, "discover server session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			downstream=pppoeSession;
			pppServer(pppoeSession, ppp_cb);

			// Trigger 1
			discoveryClient((PPPoEInterface *) pppoeSession->iface, NULL, NULL, 10); // Lose the const
		} else {
			LOG(3, pppoeSession, "discover client session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			upstream=pppoeSession;
			pppClient(pppoeSession, ppp_cb);
		}
	} else {
		// Shutdown session
		if (pppoeSession==downstream) {
			downstream=NULL;
		}
		if (pppoeSession==upstream) {
			upstream=NULL;
		}
	}
}

int main() {
	struct event *ev1, *ev2;
	struct timeval five_seconds = {5,0};
	PPPoEInterface *pppoe;

	log_stream=stdout;
	srand(getpid());
	initEvent();
	pppoe=openPPPoEInterface(INTERFACE, discovery_cb);
	discoveryServer(pppoe, NULL, NULL);
	//discoveryClient(pppoe, NULL, NULL, 10);

	// ev1=event_new(base, pppoe->discoverySock, EV_TIMEOUT|EV_READ|EV_PERSIST, cb_func, (char *) "Reading event");
	// ev1=event_new(base, 0, EV_TIMEOUT, cb_func, (char *) "Reading event");

	// event_add(ev1, &five_seconds);
	dispatchEvent();
}

