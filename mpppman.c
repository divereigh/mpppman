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

#define INTERFACE1 "vlan50"
#define INTERFACE2 "vlan51"
int debuglevel=4;
time_t time_now = 0;
uint64_t time_now_ms = 0;		// Current time in milliseconds since epoch.

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
PPPoESession *upstream1;
PPPoESession *upstream2;

PPPoEInterface *pppoe1;
PPPoEInterface *pppoe2;

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
			if (upstream1 && upstream1->pppSession) {
				LOG(3, pppSession->pppoeSession, "We have downstream auth info - trigger upstream1 auth\n");
				// strcpy(upstream1->pppSession->user, downstream->pppSession->user);
				// strcpy(upstream1->pppSession->pass, downstream->pppSession->pass);
				// upstream1->pppSession->flags |= SESSION_GOTAUTH;
				// downstream->pppSession->flags |= SESSION_GOTAUTH;
				set_auth(upstream1->pppSession);
			}
		} else if (action==PPPCBACT_IPCPOK) {
			if (upstream1 && upstream1->pppSession) {
				LOG(3, pppSession->pppoeSession, "Link sessions\n");
				upstream1->pppSession->link=downstream->pppSession;
				downstream->pppSession->link=upstream1->pppSession;
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			downstream->closing=1;
			downstream->pppSession->link=NULL;
			if (upstream1 && upstream1->pppSession) {
				LOG(3, pppSession->pppoeSession, "Un-link sessions and shutdown upstream1\n");
				upstream1->pppSession->link=NULL;
				sessionshutdown(upstream1->pppSession, 1, "Local terminate request");
			}
			if (upstream2 && upstream1->pppSession) {
				LOG(3, pppSession->pppoeSession, "Un-link sessions and shutdown upstream2\n");
				upstream2->pppSession->link=NULL;
				sessionshutdown(upstream2->pppSession, 1, "Local terminate request");
			}
		}
	} else if (((pppSession->flags & SESSION_CLIENT)) && pppSession->pppoeSession == upstream1) {
		// Upstream
		if (action==PPPCBACT_AUTHREQ) {
			if (downstream && downstream->pppSession && (downstream->pppSession->flags & SESSION_GOTAUTH)) {
				LOG(3, pppSession->pppoeSession, "Fetch auth info from downstream\n");
				strcpy(upstream1->pppSession->user, downstream->pppSession->user);
				strcpy(upstream1->pppSession->pass, downstream->pppSession->pass);
				upstream1->pppSession->flags |= SESSION_GOTAUTH;
			}
		} else if (action==PPPCBACT_AUTHOK) {
			if (downstream && downstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "We have authok, flag this with downstream\n");
				LOG(3, pppSession->pppoeSession, "trigger downstream auth\n");
				downstream->pppSession->flags |= SESSION_AUTHOK;
				upstream1->pppSession->flags |= SESSION_AUTHOK;
				// Wait for next auth request from downstream
			}
		} else if (action==PPPCBACT_IPCPOK) {
			if (downstream && downstream->pppSession) {
				if (downstream->pppSession->ip_local != upstream1->pppSession->ip_remote
					|| downstream->pppSession->ip_remote != upstream1->pppSession->ip_local) {
					// Different (or new) IP addresses from upstream1
					LOG(3, pppSession->pppoeSession, "trigger downstream IPCP\n");
					downstream->pppSession->ip_local=upstream1->pppSession->ip_remote;
					downstream->pppSession->ip_remote=upstream1->pppSession->ip_local;
					sendipcp(downstream->pppSession);
#if 0
					/* Start another session */
					LOG(3, pppSession->pppoeSession, "Client count: %d\n", discoveryClientCount());
					if (discoveryClientCount()<2) {
						if (upstream1==NULL) {
							discoveryClient(pppoe1, NULL, NULL, 10); // Lose the const
						} else {
							discoveryClient(pppoe2, NULL, NULL, 10); // Lose the const
						}
					}
#endif
				} else {
					// Just link the sessions back together
					LOG(3, pppSession->pppoeSession, "Link sessions\n");
					upstream1->pppSession->link=downstream->pppSession;
					downstream->pppSession->link=upstream1->pppSession;
				}
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			upstream1->closing=1;
			if (downstream && downstream->pppSession && downstream->closing==0) {
				LOG(3, pppSession->pppoeSession, "Unlink and restart upstream1 session\n");
				upstream1->pppSession->link=NULL;
				if (downstream->pppSession->link==upstream1->pppSession) {
					if (upstream2 && upstream2->pppSession && upstream2->closing==0) {
						downstream->pppSession->link=upstream2->pppSession;
					} else {
						downstream->pppSession->link=NULL;
					}
				}
				discoveryClient((PPPoEInterface *) pppSession->pppoeSession->iface, NULL, NULL, 10); // Lose the const
			}
		}
	} else if (((pppSession->flags & SESSION_CLIENT)) && pppSession->pppoeSession == upstream2) {
		// Upstream
		if (action==PPPCBACT_AUTHREQ) {
			if (downstream && downstream->pppSession && (downstream->pppSession->flags & SESSION_GOTAUTH)) {
				LOG(3, pppSession->pppoeSession, "Fetch auth info from downstream\n");
				strcpy(upstream2->pppSession->user, downstream->pppSession->user);
				strcpy(upstream2->pppSession->pass, downstream->pppSession->pass);
				upstream2->pppSession->flags |= SESSION_GOTAUTH;
			}
		} else if (action==PPPCBACT_AUTHOK) {
			if (downstream && downstream->pppSession) {
				upstream2->pppSession->flags |= SESSION_AUTHOK;
				// Wait for next auth request from downstream
			}
		} else if (action==PPPCBACT_IPCPOK) {
			if (downstream && downstream->pppSession) {
				if (downstream->pppSession->ip_local == upstream2->pppSession->ip_remote
					|| downstream->pppSession->ip_remote == upstream2->pppSession->ip_local) {
					// Just link the sessions back together
					LOG(3, pppSession->pppoeSession, "Link sessions\n");
					upstream2->pppSession->link=downstream->pppSession;
				} else {
					LOG(1, pppSession->pppoeSession, "Mismatched IP address\n");
				}
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			upstream2->closing=1;
			if (downstream && downstream->pppSession && downstream->closing==0) {
				LOG(3, pppSession->pppoeSession, "Unlink and restart upstream2 session\n");
				upstream2->pppSession->link=NULL;
				if (downstream->pppSession->link==upstream2->pppSession) {
					if (upstream1 && upstream1->pppSession && upstream1->closing==0) {
						downstream->pppSession->link=upstream1->pppSession;
					} else {
						downstream->pppSession->link=NULL;
					}
				}
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
			strcpy(pppoeSession->label, "dn ");
			pppServer(pppoeSession, ppp_cb);

			// Trigger 1
			discoveryClient((PPPoEInterface *) pppoeSession->iface, NULL, NULL, 10); // Lose the const
		} else {
			LOG(3, pppoeSession, "discover client session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			if (upstream1==NULL) {
				strcpy(pppoeSession->label, "up1");
				upstream1=pppoeSession;
			} else {
				strcpy(pppoeSession->label, "up2");
				upstream2=pppoeSession;
			}
			pppClient(pppoeSession, ppp_cb);
		}
	} else {
		// Shutdown session
		if (pppoeSession==downstream) {
			downstream=NULL;
		}
		if (pppoeSession==upstream1) {
			upstream1=NULL;
		}
		if (pppoeSession==upstream2) {
			upstream2=NULL;
		}
	}
}

int main() {
	struct event *ev1, *ev2;
	struct timeval five_seconds = {5,0};

	log_stream=stdout;
	srand(getpid());
	initEvent();
	pppoe1=openPPPoEInterface(INTERFACE1, discovery_cb);
	pppoe2=openPPPoEInterface(INTERFACE2, discovery_cb);
	discoveryServer(pppoe1, NULL, NULL);
	//discoveryClient(pppoe, NULL, NULL, 10);

	// ev1=event_new(base, pppoe->discoverySock, EV_TIMEOUT|EV_READ|EV_PERSIST, cb_func, (char *) "Reading event");
	// ev1=event_new(base, 0, EV_TIMEOUT, cb_func, (char *) "Reading event");

	// event_add(ev1, &five_seconds);
	dispatchEvent();
}

