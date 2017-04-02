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

#define SINGLE_INTERFACE 0
#define INTERFACE_DN "vlan50"
#define INTERFACE_UP1 "vlan50"
#define INTERFACE_UP2 "vlan51"
#define MAX_LINK 10
int debuglevel=0;
int link_count=0;
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
PPPoESession *upstream[MAX_LINK];

PPPoEInterface *pppoe_dn;
PPPoEInterface *pppoe_up[MAX_LINK];

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
	int i;
	LOG(3, pppSession->pppoeSession, "ppp_cb called: action=%d\n", action);
	if (((pppSession->flags & SESSION_CLIENT)==0) && pppSession->pppoeSession == downstream) {
		// Downstream
		if (action==PPPCBACT_AUTHREQ) {
			for (i=0; i<MAX_LINK; i++) {
				if (upstream[i] && upstream[i]->pppSession) {
					LOG(3, pppSession->pppoeSession, "We have downstream auth info - trigger upstream %d auth\n", i);
					set_auth(upstream[i]->pppSession);
				}
			}
		} else if (action==PPPCBACT_IPCPOK) {
			for (i=0; i<MAX_LINK; i++) {
				if (upstream[i] && upstream[i]->pppSession) {
					LOG(3, pppSession->pppoeSession, "Link sessions to upstream %d\n", i);
					upstream[i]->pppSession->link=downstream->pppSession;
					downstream->pppSession->link=upstream[i]->pppSession;
					break;
				}
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			downstream->closing=1;
			downstream->pppSession->link=NULL;
			for (i=0; i<MAX_LINK; i++) {
				if (upstream[i] && upstream[i]->pppSession) {
					LOG(3, pppSession->pppoeSession, "Un-link sessions and shutdown upstream %d\n", i);
					upstream[i]->pppSession->link=NULL;
					sessionshutdown(upstream[i]->pppSession, 1, "Local terminate request");
				}
			}
		}
	} else if (((pppSession->flags & SESSION_CLIENT))) {
		// Upstream
		if (action==PPPCBACT_AUTHREQ) {
			if (downstream && downstream->pppSession && (downstream->pppSession->flags & SESSION_GOTAUTH)) {
				LOG(3, pppSession->pppoeSession, "Fetch auth info from downstream\n");
				strcpy(pppSession->user, downstream->pppSession->user);
				strcpy(pppSession->pass, downstream->pppSession->pass);
				pppSession->flags |= SESSION_GOTAUTH;
			}
		} else if (action==PPPCBACT_AUTHOK) {
			if (downstream && downstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "We have authok, flag this with downstream\n");
				downstream->pppSession->flags |= SESSION_AUTHOK;
				pppSession->flags |= SESSION_AUTHOK;
				// Wait for next auth request from downstream
			}
		} else if (action==PPPCBACT_IPCPOK) {
			if (downstream && downstream->pppSession) {
				if (downstream->pppSession->ip_local != pppSession->ip_remote
					|| downstream->pppSession->ip_remote != pppSession->ip_local) {
					// Different (or new) IP addresses from upstream1
					LOG(3, pppSession->pppoeSession, "trigger downstream IPCP\n");
					downstream->pppSession->ip_local=pppSession->ip_remote;
					downstream->pppSession->ip_remote=pppSession->ip_local;
					sendipcp(downstream->pppSession);
				} else {
					// Just link the sessions back together
					LOG(3, pppSession->pppoeSession, "Link sessions\n");
					pppSession->link=downstream->pppSession;
					if (downstream->pppSession->link==NULL) {
						downstream->pppSession->link=pppSession;
					}
				}
				/* Start another session */
				LOG(3, pppSession->pppoeSession, "Client count: %d\n", discoveryClientCount());
				if (discoveryClientCount()<link_count) {
					for (i=0; i<MAX_LINK && upstream[i]!=NULL; i++);
					if (i<MAX_LINK) {
						LOG(3, pppSession->pppoeSession, "Start client: %d\n", i);
						discoveryClient(pppoe_up[i], NULL, NULL, 10);
					}
				}
			}
		} else if (action==PPPCBACT_SHUTDOWN) {
			for (i=0; i<MAX_LINK && upstream[i]!=pppSession->pppoeSession; i++);
			if (i<MAX_LINK) {
				upstream[i]=NULL;
			}
				
			if (downstream && downstream->pppSession && downstream->closing==0) {
				LOG(3, pppSession->pppoeSession, "Unlink and restart session\n");
				pppSession->link=NULL;
				if (downstream->pppSession->link==pppSession) {
					for (i=0; i<MAX_LINK && upstream[i]==NULL || upstream[i]->pppSession==NULL; i++);
					if (i<MAX_LINK) {
						downstream->pppSession->link=upstream[i]->pppSession;
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
	int i;

	if (action) {
		if (pppoeSession->server) {
			LOG(3, pppoeSession, "discover server session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			downstream=pppoeSession;
			strcpy(pppoeSession->label, "dn ");
			pppServer(pppoeSession, ppp_cb);

			discoveryClient((PPPoEInterface *) pppoeSession->iface, NULL, NULL, 10); // Lose the const
		} else {
			LOG(3, pppoeSession, "discover client session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			for (i=0; i<MAX_LINK && upstream[i]; i++);
			if (i<MAX_LINK)
			{
				sprintf(pppoeSession->label, "up%d", i);
				upstream[i]=pppoeSession;
			} else {
				sysFatal("No more space for upstream\n");
			}
			pppClient(pppoeSession, ppp_cb);
		}
	} else {
		// Shutdown session
		if (pppoeSession==downstream) {
			downstream=NULL;
		}
		for (i=0; i<MAX_LINK && upstream[i]!=pppoeSession; i++);
		upstream[i]=NULL;
	}
}

int main(int argc, char *argv[]) {
	int i;
	log_stream=stdout;
	int opt_foreground=0;

	srand(getpid());
	initEvent();

	// scan args
	while ((i = getopt(argc, argv, "fd:s:c:")) >= 0)
	{
		switch (i)
		{
		case 'f':
			opt_foreground=1;
			log_stream=stdout;
			break;
		case 'd':
			debuglevel=atoi(optarg);
			break;
		case 'c':
			pppoe_up[link_count]=openPPPoEInterface(optarg, discovery_cb);
			link_count++;
			break;
		case 's':
			if (pppoe_dn) {
				sysFatal("Can only specify one server\n");
			}
			pppoe_dn=openPPPoEInterface(optarg, discovery_cb);
			break;
		default:
			printf("Args are:\n"
			       "\t-f\t\tStay in foreground\n"
			       "\t-d <debug>\tSet debuglevel\n"
			       "\t-h <hostname>\tForce hostname\n"
			       "\t-v\t\tDebug\n");

			return (0);
			break;
		}
	}

	if (!opt_foreground) {
		if (fork()) exit(0);
		setsid();
		if(!freopen("/dev/null", "r", stdin)) LOG(0, 0, 0, "Error freopen stdin: %s\n", strerror(errno));
		if(!freopen("/dev/null", "w", stdout)) LOG(0, 0, 0, "Error freopen stdout: %s\n", strerror(errno));
		if(!freopen("/dev/null", "w", stderr)) LOG(0, 0, 0, "Error freopen stderr: %s\n", strerror(errno));
	}

	discoveryServer(pppoe_dn, NULL, NULL);
	dispatchEvent();
}

