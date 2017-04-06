#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

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
int up_link_count=0;
int dn_link_count=0;
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

PPPoESession *downstream;
PPPoESession *upstream[MAX_LINK];

PPPoEInterface *pppoe_dn;
PPPoEInterface *pppoe_up[MAX_LINK];

char *iface_name_dn;
char *iface_name_up[MAX_LINK];

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
				if (upstream[i] && upstream[i]->pppSession && upstream[i]->pppSession->bundle!=NULL) {
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
				if (discoveryClientCount()<up_link_count) {
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
					for (i=0; i<MAX_LINK && (upstream[i]==NULL || upstream[i]->pppSession==NULL || upstream[i]->pppSession->bundle==NULL); i++);
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

	switch(action) {
	case DISC_CBACT_INIT:
		if (pppoeSession->server) {
			LOG(3, pppoeSession, "discover server session initialised %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			downstream=pppoeSession;
			strcpy(pppoeSession->label, "dn ");
			LOG(3, pppoeSession, "set label: %s\n", pppoeSession->label);
		} else {
			LOG(3, pppoeSession, "discover client session initialised %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			/* See if we already have this session */
			for (i=0; i<MAX_LINK && upstream[i]!=pppoeSession; i++);
			if (i==MAX_LINK)
			{
				/* Search for free spot */
				for (i=0; i<MAX_LINK && upstream[i]; i++);
				if (i<MAX_LINK) {
					sprintf(pppoeSession->label, "up%d", i);
					upstream[i]=pppoeSession;
					// LOG(3, pppoeSession, "set label: %s\n", pppoeSession->label);
				} else {
					sysFatal("No more space for upstream\n");
				}
			} else {
				sprintf(pppoeSession->label, "up%d", i);
			}
		}
		break;

	case DISC_CBACT_OPEN:
		if (pppoeSession->server) {
			LOG(3, pppoeSession, "discover server session opened %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
	
			pppServer(pppoeSession, ppp_cb);

			discoveryClient((PPPoEInterface *) pppoe_up[0], NULL, NULL, 10); // Lose the const
		} else {
			LOG(3, pppoeSession, "discover client session opened %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			pppClient(pppoeSession, ppp_cb);
		}
		break;

	case DISC_CBACT_SHUTDOWN:
		// Shutdown session
		if (pppoeSession==downstream) {
			LOG(3, pppoeSession, "discover server session shutdown %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			downstream=NULL;
			/* Kill all the upstream sessions */
			for (i=0; i<MAX_LINK; i++) {
				if (upstream[i]) {
					pppoeSessionKill(upstream[i]);
				}
			}
		} else {
			LOG(3, pppoeSession, "discover client session shutdown %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
			for (i=0; i<MAX_LINK && upstream[i]!=pppoeSession; i++);
			if (i<MAX_LINK) {
				upstream[i]=NULL;
			}
		}
		break;
	}
}

int main(int argc, char *argv[]) {
	int i;
	int opt_foreground=0;

	syslog_log=1;

	// scan args
	while ((i = getopt(argc, argv, "fd:s:c:")) >= 0)
	{
		switch (i)
		{
		case 'f':
			opt_foreground=1;
			log_stream=stdout;
			syslog_log=0;
			break;
		case 'd':
			debuglevel=atoi(optarg);
			break;
		case 'c':
			iface_name_up[up_link_count]=strdup(optarg);
			up_link_count++;
			break;
		case 's':
			if (iface_name_dn) {
				sysFatal("Can only specify one server\n");
			}
			iface_name_dn=strdup(optarg);
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
		if (fork()==0) {
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);
			setsid();

			syslog(LOG_DAEMON, "mpppman watcher started");
			/* Now fork again, to create a watcher */
			while (fork()!=0) {
				int status;
				wait(&status);
				syslog(LOG_DAEMON, "mpppman exited status: %d", status);
				sleep(2); // So we don't spin
			}
		} else {
			exit(0);
		}
	}
	initlog(argv[0]);
	LOG(1, NULL, "mpppman started\n");

	srand(getpid());
	initEvent();

	pppoe_dn=openPPPoEInterface(iface_name_dn, discovery_cb);
	for (i=0; i<up_link_count; i++) {
		pppoe_up[i]=openPPPoEInterface(iface_name_up[i], discovery_cb);
	}

	discoveryServer(pppoe_dn, NULL, NULL);
	dispatchEvent();
}

