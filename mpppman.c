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

void ppp_cb(PPPSession *pppSession, int action)
{
	LOG(3, pppSession->pppoeSession, "ppp_cb called: action=%d\n", action);
	if (((pppSession->flags & SESSION_CLIENT)==0) && pppSession->pppoeSession == downstream) {
		if (action==1) {
			if (upstream && upstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "trigger upstream auth\n");
				strcpy(upstream->pppSession->user, downstream->pppSession->user);
				strcpy(upstream->pppSession->pass, downstream->pppSession->pass);
				upstream->pppSession->flags |= SESSION_GOTAUTH;
				do_auth(upstream->pppSession);
			}
		} else if (action==3) {
			if (upstream && upstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "Link sessions\n");
				upstream->pppSession->link=downstream->pppSession;
				downstream->pppSession->link=upstream->pppSession;
			}
		} else if (action==4) {
			if (upstream && upstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "Un-link sessions and shutdown upstream\n");
				upstream->pppSession->link=NULL;
				downstream->pppSession->link=NULL;
				sessionshutdown(upstream->pppSession, 1, "Local terminate request");
			}
		}
	} else if (((pppSession->flags & SESSION_CLIENT)) && pppSession->pppoeSession == upstream) {
		if (action==2) {
			if (downstream && downstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "trigger downstream auth\n");
				downstream->pppSession->flags |= SESSION_AUTHOK;
				// Wait for another auth request
			}
		} else if (action==3) {
			if (downstream && downstream->pppSession) {
				LOG(3, pppSession->pppoeSession, "trigger downstream IPCP\n");
				downstream->pppSession->ip_local=upstream->pppSession->ip_remote;
				downstream->pppSession->ip_remote=upstream->pppSession->ip_local;
				sendipcp(downstream->pppSession);
			}
		}
	}
}

void discovery_cb(PPPoESession *pppoeSession, int action)
{
	if (pppoeSession->server) {
		LOG(3, pppoeSession, "discover server session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
		downstream=pppoeSession;
		pppServer(pppoeSession, ppp_cb);

		discoveryClient((PPPoEInterface *) pppoeSession->iface, NULL, NULL, 10); // Lose the const
	} else {
		LOG(3, pppoeSession, "discover client session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
		upstream=pppoeSession;
		pppClient(pppoeSession, ppp_cb);
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

