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

void discovery_cb(PPPoESession *pppoeSession, int action)
{
	if (pppoeSession->server) {
		LOG(3, "discover server session started %s/%s\n", pppoeSession->ac_name, pppoeSession->service_name);
		pppoeSession->pppSession=ppp_new_session(pppoeSession);
		sendLCPConfigReq(pppoeSession->pppSession);
		change_state(pppoeSession->pppSession, lcp, RequestSent);

		discoveryClient(pppoeSession->iface, NULL, NULL, 10);
	}
}

int main() {
	struct event *ev1, *ev2;
	struct timeval five_seconds = {5,0};
	PPPoEInterface *pppoe;

	log_stream=stderr;
	srand(getpid());
	initEvent();
	pppoe=openPPPoEInterface(INTERFACE, discovery_cb);
	//discoveryServer(pppoe, NULL, NULL);
	discoveryClient(pppoe, NULL, NULL, 10);

	// ev1=event_new(base, pppoe->discoverySock, EV_TIMEOUT|EV_READ|EV_PERSIST, cb_func, (char *) "Reading event");
	// ev1=event_new(base, 0, EV_TIMEOUT, cb_func, (char *) "Reading event");

	// event_add(ev1, &five_seconds);
	dispatchEvent();
}

