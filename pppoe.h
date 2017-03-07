#ifndef __PPPOE_H
#define __PPPOE_H
#include "config.h"

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

// For MD5 results
typedef uint8_t hasht[16];

#define MAX_PPPOE_SESSION 10

typedef struct PPPSessionStruct PPPSession;

typedef struct InterfaceStruct {
	char name[IFNAMSIZ+1];		/* Interface name */
	int discoverySock;		/* Socket for discovery frames */
	int sessionSock;		/* Socket for session frames */
	int clientOK;			/* Client requests allowed (PADI, PADR) */
	int acOK;			/* AC replies allowed (PADO, PADS) */
	struct event *discoveryEvent;	/* Event for packet to be read */
	struct event *sessionEvent;	/* Event for packet to be read */
	unsigned char mac[ETH_ALEN];	/* MAC address */
} PPPoEInterface;

typedef struct PPPoESessionStruct {
	unsigned int epoch;			/* Epoch when last activity was seen */
	uint16_t sid;				/* Session number */
	PPPoEInterface const *iface;		/* Interface */
	unsigned char peerMac[ETH_ALEN];	/* Peer's MAC address */
	PPPSession *pppSession;			/* Matching PPP Session */
} PPPoESession;

PPPoEInterface * openPPPoEInterface(char const *ifname, int clientOK, int acOK, struct event_base *);
void processSession(const PPPoEInterface *iface, uint8_t *pack, int size);
void processDiscovery(const PPPoEInterface *iface, uint8_t *pack, int size);
void pppoe_sess_send(const PPPoESession *pppoeSession, const uint8_t *pack, uint16_t l);
uint8_t *pppoe_session_header(uint8_t *b, const PPPoESession *pppoeSession);
void pppoe_incr_header_length(uint8_t *b, int n);
#endif
