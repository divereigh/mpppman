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

typedef struct PPPoESessionStruct PPPoESession;

typedef void (*discovery_cb_func)(PPPoESession *, int);

// For MD5 results
typedef uint8_t hasht[16];

#define MAX_PPPOE_SESSION 10

typedef struct PPPSessionStruct PPPSession;

typedef struct InterfaceStruct {
	int id;				/* ID number */
	char name[IFNAMSIZ+1];		/* Interface name */
	int discoverySock;		/* Socket for discovery frames */
	int sessionSock;		/* Socket for session frames */
	int clientOK;			/* Client requests allowed (PADI, PADR) */
	int acOK;			/* AC replies allowed (PADO, PADS) */
	struct event *discoveryEvent;	/* Event for packet to be read */
	struct event *sessionEvent;	/* Event for packet to be read */
	discovery_cb_func discovery_cb;	/* Function called on successful/teardown discovery */
	uint8_t mac[ETH_ALEN];		/* Local MAC address */
	char server_ac_name[64];	/* Server AC name */
	char server_service_name[64];	/* Service name to match against client */
	char client_ac_name[64];	/* AC name to match against server */
	char client_service_name[64];	/* Service name to send to server */
} PPPoEInterface;

struct PPPoESessionStruct {
	int id;					/* ID number */
	unsigned int epoch;			/* Epoch when last activity was seen */
	uint16_t sid;				/* Session number (zero if not fully open) */
	char label[10];				/* Label for the logs */
	const PPPoEInterface *iface;		/* Interface */
	uint8_t peerMac[ETH_ALEN];		/* Peer's MAC address */
	PPPSession *pppSession;			/* Matching PPP Session */
	int lastPacketType;			/* Last packet type sent (PADI, PADO, PADR, PADS) */
	uint8_t hostUniq[ETH_ALEN];		/* Host Uniq for this */
	size_t hostUniqLen;			/* Length of above */
	int server;				/* True if this we are a server */
	int closing;				/* Is this session closing */
	char ac_name[64];			/* Server AC name */
	char service_name[64];			/* Service name */
	char avc_id[64];			/* NBN Circuit ID */
	struct event *timerEvent;		/* Timer event */
};

PPPoEInterface * openPPPoEInterface(char const *ifname, discovery_cb_func cb);
void processSession(const PPPoEInterface *iface, uint8_t *pack, int size);
void processDiscovery(const PPPoEInterface *iface, uint8_t *pack, int size);
void pppoe_sess_send(const PPPoESession *pppoeSession, const uint8_t *pack, uint16_t l);
uint8_t *pppoe_session_header(uint8_t *b, const PPPoESession *pppoeSession);
void pppoe_incr_header_length(uint8_t *b, int n);
void discoveryServer(PPPoEInterface *iface, char *ac_name, char *service_name);
void discoveryClient(PPPoEInterface *iface, char *ac_name, char *service_name, int attempts);
void pppoeSessionKill(PPPoESession *pppoeSession);
int discoveryClientCount();
#endif
