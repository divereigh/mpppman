#include "config.h"
// TODO: Sort out retransmission of lost PADx packets

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_LINUX_IF_PPPOX_H
#include <linux/if_pppox.h>
#endif

#include "if.h"
#include "log.h"
#include "pppoe.h"
#include "ppp.h"
#include "md5.h"
#include "lcp.h"
#include "common.h"
#include "event.h"


#define SESS_CODE           0x00
#define DEFAULT_PPPOE_AC_NAME "mpppman"

static int init_done=0;
PPPoESession pppoe_sessions[MAX_PPPOE_SESSION];
PPPoEInterface pppoe_interface[MAX_PPPOE_SESSION];

static uint32_t hostUniq=0;	// Contains an incrementing Host Uniq

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t mt_addr[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static char *code_pad[] = {
	"PADI",
	"PADO",
	"PADR",
	"PADS",
	"PADT",
	"SESS",
	NULL
};

enum
{
	INDEX_PADI = 0,
	INDEX_PADO,
	INDEX_PADR,
	INDEX_PADS,
	INDEX_PADT,
	INDEX_SESS
};

static void pppoe_send_PADI(const PPPoEInterface *iface);
static void pppoe_send_PADT(const PPPoEInterface *iface, uint16_t sid, const uint8_t *addr);

char * get_string_codepad(uint8_t codepad)
{
	char * ptrch = NULL;
	switch(codepad)
	{
		case PADI_CODE:
		ptrch = code_pad[INDEX_PADI];
		break;

		case PADO_CODE:
		ptrch = code_pad[INDEX_PADO];
		break;

		case PADR_CODE:
		ptrch = code_pad[INDEX_PADR];
		break;

		case PADS_CODE:
		ptrch = code_pad[INDEX_PADS];
		break;

		case PADT_CODE:
		ptrch = code_pad[INDEX_PADT];
		break;

		case SESS_CODE:
		ptrch = code_pad[INDEX_SESS];
		break;
	}
	
	return ptrch;
}

static void initDiscovery() {
	memset(pppoe_interface, 0, sizeof(PPPoEInterface) * MAX_PPPOE_SESSION);
	memset(pppoe_sessions, 0, sizeof(PPPoESession) * MAX_PPPOE_SESSION);
	
	hostUniq=random() & 0xffff;
	hostUniq <<= 16;
	hostUniq +=random() & 0xffff;

	init_done=1;
}

void PPPoE_cb_func(evutil_socket_t fd, short what, void *arg)
{
	uint8_t buf[65536];
	int s;
	const PPPoEInterface *pppoe = (PPPoEInterface *) arg;

	LOG(5, NULL, "===========================================\n");
	LOG(5, NULL, "Got an event on socket %d:%s%s%s%s %s\n",
		(int) fd,
		(what&EV_TIMEOUT) ? " timeout" : "",
		(what&EV_READ)    ? " read" : "",
		(what&EV_WRITE)   ? " write" : "",
		(what&EV_SIGNAL)  ? " signal" : "",
		pppoe->name);
	time(&time_now);
	if ((s = read(fd, buf, sizeof(buf))) > 0) {
		if (fd==pppoe->discoverySock) {
			processDiscovery(pppoe, buf, s);
		} else if (fd==pppoe->sessionSock) {
			processSession(pppoe, buf, s);
		}
	}
}

/* Find a session that has the given session id & MacAddr
*/
static PPPoESession *pppoeFindSessionBySID(uint16_t sid, uint8_t *addr)
{
	int i;

	for (i=0; i<MAX_PPPOE_SESSION; i++) {
		if (pppoe_sessions[i].sid==sid && (addr==NULL || memcmp(pppoe_sessions[i].peerMac, addr, ETH_ALEN)==0)) {
			return(&pppoe_sessions[i]);
		}
	}
	return(NULL);
}

/* Find a session that has the given Host Uniq
*/
static PPPoESession *pppoeFindSessionByHostUniq(uint8_t *hostUniq, size_t hostUniqLen)
{
	int i;

	for (i=0; i<MAX_PPPOE_SESSION; i++) {
		if (pppoe_sessions[i].hostUniqLen == hostUniqLen) {
			if (memcmp(pppoe_sessions[i].hostUniq, hostUniq, hostUniqLen)==0) {
				return(&pppoe_sessions[i]);
			}
		}
	}
	return(NULL);
}

/* Find a free session
*/
static PPPoESession *pppoeFindSessionFree()
{
	int i;

	for (i=0; i<MAX_PPPOE_SESSION; i++) {
		// LOG(0, NULL, "Checking %d: sid=%d, hostUniqLen=%d\n", i, pppoe_sessions[i].sid, (long) pppoe_sessions[i].hostUniqLen);
		if (pppoe_sessions[i].sid==0 && pppoe_sessions[i].hostUniqLen==0) {
			pppoe_sessions[i].id=i;
			return(&pppoe_sessions[i]);
		}
	}
	return(NULL);
}

/* Allocate and fill new session - returns PPPoESession */
PPPoESession * pppoeNewSession(const PPPoEInterface *iface, uint8_t *hostUniq, size_t hostUniqLen)
{
	PPPoESession *pppoeSession;

	if (hostUniq!=NULL && (pppoeSession=pppoeFindSessionByHostUniq(hostUniq, hostUniqLen)) != NULL) {
		return(NULL);
	} else {
		if ((pppoeSession=pppoeFindSessionFree()) == NULL) {
			LOG(0, NULL, "pppoeNewSession: No free PPPoESession available\n");
			return(NULL);
		}
	}
	
	memcpy(pppoeSession->hostUniq, hostUniq, hostUniqLen);
	pppoeSession->hostUniqLen=hostUniqLen;
	pppoeSession->iface=iface;
	LOG(3, pppoeSession, "PPPoESession allocated with hostUniq=%s\n", fmtBinary(pppoeSession->hostUniq, hostUniqLen));
	return(pppoeSession);
}

int pppoeIsSessionUnique(char *avc_id)
{
	int i;

	return(1);
	for (i=0; i<MAX_PPPOE_SESSION; i++) {
		// LOG(0, NULL, "Checking %d: sid=%d, hostUniqLen=%d\n", i, pppoe_sessions[i].sid, (long) pppoe_sessions[i].hostUniqLen);
		if ((pppoe_sessions[i].sid!=0 || pppoe_sessions[i].hostUniqLen!=0) && strcmp(avc_id, pppoe_sessions[i].avc_id)==0) {
			return(0);
		}
	}
	return(1);
}

void pppoeSessionKill(PPPoESession *pppoeSession)
{
	if (pppoeSession->sid) {
		/* Only do this for open sessions */
		pppoe_send_PADT(pppoeSession->iface, pppoeSession->sid, pppoeSession->peerMac);
	}
	if (pppoeSession->timerEvent) {
		stopTimer(pppoeSession->timerEvent);
		pppoeSession->timerEvent=NULL;
	}
	(pppoeSession->iface->discovery_cb)((void *) pppoeSession, DISC_CBACT_SHUTDOWN); // OK I know it's a const
	memset((void *) pppoeSession, 0, sizeof(PPPoESession)); // OK I know it's a const
}

#if 0
/* Allocate and fill new session - returns PPPoESession */
PPPoESession * pppoeNewSession(const PPPoEInterface *iface, const uint8_t *addr, uint16_t sid)
{
	PPPoESession *pppoeSession;

	if (sid && (pppoeSession=pppoeFindSessionBySID(sid, NULL)) != NULL) {
		memset(pppoeSession, 0, sizeof(PPPoESession));
	} else {
		if ((pppoeSession=pppoeFindSessionFree()) == NULL) {
			LOG(0, NULL, "No free PPPoESession available\n");
		}
	}
	
	if (sid==0) {
		do {
			sid=random() & 0xffff; // Lower 16 bits
		} while(pppoeFindSessionBySID(sid, NULL)!=NULL);
	}

	pppoeSession->sid=sid;
	pppoeSession->iface=iface;
	memcpy(pppoeSession->peerMac, addr, ETH_ALEN);
	LOG(3, pppoeSession, "PPPoESession allocated with sid=0x%04x\n", pppoeSession->sid);
	return(pppoeSession);
}
#endif

/**********************************************************************
*%FUNCTION: openPPPoEInterface
*%ARGUMENTS:
* ifname -- name of interface
*%RETURNS:
* A PPPoEInterface with discovery and session sockets open
*%DESCRIPTION:
* Opens a PPPoE Interface
***********************************************************************/
PPPoEInterface *
openPPPoEInterface(char const *ifname, discovery_cb_func cb)
{
	int i;
	PPPoEInterface *pppoe;

	if (!init_done) {
		initDiscovery();
	}

	LOG(3, NULL, "pppoe: open interface %s\n", ifname);
	/* Look for an existing interface */
	for (i=0; i<MAX_PPPOE_SESSION && pppoe_interface[i].name[0]; i++) {
		if (strcmp(ifname, pppoe_interface[i].name)==0) {
			LOG(3, NULL, "pppoe: interface %s already open\n", ifname);
			return(&pppoe_interface[i]);
		}
	}

	if (i==MAX_PPPOE_SESSION) {
		sysFatal("No more PPPoEInterface slots");
	}

	pppoe=&pppoe_interface[i];

	pppoe->discoverySock = openInterface(ifname, ETH_P_PPP_DISC, pppoe->mac, NULL);
	pppoe->sessionSock = openInterface(ifname, ETH_P_PPP_SES, NULL, NULL);
	strncpy(pppoe->name, ifname, sizeof(pppoe->name));

	pppoe->discoveryEvent=eventSocket(pppoe->discoverySock, PPPoE_cb_func, (void *) pppoe);
	pppoe->sessionEvent=eventSocket(pppoe->sessionSock, PPPoE_cb_func, (void *) pppoe);

	pppoe->discovery_cb=cb;
	return(pppoe);
}

static uint8_t * setup_header(uint8_t *pack, const uint8_t *src, const uint8_t *dst, int code, uint16_t sid, uint16_t h_proto)
{
	uint8_t * p;

	// 14 bytes ethernet Header + 6 bytes header pppoe
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	memcpy(ethhdr->h_source, src, ETH_ALEN);
	memcpy(ethhdr->h_dest, dst, ETH_ALEN);
	ethhdr->h_proto = htons(h_proto);

	hdr->ver = 1;
	hdr->type = 1;
	hdr->code = code;
	hdr->sid = htons(sid);
	hdr->length = 0;

	p = (uint8_t *)(pack + ETH_HLEN + sizeof(*hdr));

	return p;
}

// generate cookie
static void pppoe_gen_cookie(const uint8_t *serv_hwaddr, const uint8_t *client_hwaddr, uint8_t *out)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	// MD5_Update(&ctx, config->l2tp_secret, strlen(config->l2tp_secret));
	MD5_Update(&ctx, (void *) serv_hwaddr, ETH_ALEN);
	MD5_Update(&ctx, (void *) client_hwaddr, ETH_ALEN);
	MD5_Final(out, &ctx);
}

// check cookie
static int pppoe_check_cookie(const uint8_t *serv_hwaddr, const uint8_t *client_hwaddr, uint8_t *cookie)
{
	hasht hash;

	pppoe_gen_cookie(serv_hwaddr, client_hwaddr, hash);

	return memcmp(hash, cookie, 16);
}

static void end_tag(uint8_t *pack)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	tag->tag_type = htons(PTT_EOL);
	tag->tag_len = 0;
	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag));
}

static void add_tag(uint8_t *pack, int type, const uint8_t *data, int len)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	tag->tag_type = type;
	tag->tag_len = htons(len);
	memcpy(tag->tag_data, data, len);
	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + len);
}

static void add_tag2(uint8_t *pack, const struct pppoe_tag *t)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	if (t) {
		memcpy(tag, t, sizeof(*t) + ntohs(t->tag_len));
		
		hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + ntohs(t->tag_len));
	}
}

static void add_ac_name_tag(uint8_t *pack, const char *ac_name)
{
	char pppoe_ac_name[64];

	strncpy(pppoe_ac_name, ac_name, sizeof(pppoe_ac_name));
	add_tag(pack, PTT_AC_NAME, (uint8_t *)pppoe_ac_name, strlen(pppoe_ac_name));
}

static void pppoe_recv_PADT(const PPPoEInterface *iface, uint8_t *pack, int size) {
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	uint16_t sid;
	PPPoESession *pppoeSession;

	sid = ntohs(hdr->sid);

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(3, NULL, "pppoe: discard PADT (destination address is broadcast)\n");
		return;
	}

	if ((pppoeSession=pppoeFindSessionBySID(sid, ethhdr->h_source))==NULL)
	{
		LOG(3, NULL, "Received PADT packet with unknown session ID (0x%04x) - ignoring\n", sid);
		return;
	}

	LOG(2, pppoeSession, "Received PADT - shutdown session\n");
	if (pppoeSession->pppSession) {
		sessionshutdown(pppoeSession->pppSession, 0, "Received PADT");
	} else {
		pppoeSessionKill(pppoeSession);
	}
}

static void pppoe_disc_send(const PPPoEInterface *iface, const uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n, s;

	s = ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length);

	LOG(3, NULL, "SENT pppoe_disc: Code %s to %s\n", get_string_codepad(hdr->code), fmtMacAddr(ethhdr->h_dest));
	LOG_HEX(5, NULL, "pppoe_disc_send", pack, s);

	n = write(iface->discoverySock, pack, s);
	if (n < 0 )
		LOG(0, NULL, "pppoe: write: %s\n", strerror(errno));
	else if (n != s) {
		LOG(0, NULL, "pppoe: short write %i/%i\n", n,s);
	}
}

static void pppoe_send_err(const PPPoEInterface *iface, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, int code, int tag_type)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, iface->mac, addr, code, 0, ETH_P_PPP_DISC);

	add_ac_name_tag(pack, iface->server_ac_name);
	add_tag(pack, tag_type, NULL, 0);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoe_disc_send(iface, pack);
}

void pppoe_sess_send(const PPPoESession *pppoeSession, const uint8_t *pack, uint16_t l)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n;
	uint16_t sizeppp;

	if (l < (ETH_HLEN + sizeof(*hdr) + 3))
	{
		LOG(0, pppoeSession, "ERROR pppoe_sess_send: packet too small for pppoe sent (size=%d)\n", l);
		return;
	}

	// recalculate the ppp frame length
	sizeppp = l - (ETH_HLEN + sizeof(*hdr));
	hdr->length = htons(sizeppp);

	LOG_HEX(5, pppoeSession, "pppoe_sess_send", pack, l);

	n = write(pppoeSession->iface->sessionSock, pack, l);
	if (n < 0 )
		LOG(0, pppoeSession, "pppoe_sess_send: write: %s\n", strerror(errno));
	else if (n != l)
		LOG(0, pppoeSession, "pppoe_sess_send: short write %i/%i\n", n,l);
}

static void pppoe_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	PPPoESession *pppoeSession=(PPPoESession *) arg;
	const PPPoEInterface *iface=pppoeSession->iface;
	int server=pppoeSession->server;

	LOG(3, NULL, "pppoe_timer_cb called\n");
	/* Destroy that session and start a new one */
	stopTimer(pppoeSession->timerEvent);
	memset(pppoeSession, 0, sizeof(PPPoESession));
	if (server==0) {
		/* Only restart if in client mode */
		pppoe_send_PADI(iface);
	}
}

// Only used in client mode
static void pppoe_send_PADI(const PPPoEInterface *iface)
{
	uint8_t pack[ETHER_MAX_LEN];
	PPPoESession *pppoeSession;

	hostUniq++;
	if(hostUniq==0) {
		hostUniq=1;
	}

	setup_header(pack, iface->mac, bc_addr, PADI_CODE, 0, ETH_P_PPP_DISC);

	add_tag(pack, PTT_HOST_UNIQ, (uint8_t *) &hostUniq, sizeof(hostUniq));

	add_tag(pack, PTT_SRV_NAME, (uint8_t *) iface->client_service_name, strlen(iface->client_service_name));
	//end_tag(pack);

	if ((pppoeSession=pppoeNewSession(iface, (uint8_t *) &hostUniq, sizeof(hostUniq)))==NULL) {
		LOG(0, NULL, "pppoe: Failed to send PADI - No free sessions\n");
		return;
	}

	pppoeSession->server=0;
	(iface->discovery_cb)((void *) pppoeSession, DISC_CBACT_INIT);
	pppoeSession->timerEvent=newTimer(pppoe_timer_cb, pppoeSession);
	startTimer(pppoeSession->timerEvent, 2);
	pppoeSession->lastPacketType=PADI_CODE;
	pppoe_disc_send(iface, pack);
}

// Only used in server mode
static void pppoe_send_PADO(PPPoESession *pppoeSession, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];
	hasht hash;

	setup_header(pack, pppoeSession->iface->mac, addr, PADO_CODE, 0, ETH_P_PPP_DISC);

	add_ac_name_tag(pack, pppoeSession->iface->server_ac_name);

	if (service_name)
		add_tag2(pack, service_name);

	pppoe_gen_cookie(pppoeSession->iface->mac, addr, hash);
	add_tag(pack, PTT_AC_COOKIE, hash, 16);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoeSession->lastPacketType=PADO_CODE;
	pppoe_disc_send(pppoeSession->iface, pack);
}

// Only used in server mode
static void pppoe_send_PADS(PPPoESession *pppoeSession, uint16_t sid, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];
	char pppoe_ac_name[64];

	setup_header(pack, pppoeSession->iface->mac, addr, PADS_CODE, sid, ETH_P_PPP_DISC);

	add_ac_name_tag(pack, pppoeSession->iface->server_ac_name);

	add_tag2(pack, service_name);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoeSession->lastPacketType=PADS_CODE;
	pppoe_disc_send(pppoeSession->iface, pack);
}


// Only used in client mode
static void pppoe_send_PADR(PPPoESession *pppoeSession, uint16_t sid, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *service_name, const struct pppoe_tag *ac_cookie_tag)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, pppoeSession->iface->mac, addr, PADR_CODE, sid, ETH_P_PPP_DISC);

	add_tag2(pack, service_name);

	add_tag2(pack, ac_cookie_tag);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	pppoeSession->lastPacketType=PADR_CODE;
	pppoe_disc_send(pppoeSession->iface, pack);
}

// Server or client mode
static void pppoe_send_PADT(const PPPoEInterface *iface, uint16_t sid, const uint8_t *addr)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, iface->mac, addr, PADT_CODE, sid, ETH_P_PPP_DISC);

	add_ac_name_tag(pack, iface->server_ac_name);

	LOG(3, NULL, "pppoe: Sent PADT sid=0x%04x\n", sid);

	pppoe_disc_send(iface, pack);
}

// Only used in server mode
static void pppoe_recv_PADI(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int n, service_match = 0;
	PPPoESession *pppoeSession;
	int len;

	if (!iface->acOK) {
		LOG(3, NULL, "Ignoring PADI - not in ac mode\n");
		return;
	}

	if (hdr->sid)
		return;

	len = ntohs(hdr->length);
	for (n = 0; n < len; n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > len)
			return;
		if (tag->tag_type==PTT_EOL)
			break;
		switch (tag->tag_type)
		{
			case PTT_SRV_NAME:
				if (*iface->server_service_name && !tag->tag_len)
				{
					break;
				}
				else if (*iface->server_service_name && tag->tag_len)
				{
					if (ntohs(tag->tag_len) != strlen(iface->server_service_name))
						break;
					if (memcmp(tag->tag_data, iface->server_service_name, ntohs(tag->tag_len)))
						break;
					service_name_tag = tag;
					service_match = 1;
				}
				else
				{
					service_name_tag = tag;
					service_match = 1;
				}
				break;
			case PTT_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case PTT_RELAY_SID:
				relay_sid_tag = tag;
				break;
		}
	}

	if (!service_match)
	{
		LOG(3, NULL, "pppoe: discarding PADI packet (Service-Name mismatch)\n");
		return;
	}

	/* Use the peerMAC as the hostUniq */
	if ((pppoeSession=pppoeNewSession(iface, (uint8_t *) ethhdr->h_source, ETH_ALEN))==NULL) {
		return;
	}

	pppoeSession->server=1;
	(iface->discovery_cb)((void *) pppoeSession, DISC_CBACT_INIT);
	pppoeSession->timerEvent=newTimer(pppoe_timer_cb, pppoeSession);
	startTimer(pppoeSession->timerEvent, 2);
	pppoe_send_PADO(pppoeSession, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);
}

// Only used in client mode
static void pppoe_recv_PADO(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *ac_cookie_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	struct pppoe_tag *vendor_tag = NULL;
	int n, service_match = 0;
	uint32_t recvHostUniq;
	char avc_id[16];
	PPPoESession *pppoeSession;
	
	if (!iface->clientOK) {
		LOG(3, NULL, "Ignoring PADO - not in client mode\n");
		return;
	}

#if 0
	if (tunnel[t].state != TUNNELDISCPADI) {
		LOG(1, NULL, "Rcv pppoe: discard PADO (not expecting it)\n");
		return;
	}
#endif

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(1, NULL, "Rcv pppoe: discard PADO (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid)
	{
		LOG(1, NULL, "Rcv pppoe: discarding PADO packet (sid is not zero)\n");
		return;
	}

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (tag->tag_type==PTT_EOL)
			break;
		switch (tag->tag_type)
		{
			case PTT_SRV_NAME:
				service_name_tag = tag;
				if (tag->tag_len == 0)
					service_match = 1;
				else if (*iface->client_service_name)
				{
					if (ntohs(tag->tag_len) != strlen(iface->client_service_name))
						break;
					if (memcmp(tag->tag_data, iface->client_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				}
				else
				{
					service_match = 1;
				}
				break;
			case PTT_HOST_UNIQ:
				host_uniq_tag = tag;
				if (ntohs(tag->tag_len) == sizeof(recvHostUniq)) {
					memcpy((void *) &recvHostUniq, tag->tag_data, ntohs(tag->tag_len));
				} else {
					recvHostUniq=0;
				}
				break;
			case PTT_AC_COOKIE:
				ac_cookie_tag = tag;
				break;
			case PTT_RELAY_SID:
				relay_sid_tag = tag;
				break;
			case PTT_VENDOR:
				vendor_tag = tag;
				if (ntohs(tag->tag_len) == 21) {
					uint32_t vendor_id=ntohl(*((uint32_t *) tag->tag_data));
					if (vendor_id==3561) {
						uint8_t *p=tag->tag_data+sizeof(uint32_t);
						if (p[0]==1 && p[1]==15) {
							memcpy(avc_id, p+2, 15);
							avc_id[15]='\0';
							LOG(3, NULL, "avc_id=%s\n", avc_id);
						}
					}
				}
				break;
		}
	}

	if (!service_match)
	{
		LOG(3, NULL, "pppoe: Service-Name mismatch\n");
		pppoe_send_err(iface, ethhdr->h_source, host_uniq_tag, relay_sid_tag, PADS_CODE, PTT_SRV_ERR);
		return;
	}

	if ((pppoeSession=pppoeFindSessionByHostUniq((uint8_t *) &recvHostUniq, sizeof(recvHostUniq)))==NULL) {
		LOG(0, NULL, "Cannot find session for HostUniq: %s\n", fmtBinary((uint8_t *) &recvHostUniq, sizeof(recvHostUniq)));
		return;
	}

	if (pppoeSession->lastPacketType!=PADI_CODE) {
		LOG(3, NULL, "pppoe: Ignoring duplicate response\n");
		return;
	}

	if (!pppoeIsSessionUnique(avc_id)) {
		LOG(3, NULL, "pppoe: Ignoring response from existing link\n");
		return;
	}
	strcpy(pppoeSession->avc_id, avc_id);

	/* Restart timer */
	startTimer(pppoeSession->timerEvent, 2);
	pppoe_send_PADR(pppoeSession, hdr->sid, ethhdr->h_source, host_uniq_tag, service_name_tag, ac_cookie_tag);
}

// Only used in server mode
static void pppoe_recv_PADR(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *ac_cookie_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int n, service_match = 0;
	PPPoESession *pppoeSession;
	uint16_t sid;

	if (!iface->acOK) {
		LOG(3, NULL, "Ignoring PADR - not in ac mode\n");
		return;
	}

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(1, NULL, "Rcv pppoe: discard PADR (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid)
	{
		LOG(1, NULL, "Rcv pppoe: discarding PADR packet (sid is not zero)\n");
		return;
	}

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (tag->tag_type==PTT_EOL)
			break;
		switch (tag->tag_type)
		{
			case PTT_SRV_NAME:
				service_name_tag = tag;
				if (tag->tag_len == 0)
					service_match = 1;
				else if (*iface->server_service_name)
				{
					if (ntohs(tag->tag_len) != strlen(iface->server_service_name))
						break;
					if (memcmp(tag->tag_data, iface->server_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				}
				else
				{
					service_match = 1;
				}
				break;
			case PTT_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case PTT_AC_COOKIE:
				ac_cookie_tag = tag;
				break;
			case PTT_RELAY_SID:
				relay_sid_tag = tag;
				break;
		}
	}

	if (!service_match)
	{
		LOG(3, NULL, "pppoe: Service-Name mismatch\n");
		pppoe_send_err(iface, ethhdr->h_source, host_uniq_tag, relay_sid_tag, PADS_CODE, PTT_SRV_ERR);
		return;
	}

	if (!ac_cookie_tag)
	{
		LOG(3, NULL, "pppoe: discard PADR packet (no AC-Cookie tag present)\n");
		return;
	}

	if (ntohs(ac_cookie_tag->tag_len) != 16)
	{
		LOG(3, NULL, "pppoe: discard PADR packet (incorrect AC-Cookie tag length)\n");
		return;
	}

	if (pppoe_check_cookie(ethhdr->h_dest, ethhdr->h_source, (uint8_t *) ac_cookie_tag->tag_data))
	{
		LOG(3, NULL, "pppoe: discard PADR packet (incorrect AC-Cookie)\n");
		return;
	}

	do {
		sid=random() & 0xffff; // Lower 16 bits
	} while(pppoeFindSessionBySID(sid, NULL)!=NULL);

	if ((pppoeSession=pppoeFindSessionByHostUniq((uint8_t *) ethhdr->h_source, ETH_ALEN))==NULL) {
		LOG(0, NULL, "Cannot find session for HostUniq: %s\n", fmtMacAddr((uint8_t *) ethhdr->h_source));
		return;
	}
	pppoeSession->sid=sid;
	memcpy(pppoeSession->peerMac, ethhdr->h_source, ETH_ALEN);
	stopTimer(pppoeSession->timerEvent);

#if 0
	sid = sessionfree;
	sessionfree = session[sid].next;
	memset(&session[sid], 0, sizeof(session[0]));

	if (sid > config->cluster_highest_sessionid)
		config->cluster_highest_sessionid = sid;

	session[sid].opened = time_now;
	session[sid].tunnel = TUNNEL_ID_PPPOE;
	session[sid].last_packet = session[sid].last_data = time_now;

	//strncpy(session[sid].called, called, sizeof(session[sid].called) - 1);
	//strncpy(session[sid].calling, calling, sizeof(session[sid].calling) - 1);

	session[sid].ppp.phase = Establish;
	session[sid].ppp.lcp = Starting;

	session[sid].magic = time_now; // set magic number
	session[sid].mru = PPPoE_MRU; // default

	// start LCP
	sess_local[sid].lcp_authtype = config->radius_authprefer;
	sess_local[sid].ppp_mru = MRU;

	// Set multilink options before sending initial LCP packet
	sess_local[sid].mp_mrru = 1614;
	sess_local[sid].mp_epdis = ntohl(config->iftun_address ? config->iftun_address : my_address);

	memcpy(session[sid].src_hwaddr, ethhdr->h_source, ETH_ALEN);
#endif
	pppoe_send_PADS(pppoeSession, pppoeSession->sid, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);

	(*iface->discovery_cb)(pppoeSession, DISC_CBACT_OPEN);
}

// Only used in client mode
static void pppoe_recv_PADS(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	// struct pppoe_tag *service_name_tag = NULL;
	int n, service_match = 0;
	PPPoESession *pppoeSession;
	uint32_t recvHostUniq;
	uint16_t sid;

	if (!iface->clientOK) {
		LOG(3, NULL, "Ignoring PADS - not in client mode\n");
		return;
	}

#if 0
	if (tunnel[t].state != TUNNELDISCPADR) {
		LOG(1, NULL, "Rcv pppoe: discard PADS (not expecting it)\n");
		return;
	}
#endif

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(1, NULL, "Rcv pppoe: discard PADS (destination address is broadcast)\n");
		return;
	}

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (tag->tag_type==PTT_EOL)
			break;
		switch (tag->tag_type)
		{
			case PTT_SRV_NAME:
				// service_name_tag = tag;
				if (tag->tag_len == 0)
					service_match = 1;
				else if (*iface->client_service_name)
				{
					if (ntohs(tag->tag_len) != strlen(iface->client_service_name))
						break;
					if (memcmp(tag->tag_data, iface->client_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				}
				else
				{
					service_match = 1;
				}
				break;
			case PTT_HOST_UNIQ:
				host_uniq_tag = tag;
				if (ntohs(tag->tag_len) == sizeof(recvHostUniq)) {
					memcpy((void *) &recvHostUniq, tag->tag_data, ntohs(tag->tag_len));
				} else {
					recvHostUniq=0;
				}
				break;
			case PTT_RELAY_SID:
				relay_sid_tag = tag;
				break;
		}
	}

	if (!service_match)
	{
		LOG(3, NULL, "pppoe: Service-Name mismatch\n");
		// TODO - fix this
		pppoe_send_err(iface, ethhdr->h_source, host_uniq_tag, relay_sid_tag, PADS_CODE, PTT_SRV_ERR);
		return;
	}

	sid = ntohs(hdr->sid);
	if ((pppoeSession=pppoeFindSessionByHostUniq((uint8_t *) &recvHostUniq, sizeof(recvHostUniq)))==NULL) {
		LOG(0, NULL, "Cannot find session for HostUniq: %s\n", fmtBinary((uint8_t *) &recvHostUniq, sizeof(recvHostUniq)));
		return;
	}
	pppoeSession->sid=sid;
	memcpy(pppoeSession->peerMac, ethhdr->h_source, ETH_ALEN);
	pppoeSession->server=0;
	stopTimer(pppoeSession->timerEvent);
	(*iface->discovery_cb)(pppoeSession, DISC_CBACT_OPEN);
}

// pppoe discovery recv data
void processDiscovery(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	LOG(3, NULL, "RCV pppoe_disc: Code %s from %s\n", get_string_codepad(hdr->code), fmtMacAddr(ethhdr->h_source));
	LOG_HEX(5, NULL, "PPPOE Disc", pack, size);

	if (size < (ETH_HLEN + sizeof(*hdr)))
	{
		LOG(1, NULL, "Error pppoe_disc: short packet received (%i)\n", size);
		return;
	}

	/* Work around RouterOS bug */
	if (memcmp(ethhdr->h_dest, mt_addr, ETH_ALEN)==0) {
		LOG(1, NULL, "Fix Mikrotik RouterOS Bug\n");
		memcpy(ethhdr->h_dest, iface->mac, ETH_ALEN);
	}

	if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, iface->mac, ETH_ALEN))
	{
		LOG(1, NULL, "Error pppoe_disc: h_dest != Broadcast and  h_dest != %s\n", fmtMacAddr(iface->mac));
		return;
	}

	if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN))
	{
		LOG(1, NULL, "Error pppoe_disc: discarding packet (source address is broadcast)\n");
		return;
	}

	if ((ethhdr->h_source[0] & 1) != 0)
	{
		LOG(1, NULL, "Error pppoe_disc: discarding packet (host address is not unicast)\n");
		return;
	}

	if (size < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length))
	{
		LOG(1, NULL, "Error pppoe_disc: short packet received\n");
		return;
	}

	if (hdr->ver != 1)
	{
		LOG(1, NULL, "Error pppoe_disc: discarding packet (unsupported version %i)\n", hdr->ver);
		return;
	}

	if (hdr->type != 1)
	{
		LOG(1, NULL, "Error pppoe_disc: discarding packet (unsupported type %i)\n", hdr->type);
		return;
	}

	switch (hdr->code) {
		case PADI_CODE:
			pppoe_recv_PADI(iface, pack, size);
			break;
		case PADO_CODE:
			pppoe_recv_PADO(iface, pack, size);
			break;
		case PADR_CODE:
			pppoe_recv_PADR(iface, pack, size);
			break;
		case PADS_CODE:
			pppoe_recv_PADS(iface, pack, size);
			break;
		case PADT_CODE:
			pppoe_recv_PADT(iface, pack, size);
			break;
	}
}

void processSession(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	uint16_t lppp = ntohs(hdr->length);
	uint8_t *pppdata = (uint8_t *) hdr->tag;
	uint16_t proto, sid, t;
	int doclient=0;
	PPPoESession *pppoeSession;

	if (doclient) {
#if 0
		sid = pppoe_local_sid;
		if (pppoe_remote_sid!=ntohs(hdr->sid)) {
			LOG(0, NULL, "Received pppoe packet with invalid session ID (0x%04x)\n", sid;);
		}
#endif
	} else {
		sid = ntohs(hdr->sid);
	}

	LOG_HEX(5, NULL, "RCV PPPOE Sess", pack, size);

	if ((pppoeSession=pppoeFindSessionBySID(sid, ethhdr->h_source))==NULL)
	{
		LOG(0, NULL, "Received pppoe packet with invalid session ID (0x%04x)\n", sid);
		pppoe_send_PADT(iface, sid, ethhdr->h_source);
		return;
	}

	if (hdr->ver != 1)
	{
		LOG(3, NULL, "Error processSession: discarding packet (unsupported version %i)\n", hdr->ver);
		return;
	}

	if (hdr->type != 1)
	{
		LOG(3, NULL, "Error processSession: discarding packet (unsupported type %i)\n", hdr->type);
		return;
	}

	if (pppoeSession->pppSession) {
		processPPP(pppoeSession->pppSession, pppdata, lppp);
	} else {
		LOG(3, NULL, "Error processSession: no pppSession active\n");
	}

}

uint8_t *pppoe_session_header(uint8_t *b, const PPPoESession *pppoeSession)
{
	return(setup_header(b, pppoeSession->iface->mac, pppoeSession->peerMac, SESS_CODE, pppoeSession->sid, ETH_P_PPP_SES));
}

// Increment pppoe header length - saving upper levels digging into structure
void pppoe_incr_header_length(uint8_t *b, int n)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *) b;
	hdr->length += n;
}

void discoveryServer(PPPoEInterface *iface, char *ac_name, char *service_name)
{
	if (!init_done) {
		initDiscovery();
	}

	if (ac_name) {
		strncpy(iface->server_ac_name, ac_name, sizeof(iface->server_ac_name));
	} else {
		strncpy(iface->server_ac_name, DEFAULT_PPPOE_AC_NAME, sizeof(iface->server_ac_name));
	}

	if (service_name) {
		strncpy(iface->server_service_name, service_name, sizeof(iface->server_service_name));
	}

	iface->acOK=1;
}

void discoveryClient(PPPoEInterface *iface, char *ac_name, char *service_name, int attempts)
{
	if (!init_done) {
		initDiscovery();
	}

	if (ac_name) {
		strncpy(iface->client_ac_name, ac_name, sizeof(iface->client_ac_name));
	}

	if (service_name) {
		strncpy(iface->client_service_name, service_name, sizeof(iface->client_service_name));
	}

	iface->clientOK=1;
	pppoe_send_PADI(iface);
}

int discoveryClientCount()
{
	int i;
	int count=0;

	for (i=0; i<MAX_PPPOE_SESSION; i++) {
		if (pppoe_sessions[i].sid!=0 && pppoe_sessions[i].server==0) {
			count++;
		}
	}
	return(count);
	
}
