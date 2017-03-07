#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
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


#define SESS_CODE           0x00
#define DEFAULT_PPPOE_AC_NAME "mpppman"

PPPoESession pppoe_sessions[MAX_PPPOE_SESSION];

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

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

void PPPoE_cb_func(evutil_socket_t fd, short what, void *arg)
{
	uint8_t buf[65536];
	int s;
	const PPPoEInterface *pppoe = (PPPoEInterface *) arg;

	LOG(3, "Got an event on socket %d:%s%s%s%s %s\n",
		(int) fd,
		(what&EV_TIMEOUT) ? " timeout" : "",
		(what&EV_READ)    ? " read" : "",
		(what&EV_WRITE)   ? " write" : "",
		(what&EV_SIGNAL)  ? " signal" : "",
		pppoe->name);
	if ((s = read(fd, buf, sizeof(buf))) > 0) {
		if (fd==pppoe->discoverySock) {
			processDiscovery(pppoe, buf, s);
		} else if (fd==pppoe->sessionSock) {
			processSession(pppoe, buf, s);
		}
	}
}

/* Find a session that has the given session id, 0 will find a free session
*/
PPPoESession *pppoe_find_session(uint16_t sid)
{
	int i;

	for (i=0; i<MAX_PPPOE_SESSION; i++) {
		if (pppoe_sessions[i].sid==sid) {
			return(&pppoe_sessions[i]);
		}
	}
	return(NULL);
}

/* Allocate and fill new session - returns PPPoESession */
PPPoESession * pppoe_new_session(const PPPoEInterface *iface, const uint8_t *addr)
{
	uint16_t sid;
	int i;
	PPPoESession *pppoeSession;

	if ((pppoeSession=pppoe_find_session(0)) == NULL) {
		LOG(0, "No free PPPoESession available\n");
	}
	
	do {
		sid=random() & 0xffff; // Lower 16 bits
	} while(pppoe_find_session(sid)!=NULL);

	pppoeSession->sid=sid;
	pppoeSession->iface=iface;
	memcpy(pppoeSession->peerMac, addr, ETH_ALEN);
	LOG(3, "PPPoESession allocated with sid=%04x\n", pppoeSession->sid);
	return(pppoeSession);
}

/**********************************************************************
*%FUNCTION: openPPPoEInterface
*%ARGUMENTS:
* ifname -- name of interface
* clientOK -- true if this interface should relay PADI, PADR packets.
* acOK -- true if this interface should relay PADO, PADS packets.
*%RETURNS:
* A PPPoEInterface with discovery and session sockets open
*%DESCRIPTION:
* Opens a PPPoE Interface
***********************************************************************/
PPPoEInterface *
openPPPoEInterface(char const *ifname, int clientOK, int acOK, struct event_base *base)
{
	PPPoEInterface *pppoe;

	if ((pppoe=(PPPoEInterface *) malloc(sizeof(PPPoEInterface)))==NULL) {
		sysFatal("PPPoEInterface malloc");
	}

	pppoe->discoverySock = openInterface(ifname, ETH_P_PPP_DISC, pppoe->mac, NULL);
	pppoe->sessionSock = openInterface(ifname, ETH_P_PPP_SES, NULL, NULL);
	pppoe->clientOK=clientOK;
	pppoe->acOK=acOK;
	strncpy(pppoe->name, ifname, sizeof(pppoe->name));

	pppoe->discoveryEvent=event_new(base, pppoe->discoverySock, EV_READ|EV_PERSIST, PPPoE_cb_func, (void *) pppoe);
	pppoe->sessionEvent=event_new(base, pppoe->sessionSock, EV_READ|EV_PERSIST, PPPoE_cb_func, (void *) pppoe);

	event_add(pppoe->discoveryEvent, NULL);
	event_add(pppoe->sessionEvent, NULL);
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

	memcpy(tag, t, sizeof(*t) + ntohs(t->tag_len));
	
	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + ntohs(t->tag_len));
}

static void add_ac_name_tag(uint8_t *pack)
{
	char pppoe_ac_name[64];

	strcpy(pppoe_ac_name, DEFAULT_PPPOE_AC_NAME);
	add_tag(pack, PTT_AC_NAME, (uint8_t *)pppoe_ac_name, strlen(pppoe_ac_name));
}

static void pppoe_recv_PADO(const PPPoEInterface *iface, uint8_t *pack, int size) {}
static void pppoe_recv_PADS(const PPPoEInterface *iface, uint8_t *pack, int size) {}
static void pppoe_recv_PADT(const PPPoEInterface *iface, uint8_t *pack, int size) {}

static void pppoe_disc_send(const PPPoEInterface *iface, const uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n, s;

	s = ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length);

	LOG(3, "SENT pppoe_disc: Code %s to %s\n", get_string_codepad(hdr->code), fmtMacAddr(ethhdr->h_dest));
	LOG_HEX(5, "pppoe_disc_send", pack, s);

	n = write(iface->discoverySock, pack, s);
	if (n < 0 )
		LOG(0, "pppoe: write: %s\n", strerror(errno));
	else if (n != s) {
		LOG(0, "pppoe: short write %i/%i\n", n,s);
	}
}

static void pppoe_send_err(const PPPoEInterface *iface, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, int code, int tag_type)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, iface->mac, addr, code, 0, ETH_P_PPP_DISC);

	add_ac_name_tag(pack);
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
		LOG(0, "ERROR pppoe_sess_send: packet too small for pppoe sent (size=%d)\n", l);
		return;
	}

	// recalculate the ppp frame length
	sizeppp = l - (ETH_HLEN + sizeof(*hdr));
	hdr->length = htons(sizeppp);

	LOG_HEX(5, "pppoe_sess_send", pack, l);

	n = write(pppoeSession->iface->sessionSock, pack, l);
	if (n < 0 )
		LOG(0, "pppoe_sess_send: write: %s\n", strerror(errno));
	else if (n != l)
		LOG(0, "pppoe_sess_send: short write %i/%i\n", n,l);
}

// Only used in server mode
static void pppoe_send_PADO(const PPPoEInterface *iface, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];
	hasht hash;

	setup_header(pack, iface->mac, addr, PADO_CODE, 0, ETH_P_PPP_DISC);

	add_ac_name_tag(pack);

	if (service_name)
		add_tag2(pack, service_name);

	pppoe_gen_cookie(iface->mac, addr, hash);
	add_tag(pack, PTT_AC_COOKIE, hash, 16);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoe_disc_send(iface, pack);
}

// Only used in server mode
static void pppoe_send_PADS(const PPPoEInterface *iface, uint16_t sid, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];
	char pppoe_ac_name[64];

	setup_header(pack, iface->mac, addr, PADS_CODE, sid, ETH_P_PPP_DISC);

	add_ac_name_tag(pack);

	add_tag2(pack, service_name);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

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
	int len;

	if (hdr->sid)
		return;

	len = ntohs(hdr->length);
	for (n = 0; n < len; n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > len)
			return;
		switch (tag->tag_type)
		{
			case PTT_EOL:
				break;
			case PTT_SRV_NAME:
/*
TODO
				if (config->pppoe_only_equal_svc_name && *config->pppoe_service_name && !tag->tag_len)
				{
					break;
				}
				else if (*config->pppoe_service_name && tag->tag_len)
				{
					if (ntohs(tag->tag_len) != strlen(config->pppoe_service_name))
						break;
					if (memcmp(tag->tag_data, config->pppoe_service_name, ntohs(tag->tag_len)))
						break;
					service_name_tag = tag;
					service_match = 1;
				}
				else
				{
*/
					service_name_tag = tag;
					service_match = 1;
//				}
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
		LOG(3, 0, 0, "pppoe: discarding PADI packet (Service-Name mismatch)\n");
		return;
	}

	pppoe_send_PADO(iface, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);
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

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(1, "Rcv pppoe: discard PADR (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid)
	{
		LOG(1, "Rcv pppoe: discarding PADR packet (sid is not zero)\n");
		return;
	}

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		switch (tag->tag_type)
		{
			case PTT_EOL:
				break;
			case PTT_SRV_NAME:
				service_name_tag = tag;
/*
TODO
				if (tag->tag_len == 0)
					service_match = 1;
				else if (*config->pppoe_service_name)
				{
					if (ntohs(tag->tag_len) != strlen(config->pppoe_service_name))
						break;
					if (memcmp(tag->tag_data, config->pppoe_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				}
				else
				{
*/
					service_match = 1;
//				}
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
		LOG(3, "pppoe: Service-Name mismatch\n");
		pppoe_send_err(iface, ethhdr->h_source, host_uniq_tag, relay_sid_tag, PADS_CODE, PTT_SRV_ERR);
		return;
	}

	if (!ac_cookie_tag)
	{
		LOG(3, "pppoe: discard PADR packet (no AC-Cookie tag present)\n");
		return;
	}

	if (ntohs(ac_cookie_tag->tag_len) != 16)
	{
		LOG(3, "pppoe: discard PADR packet (incorrect AC-Cookie tag length)\n");
		return;
	}

	if (pppoe_check_cookie(ethhdr->h_dest, ethhdr->h_source, (uint8_t *) ac_cookie_tag->tag_data))
	{
		LOG(3, "pppoe: discard PADR packet (incorrect AC-Cookie)\n");
		return;
	}

	pppoeSession=pppoe_new_session(iface, ethhdr->h_source);
	pppoeSession->pppSession=ppp_new_session(pppoeSession);
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
	pppoe_send_PADS(iface, pppoeSession->sid, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);

	sendlcp(pppoeSession->pppSession);
	change_state(pppoeSession->pppSession, lcp, RequestSent);
}


// pppoe discovery recv data
void processDiscovery(const PPPoEInterface *iface, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	LOG(3, "RCV pppoe_disc: Code %s from %s\n", get_string_codepad(hdr->code), fmtMacAddr(ethhdr->h_source));
	LOG_HEX(5, "PPPOE Disc", pack, size);

	if (size < (ETH_HLEN + sizeof(*hdr)))
	{
		LOG(1, 0, 0, "Error pppoe_disc: short packet received (%i)\n", size);
		return;
	}

	if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, iface->mac, ETH_ALEN))
	{
		LOG(1, 0, 0, "Error pppoe_disc: h_dest != Broadcast and  h_dest != %s\n", fmtMacAddr(iface->mac));
		return;
	}

	if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN))
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (source address is broadcast)\n");
		return;
	}

	if ((ethhdr->h_source[0] & 1) != 0)
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (host address is not unicast)\n");
		return;
	}

	if (size < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length))
	{
		LOG(1, 0, 0, "Error pppoe_disc: short packet received\n");
		return;
	}

	if (hdr->ver != 1)
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (unsupported version %i)\n", hdr->ver);
		return;
	}

	if (hdr->type != 1)
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (unsupported type %i)\n", hdr->type);
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
#if 0
	//struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	uint16_t lppp = ntohs(hdr->length);
	uint8_t *pppdata = (uint8_t *) hdr->tag;
	uint16_t proto, sid, t;
	int doclient=0;

	if (doclient) {
		sid = pppoe_local_sid;
		if (pppoe_remote_sid!=ntohs(hdr->sid)) {
			LOG(0, sid, t, "Received pppoe packet with invalid session ID\n");
		}
	} else {
		sid = ntohs(hdr->sid);
	}

	LOG_HEX(5, "RCV PPPOE Sess", pack, size);

	if (sid >= MAXSESSION)
	{
		LOG(0, sid, t, "Received pppoe packet with invalid session ID\n");
		STAT(tunnel_rx_errors);
		return;
	}

	if (session[sid].tunnel != t)
	{
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }

		LOG(1, sid, t, "ERROR process_pppoe_sess: Session is not a session pppoe\n");
		return;
	}

	if (hdr->ver != 1)
	{
		LOG(3, sid, t, "Error process_pppoe_sess: discarding packet (unsupported version %i)\n", hdr->ver);
		return;
	}

	if (hdr->type != 1)
	{
		LOG(3, sid, t, "Error process_pppoe_sess: discarding packet (unsupported type %i)\n", hdr->type);
		return;
	}

	if (lppp > 2 && pppdata[0] == 0xFF && pppdata[1] == 0x03)
	{	// HDLC address header, discard
		LOG(5, sid, t, "pppoe_sess: HDLC address header, discard\n");
		pppdata += 2;
		lppp -= 2;
	}
	if (lppp < 2)
	{
		LOG(3, sid, t, "Error process_pppoe_sess: Short ppp length %d\n", lppp);
		return;
	}
	if (*pppdata & 1)
	{
		proto = *pppdata++;
		lppp--;
	}
	else
	{
		proto = ntohs(*(uint16_t *) pppdata);
		pppdata += 2;
		lppp -= 2;
	}

	if (session[sid].forwardtosession)
	{	// Must be forwaded to a remote lns tunnel l2tp
		pppoe_forwardto_session_rmlns(pack, size, sid, proto);
		return;
	}

	if (proto == PPPPAP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processpap(sid, t, pppdata, lppp);
	}
	else if (proto == PPPCHAP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processchap(sid, t, pppdata, lppp);
	}
	else if (proto == PPPLCP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processlcp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIPCP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipcp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIPV6CP && config->ipv6_prefix.s6_addr[0])
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipv6cp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPCCP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processccp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIP)
	{
		session[sid].last_packet = session[sid].last_data = time_now;
		if (session[sid].walled_garden && !config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipin(sid, t, pppdata, lppp);
	}
	else if (proto == PPPMP)
	{
		session[sid].last_packet = session[sid].last_data = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processmpin(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0])
	{
		session[sid].last_packet = session[sid].last_data = time_now;
		if (session[sid].walled_garden && !config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipv6in(sid, t, pppdata, lppp);
	}
	else if (session[sid].ppp.lcp == Opened)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		protoreject(sid, t, pppdata, lppp, proto);
	}
	else
	{
		LOG(3, sid, t, "process_pppoe_sess: Unknown PPP protocol 0x%04X received in LCP %s state\n",
			proto, ppp_state(session[sid].ppp.lcp));
	}
#endif
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

