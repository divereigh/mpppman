#include "config.h"

#ifdef HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "event.h"
#include "auth.h"
#include "log.h"
#include "constants.h"
#include "common.h"
#include "ip.h"


// send an IPCP Config Request challenge
void sendipcp(PPPSession *pppSession)
{
	LOG(3, "sendipcp called\n");
}

/* Process IPCP packet - pack points the PPP payload */
void processipcp(PPPSession *pppSession, uint8_t *pack, int size)
{
	LOG(3, "Recv IPCP Packet\n");
}

/* Process IP packet - pack points the PPP payload */
void processip(PPPSession *pppSession, uint8_t *pack, int size)
{
	LOG(3, "Recv IP Packet\n");
}


