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
#include "ipv6.h"


// send an IPV6CP Config Request challenge
void sendipv6cp(PPPSession *pppSession)
{
	LOG(3, pppSession->pppoeSession, "sendipv6cp called\n");
}

/* Process IPV6CP packet - pack points the PPP payload */
void processipv6cp(PPPSession *pppSession, uint8_t *pack, int size)
{
	LOG(3, pppSession->pppoeSession, "Recv IPV6CP Packet\n");
}

/* Process IPV6 packet - pack points the PPP payload */
void processipv6(PPPSession *pppSession, uint8_t *pack, int size)
{
	LOG(3, pppSession->pppoeSession, "Recv IPV6 Packet\n");
}


