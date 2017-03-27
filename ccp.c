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
#include "ccp.h"


// send an CCPCP Config Request challenge
void sendccp(PPPSession *pppSession)
{
	LOG(3, pppSession->pppoeSession, "sendccpcp called\n");
}

/* Process CCPCP packet - pack points the PPP payload */
void processccpcp(PPPSession *pppSession, uint8_t *pack, int size)
{
	LOG(3, pppSession->pppoeSession, "Recv CCPCP Packet\n");
}

/* Process CCP packet - pack points the PPP payload */
void processccp(PPPSession *pppSession, uint8_t *pack, int size)
{
	LOG(3, pppSession->pppoeSession, "Recv CCP Packet\n");
}


