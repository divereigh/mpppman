#ifndef __LCP_H
#define __LCP_H
#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ppp.h"

void processlcp(PPPSession *pppSession, uint8_t *p, uint16_t l);
void sendLCPConfigReq(PPPSession *pppSession);
void sendLCPTerminateReq(PPPSession *pppSession, const char *reason);
void dumplcp(const PPPoESession *pppoe, uint8_t *p, int l);
void lcp_open(PPPSession *pppSession);

#endif
