#ifndef __CCP_H
#define __CCP_H
#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ppp.h"

void sendccpcp(PPPSession *pppSession);
void processccpcp(PPPSession *pppSession, uint8_t *pack, int size);
void processccp(PPPSession *pppSession, uint8_t *pack, int size);

#endif
