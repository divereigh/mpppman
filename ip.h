#ifndef __IP_H
#define __IP_H
#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ppp.h"

void sendipcp(PPPSession *pppSession);
void processipcp(PPPSession *pppSession, uint8_t *p, uint16_t l);
void processip(PPPSession *pppSession, uint8_t *pack, int size);

#endif
