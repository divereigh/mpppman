#ifndef __IPV6_H
#define __IPV6_H
#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ppp.h"

void sendipv6cp(PPPSession *pppSession);
void processipv6cp(PPPSession *pppSession, uint8_t *pack, int size);
void processipv6(PPPSession *pppSession, uint8_t *pack, int size);

#endif
