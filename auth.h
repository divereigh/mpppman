#ifndef __AUTH_H
#define __AUTH_H
#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "ppp.h"

void processpap(PPPSession *pppSession, uint8_t *pack, int size);
void processchap(PPPSession *pppSession, uint8_t *pack, int size);
void sendchap(PPPSession *pppSession);
void sendpap(PPPSession *pppSession);
void set_auth(PPPSession *pppSession);
void do_auth(PPPSession *pppSession);

#endif
