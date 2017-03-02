#ifndef __IF_H
#define __IF_H
#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

int openInterface(char const *ifname, uint16_t type, unsigned char *hwaddr, uint16_t *mtu);
#endif
