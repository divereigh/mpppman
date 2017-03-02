#ifndef __LOG_H
#define __LOG_H

#include "config.h"
#include <stdio.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

/*
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
*/

void sysFatal(char const *str);
void sysErr(char const *str);
void printErr(char const *str);

#undef LOG
#undef LOG_HEX
#define LOG(D, f, ...)    ({ if (D <= debuglevel) _log(D, f, ## __VA_ARGS__); })
#define LOG_HEX(D, t, d, s)     ({ if (D <= debuglevel) _log_hex(D, t, d, s); })

void _log(int level, const char *format, ...) __attribute__((format (printf, 2, 3)));
void _log_hex(int level, const char *title, const uint8_t *data, int maxsize);

extern int debuglevel;
extern FILE *log_stream;
//char *fmtaddr(struct in_addr addr, int n);
char *fmtMacAddr(const uint8_t *pMacAddr);

#endif
