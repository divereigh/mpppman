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
*/

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "pppoe.h"

void sysFatal(char const *str);
void sysErr(char const *str);
void printErr(char const *str);

#undef LOG
#undef LOG_HEX
#define LOG(D, pppoe, f, ...)    ({ if (D <= debuglevel) _log(D, pppoe, f, ## __VA_ARGS__); })
#define LOG_HEX(D, pppoe, t, d, s)     ({ if (D <= debuglevel) _log_hex(D, pppoe, t, d, s); })

void _log(int level, const PPPoESession *pppoe, const char *format, ...) __attribute__((format (printf, 3, 4)));
void _log_hex(int level, const PPPoESession *pppoe, const char *title, const uint8_t *data, int maxsize);

extern int debuglevel;
extern FILE *log_stream;
extern int syslog_log;
char *fmtaddr(in_addr_t addr, int n);
char *fmtMacAddr(const uint8_t *pMacAddr);
char *fmtBinary(const uint8_t *pData, size_t len);
void initlog(char *prog);

#endif
