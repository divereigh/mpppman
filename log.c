#include "config.h"

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "log.h"

FILE *log_stream;

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
sysFatal(char const *str)
{
	sysErr(str);
	exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
	LOG(0, NULL, "%.256s: %.256s\n", str, strerror(errno));
}

//
// Log a debug message.  Typically called via the LOG macro
//
void _log(int level, const PPPoESession *pppoe, const char *format, ...)
{
	static char message[65536] = {0};
	va_list ap;

	struct timeval tv;
	time_t now;
	int millisec;
	struct tm *lt;
	char time_now_string[256];

	gettimeofday(&tv, NULL);
	now = (time_t) tv.tv_sec;
	millisec = tv.tv_usec / 1000;
	lt = localtime(&now);
	strftime(time_now_string, 256, "%H:%M:%S", lt);
	sprintf(time_now_string+strlen(time_now_string), ".%03d", millisec);

#ifdef RINGBUFFER
	if (ringbuffer)
	{
		if (++ringbuffer->tail >= RINGBUFFER_SIZE)
			ringbuffer->tail = 0;
		if (ringbuffer->tail == ringbuffer->head)
			if (++ringbuffer->head >= RINGBUFFER_SIZE)
				ringbuffer->head = 0;

		ringbuffer->buffer[ringbuffer->tail].level = level;
		ringbuffer->buffer[ringbuffer->tail].session = s;
		ringbuffer->buffer[ringbuffer->tail].tunnel = t;
		va_start(ap, format);
		vsnprintf(ringbuffer->buffer[ringbuffer->tail].message, MAX_LOG_LENGTH, format, ap);
		va_end(ap);
	}
#endif

	if (debuglevel < level) return;

	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);

	if (log_stream)
		fprintf(log_stream, "%s [%04x] %s", time_now_string, pppoe ? pppoe->sid : 0, message);
/*
	else if (syslog_log)
		syslog(level + 2, "%s", message); // We don't need LOG_EMERG or LOG_ALERT
*/

	va_end(ap);
}

void _log_hex(int level, const PPPoESession *pppoe, const char *title, const uint8_t *data, int maxsize)
{
	int i, j;
	const uint8_t *d = data;

	if (debuglevel < level) return;

	// No support for _log_hex to syslog
	if (log_stream)
	{
		_log(level, pppoe, "%s (%d bytes):\n", title, maxsize);
		setvbuf(log_stream, NULL, _IOFBF, 16384);

		for (i = 0; i < maxsize; )
		{
			fprintf(log_stream, "%4X: ", i);
			for (j = i; j < maxsize && j < (i + 16); j++)
			{
				fprintf(log_stream, "%02X ", d[j]);
				if (j == i + 7)
					fputs(": ", log_stream);
			}

			for (; j < i + 16; j++)
			{
				fputs("   ", log_stream);
				if (j == i + 7)
					fputs(": ", log_stream);
			}

			fputs("  ", log_stream);
			for (j = i; j < maxsize && j < (i + 16); j++)
			{
				if (d[j] >= 0x20 && d[j] < 0x7f && d[j] != 0x20)
					fputc(d[j], log_stream);
				else
					fputc('.', log_stream);

				if (j == i + 7)
					fputs("  ", log_stream);
			}

			i = j;
			fputs("\n", log_stream);
		}

		fflush(log_stream);
		setbuf(log_stream, NULL);
	}
}

// format ipv4 addr as a dotted-quad; n chooses one of 4 static buffers
// to use
char *fmtaddr(in_addr_t addr, int n)
{
    static char addrs[4][16];
    struct in_addr in;

    if (n < 0 || n >= 4)
	return "";

    in.s_addr=addr;
    return strcpy(addrs[n], inet_ntoa(in));
}

char *fmtMacAddr(const uint8_t *pMacAddr)
{
	static char strMAC[2*ETH_ALEN];

	sprintf(strMAC, "%02X:%02X:%02X:%02X:%02X:%02X",
			pMacAddr[0], pMacAddr[1], pMacAddr[2],
			pMacAddr[3], pMacAddr[4], pMacAddr[5]);

  return strMAC;
}

