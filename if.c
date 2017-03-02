#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_LINUX_IF_PACKET_H
#define HAVE_STRUCT_SOCKADDR_LL 1
#include <linux/if_packet.h>
#endif

#include "if.h"
#include "log.h"

#define NOT_UNICAST(e) ((e[0] & 0x01) != 0)

/**********************************************************************
*%FUNCTION: openInterface
*%ARGUMENTS:
* ifname -- name of interface
* type -- Ethernet frame type
* hwaddr -- if non-NULL, set to the hardware address
* mtu    -- if non-NULL, set to the MTU
*%RETURNS:
* A raw socket for talking to the Ethernet card.  Exits on error.
*%DESCRIPTION:
* Opens a raw Ethernet socket
***********************************************************************/
int
openInterface(char const *ifname, uint16_t type, unsigned char *hwaddr, uint16_t *mtu)
{
	int optval=1;
	int fd;
	struct ifreq ifr;
	int domain, stype;

#ifdef HAVE_STRUCT_SOCKADDR_LL
	struct sockaddr_ll sa;
#else
	struct sockaddr sa;
#endif

	memset(&sa, 0, sizeof(sa));

#ifdef HAVE_STRUCT_SOCKADDR_LL
	domain = PF_PACKET;
	stype = SOCK_RAW;
#else
	domain = PF_INET;
	stype = SOCK_PACKET;
#endif

	if ((fd = socket(domain, stype, htons(type))) < 0) {
		/* Give a more helpful message for the common error case */
		if (errno == EPERM) {
			LOG(0, "Cannot create raw socket -- must be run as root.\n");
		}
		sysFatal("socket");
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
		sysFatal("setsockopt");
	}

	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		sysFatal("fcntl");
	}

	/* Fill in hardware address */
	if (hwaddr) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
	    		sysFatal("ioctl(SIOCGIFHWADDR)");
		}
		memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#ifdef ARPHRD_ETHER
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			char buffer[256];
			sprintf(buffer, "Interface %.16s is not Ethernet", ifname);
			sysFatal(buffer);
		}
#endif
	if (NOT_UNICAST(hwaddr)) {
	    char buffer[256];
	    sprintf(buffer,
		    "Interface %.16s has broadcast/multicast MAC address??",
		    ifname);
	    sysFatal(buffer);
	}
}

	/* Sanity check on MTU */
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		sysFatal("ioctl(SIOCGIFMTU)");
	}
	if (ifr.ifr_mtu < ETH_DATA_LEN) {
		char buffer[256];
		sprintf(buffer, "Interface %.16s has MTU of %d -- should be %d.  You may have serious connection problems.",
		ifname, ifr.ifr_mtu, ETH_DATA_LEN);
		LOG(0, "%s\n", buffer);
	}
	if (mtu) *mtu = ifr.ifr_mtu;

#ifdef HAVE_STRUCT_SOCKADDR_LL
	/* Get interface index */
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(type);

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		sysFatal("ioctl(SIOCFIGINDEX): Could not get interface index");
	}
	sa.sll_ifindex = ifr.ifr_ifindex;

#else
	strcpy(sa.sa_data, ifname);
#endif

	/* We're only interested in packets on specified interface */
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		sysFatal("bind");
	}

	return fd;
}

