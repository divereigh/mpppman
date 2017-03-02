#include "config.h"

#define MAXUSER         128             // username
#define MAXPASS         128             // password

typedef struct PPPSessionStruct {
	PPPoESession *pppoe_session;		/* PPPoE Session */
	struct {
		uint8_t phase;          // PPP phase
		uint8_t lcp:4;          //   LCP    state
		uint8_t ipcp:4;         //   IPCP   state
		uint8_t ipv6cp:4;       //   IPV6CP state
		uint8_t ccp:4;          //   CCP    state
	} ppp;
	uint16_t mru;			// maximum receive unit
	in_addr_t ip_remote;		// Remote IP of session
	in_addr_t ip_local;		// Local IP of session
	uint32_t unique_id;		// unique session id
	uint32_t magic;			// ppp magic number
	uint32_t pin, pout;		// packet counts
	uint32_t cin, cout;		// byte counts
	clockt opened;			// when started
	clockt die;			// being closed, when to finally free
	uint32_t session_timeout;	// Maximum session time in seconds
	uint32_t idle_timeout;		// Maximum idle time in seconds
	in_addr_t dns1, dns2;		// DNS servers
	char user[MAXUSER];		// username for client session
	char password[MAXPASS];		// password for client session
} PPPSession;

