#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#define MAXUSER         128             // username
#define MAXPASS         128             // password
#define MAX_PPP_SESSION 20		// Max PPP sessions
#define PPPoE_MRU       1492            // maximum PPPoE MRU (rfc2516: 1500 less PPPoE header (6) and PPP protocol ID (2))
#define AUTHPAP         1       // allow PAP
#define AUTHCHAP        2       // allow CHAP

// I can't believe these are in a header file somewhere
#define LCP_CONFREQ     1
#define LCP_CONFACK     2
#define LCP_CONFNAK     3
#define LCP_CONFREJ     4
#define LCP_TERMREQ     5
#define LCP_TERMACK     6
#define LCP_CODEREJ     7
#define LCP_PROTOCOLREJ 8
#define LCP_ECHOREQ     9
#define LCP_ECHOREPLY   10
#define LCP_DISCARDREQ  11
#define LCP_IDENTREQ    12


// This should be a time_t I reckon - DAI
typedef uint32_t clockt;

extern int ppp_restart_time;

#include "pppoe.h"

// PPP phases
enum {
    	Dead,
	Establish,
	Authenticate,
	Network,
	Terminate
};

// PPP states
enum {
	Initial,
	Starting,
	Closed,
	Stopped,
	Closing,
	Stopping,
	RequestSent,
	AckReceived,
	AckSent,
	Opened
};

enum
{
        NULLCLASS = 0,          //End Point Discriminator classes
        LOCALADDR,
        IPADDR,
        IEEEMACADDR,
        PPPMAGIC,
        PSNDN,
};

typedef struct PPPSessionStruct {
	unsigned int epoch;			/* Epoch when last activity was seen */
	uint16_t sesNum;			/* Session number */
	PPPoEInterface const *iface;		/* Interface */
	unsigned char peerMac[ETH_ALEN];	/* Peer's MAC address */
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
	time_t opened;			// when started
	time_t die;			// being closed, when to finally free
	uint32_t session_timeout;	// Maximum session time in seconds
	uint32_t idle_timeout;		// Maximum idle time in seconds
	in_addr_t dns1, dns2;		// DNS servers
	char user[MAXUSER];		// username for client session
	char password[MAXPASS];		// password for client session

	// PPP restart timer/counters
	struct {
		time_t restart;
		int conf_sent;
		int nak_sent;
	} lcp, ipcp, ipv6cp, ccp;

	// identifier for Protocol-Reject, Code-Reject
	uint8_t lcp_ident;

	// authentication to use
	int lcp_authtype;

	// our MRU
	uint16_t ppp_mru;

	// our MRRU
	uint16_t mp_mrru;

	// our mssf
	uint16_t mp_mssf;

	// our Endpoint Discriminator
	in_addr_t mp_epdis;

	// DoS prevention
	clockt last_packet_out;
	uint32_t packets_out;
	uint32_t packets_dropped;

	// RADIUS session in use
	uint16_t radius;

	// interim RADIUS
	time_t last_interim;

	// last LCP Echo
	time_t last_echo;

	// Last Multilink frame sequence number received
	uint32_t last_seq;

	// jitter average of the session
	uint32_t jitteravg;
	// time in milliseconds of the last fragment.
	uint64_t prev_time;
} PPPSession;

PPPSession *ppp_find_session(uint16_t sid);
PPPSession * ppp_new_session(const PPPoEInterface *iface, const uint8_t *addr);
uint8_t *pppoe_makeppp(uint8_t *b, int size, uint8_t *p, int l, const PPPSession *pppSession,
		uint16_t mtype, uint8_t prio, int bid, uint8_t mp_bits);
void sendlcp(PPPSession *pppSession);

// increment ConfReq counter and reset timer
#define restart_timer(_s, _fsm) ({                              \
        _s->_fsm.conf_sent++;                        \
        _s->_fsm.restart =                           \
                time_now + ppp_restart_time;            \
})

// reset state machine counters
#define initialise_restart_count(_s, _fsm)			\
	_s->_fsm.conf_sent =				\
	_s->_fsm.nak_sent = 0

// stop timer on change to state where timer does not run
#define change_state(_s, _fsm, _new) ({				\
	if (_new != _s->ppp._fsm)			\
	{ 							\
		switch (_new)					\
		{						\
		case Initial:					\
		case Starting:					\
		case Closed:					\
		case Stopped:					\
		case Opened:					\
			_s->_fsm.restart = 0;	\
			initialise_restart_count(_s, _fsm);	\
			break;					\
		default:					\
			break;					\
		}						\
		_s->ppp._fsm = _new;			\
	}							\
})

