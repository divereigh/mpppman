#ifndef __BUNDLE_H
#define __BUNDLE_H
#include "config.h"

#include "ppp.h"

#define MAXBUNDLESES 10
#define MAXBUNDLE 5

#define MP_BEGIN        0x80            // This value is used when (b)egin bit is set in MP header
#define MP_END          0x40            // This value is used when (e)nd bit is set in MP header
#define MP_BOTH_BITS    0xC0            // This value is used when both bits (begin and end) are set in MP header

#define MINFRAGLEN	64		// Minumum fragment length
#define MAXFRAGLEN	1496	// Maximum length for Multilink fragment (The multilink may contain only one link)
#define MAXFRAGNUM	512		// Maximum number of Multilink fragment in a bundle (must be in the form of 2^X)
					// it's not expected to have a space for more than 10 unassembled packets = 10 * MAXBUNDLESES
#define	MAXFRAGNUM_MASK	(MAXFRAGNUM - 1)		// Must be equal to MAXFRAGNUM-1

enum
{
	BUNDLEFREE = 0,		// Not in use
	BUNDLEOPEN,		// Active bundle
	BUNDLEUNDEF,		// Undefined
};

typedef struct {
	PPPSession *pppSession;		// Fragment originating session
	uint8_t	flags;			// MP frame flags
	uint32_t seq;			// fragment seq num
	uint32_t jitteravg;
        uint16_t length;                // Fragment length
        uint8_t data[MAXFRAGLEN];       // Fragment data
} fragmentt;

typedef struct
{
	fragmentt fragment[MAXFRAGNUM];
	uint8_t reassembled_frame[MAXETHER];    // The reassembled frame
	uint16_t re_frame_len;                  // The reassembled frame length
	uint16_t re_frame_begin_index, re_frame_end_index;	// reassembled frame begin index, end index respectively
	uint16_t start_index, end_index;	// start and end sequence numbers available on the fragments array respectively
	uint32_t M;				// Minumum frame sequence number received over all bundle members
	uint32_t start_seq;                     // Last received frame sequence number (bearing B bit)
}
fragmentationt;

typedef struct PPPBundleStruct {
	int id;					// ID number
        int state;                              // current state (bundlestate enum)
        uint32_t seq_num_t;                     // Sequence Number (transmission)
        uint32_t timeout;                       // Session-Timeout for bundle
	uint32_t max_seq;			// Max value of sequence number field
        uint8_t num_of_links;                   // Number of links joint to this bundle
        uint32_t online_time;                   // The time this bundle is online
        clockt last_check;                      // Last time the timeout is checked
        uint32_t mrru;                          // Multilink Max-Receive-Reconstructed-Unit
        uint8_t mssf;                           // Multilink Short Sequence Number Header Format
        epdist epdis;                           // Multilink Endpoint Discriminator
        char user[MAXUSER];                     // Needed for matching member links
        uint32_t current_ses;                       // Current session to use for sending (used in RR load-balancing)
        PPPSession *members[MAXBUNDLESES];       // Array for member links sessions
	fragmentationt *frag;			// Link to fragmentation stuff
} PPPBundle;

PPPBundle *join_bundle(PPPSession *pppSession);
void processmp(PPPSession *pppSession, uint8_t *p, uint16_t l);
#endif
