#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#endif

#include "common.h"
#include "ppp.h"
#include "bundle.h"
#include "log.h"
#include "ip.h"
#include "ipv6.h"
#include "ccp.h"

PPPBundle bundle[MAXBUNDLE];
fragmentationt frag[MAXBUNDLE];

extern uint64_t time_now_ms;

static int epdiscmp(epdist ep1, epdist ep2)
{
	int ad;
	if (ep1.length != ep2.length)
		return 0;

	if (ep1.addr_class != ep2.addr_class)
		return 0;

	for (ad = 0; ad < ep1.length; ad++)
		if (ep1.address[ad] != ep2.address[ad])
			return 0;

	return 1;
}

static void setepdis(epdist *ep1, epdist ep2)
{
	int ad;
	ep1->length = ep2.length;
	ep1->addr_class = ep2.addr_class;
	for (ad = 0; ad < ep2.length; ad++)
		ep1->address[ad] = ep2.address[ad];
}

static PPPBundle *new_bundle()
{
	int i;
	for (i = 1; i < MAXBUNDLE; i++)
	{
		LOG(3, NULL, "MPPP: Check bundle %d, state=%d\n", i, bundle[i].state);
		if (bundle[i].state == BUNDLEFREE)
		{
			LOG(4, NULL, "MPPP: Assigning bundle ID %d\n", i);
			bundle[i].id=i;
			bundle[i].num_of_links = 1;
			bundle[i].last_check = time_now;        // Initialize last_check value
			bundle[i].state = BUNDLEOPEN;
			bundle[i].current_ses = -1;     // This is to enforce the first session 0 to be used at first
			memset(&frag[i], 0, sizeof(fragmentationt));
			bundle[i].frag=&frag[i];
			return &bundle[i];
		}
	}
	LOG(0, NULL, "MPPP: Can't find a free bundle! There shouldn't be this many in use!\n");
	return NULL;
}

PPPBundle *join_bundle(PPPSession *pppSession)
{
	// Search for a bundle to join
	int i;
	PPPBundle *b;

	if (!pppSession->opened || pppSession->die)
	{
		LOG(3, NULL, "Called join_bundle on an unopened/shutdown session.\n");
		return NULL;                   // not a live session
	}

	for (i = 1; i < MAXBUNDLE; i++)
	{
		if (bundle[i].state != BUNDLEFREE)
		{
			if (epdiscmp(pppSession->epdis,bundle[i].epdis) && !strcmp(pppSession->user, bundle[i].user))
			{
				PPPSession *first_ses = bundle[i].members[0];
				if (bundle[i].mssf != pppSession->mssf)
				{
					// uniformity of sequence number format must be insured
					LOG(3, pppSession->pppoeSession, "MPPP: unable to bundle session in bundle %d cause of different mssf\n", i);
					LOG(0, pppSession->pppoeSession, "MPPP: Mismatching mssf option with other sessions in bundle\n");
					return NULL;
				}
				pppSession->bundle = &bundle[i];
				//pppSession->ip = first_ses->ip;
				//pppSession->dns1 = first_ses->dns1;
				//pppSession->dns2 = first_ses->dns2;
				//pppSession->timeout = first_ses->timeout;

				if(pppSession->epdis.length > 0)
					setepdis(&bundle[i].epdis, pppSession->epdis);

				strcpy(bundle[i].user, pppSession->user);
				bundle[i].members[bundle[i].num_of_links] = pppSession;
				bundle[i].num_of_links++;
				LOG(3, pppSession->pppoeSession, "MPPP: Bundling additional line in bundle (%d), lines:%d\n",i,bundle[i].num_of_links);
				return &bundle[i];
			}
		}
	}

	// No previously created bundle was found for this session, so create a new one
	if (!(b = new_bundle())) return NULL;

	pppSession->bundle = b;
	b->mrru = pppSession->mrru;
	b->mssf = pppSession->mssf;
	// FIXME !!! to enable l2tpns reading mssf frames receiver_max_seq, sender_max_seq must be introduce
	// now session[s].mssf flag indecates that the receiver wish to receive frames in mssf, so max_seq (i.e. recv_max_seq) = 1<<24
	/*
	if (b->mssf)
		b->max_seq = 1 << 12;
	else */
		b->max_seq = 1 << 24;
	if(pppSession->epdis.length > 0)
		setepdis(&(b->epdis), pppSession->epdis);

	strcpy(b->user, pppSession->user);
	b->members[0] = pppSession;
	//b->timeout = pppSession->timeout;
	LOG(3, pppSession->pppoeSession, "MPPP: Created a new bundle\n");
	return b;
}

void processmpframe(PPPSession *pppSession, uint8_t *p, uint16_t l, uint8_t extra)
{
	uint16_t proto;
	if (extra) {
		// Skip the four extra bytes
		p += 4;
		l -= 4;
	}

        if (*p & 1)
        {
                proto = *p++;
                l--;
        }
        else
        {
                proto = ntohs(*(uint16_t *) p);
                p += 2;
                l -= 2;
        }
        if (proto == PPP_IP)
        {
                if (pppSession->die)
                {
                        LOG(4, pppSession->pppoeSession, "MPPP: Session is closing.  Don't process PPP packets\n");
                        return;              // closing session, PPP not processed
                }
                pppSession->last_packet = pppSession->last_data = time_now;
                processip_in(pppSession, p, l);
        }
        else if (proto == PPP_IPV6 /* && config->ipv6_prefix.s6_addr[0] */)
        {
                if (pppSession->die)
                {
                        LOG(4, pppSession->pppoeSession, "MPPP: Session is closing.  Don't process PPP packets\n");
                        return;              // closing session, PPP not processed
                }

                pppSession->last_packet = pppSession->last_data = time_now;
                processipv6(pppSession, p, l);
        }
	else if (proto == PPP_IPCP)
        {
                pppSession->last_packet = pppSession->last_data = time_now;
                processipcp(pppSession, p, l);
        }
        else if (proto == PPP_CCP)
        {
                pppSession->last_packet = pppSession->last_data = time_now;
                processccp(pppSession, p, l);
        }
        else
        {
                LOG(2, pppSession->pppoeSession, "MPPP: Unsupported MP protocol 0x%04X received\n",proto);
        }
}

/* Process MP packet - pack points the PPP payload */
void processmp(PPPSession *pppSession, uint8_t *p, uint16_t l)
{
	PPPBundle * this_bundle = pppSession->bundle;
	uint32_t maskSeq, max_seq;
	int frag_offset;
	uint16_t frag_index, frag_index_next, frag_index_prev;
	fragmentationt *this_fragmentation;
	uint8_t begin_frame = (*p & MP_BEGIN);
	uint8_t end_frame = (*p & MP_END);
	uint32_t seq_num, seq_num_next, seq_num_prev;
	uint32_t i;
	uint8_t flags = *p;
	uint16_t begin_index, end_index;

	LOG(3, pppSession->pppoeSession, "Got MP packet\n");
	// Perform length checking
	if(l > MAXFRAGLEN)
	{
		LOG(2, pppSession->pppoeSession, "MPPP: discarding fragment larger than MAXFRAGLEN\n");
		return;
	}

	if(this_bundle==NULL)
	{
		LOG(2, pppSession->pppoeSession, "MPPP: Invalid bundle : NULL\n");
		return;
	}

	this_fragmentation = this_bundle->frag;

	// FIXME !! session[s].mssf means that the receiver wants to receive frames in mssf not means the receiver will send frames in mssf
	/* if(session[s].mssf)
	{
		// Get 12 bit for seq number
		seq_num = ntohs((*(uint16_t *) p) & 0xFF0F);
		p += 2;
		l -= 2;
		// After this point the pointer should be advanced 2 bytes
		LOG(3, pppSession->pppoeSession, "MPPP: 12 bits, sequence number: %d\n",seq_num);
	}
	else */
	{
		// Get 24 bit for seq number
		seq_num = ntohl((*(uint32_t *) p) & 0xFFFFFF00);
		p += 4;
		l -= 4;
		// After this point the pointer should be advanced 4 bytes
		LOG(4, pppSession->pppoeSession, "MPPP: 24 bits sequence number:%d\n",seq_num);
	}

	max_seq = this_bundle->max_seq;
	maskSeq = max_seq - 1;

	/*
	 * Expand sequence number to 32 bits, making it as close
	 * as possible to this_fragmentation->M.
	 */
	seq_num |= this_fragmentation->M & ~maskSeq;
	if ((int)(this_fragmentation->M - seq_num) > (int)(maskSeq >> 1))
	{
		seq_num += maskSeq + 1;
	}
	else if ((int)(seq_num - this_fragmentation->M) > (int)(maskSeq >> 1))
	{
		seq_num -= maskSeq + 1;	/* should never happen */
	}

	// calculate this fragment's offset from the begin seq in the bundle
	frag_offset = (int) (seq_num - this_fragmentation->start_seq);
	
	pppSession->last_seq = seq_num;

	// calculate the jitter average
	uint32_t ljitter = time_now_ms - pppSession->prev_time;
	if (ljitter > 0)
	{
		pppSession->jitteravg = (pppSession->jitteravg + ljitter)>>1;
		pppSession->prev_time = time_now_ms;
	}

	uint32_t Mmin;

	if (seq_num < this_fragmentation->M)
	{
		Mmin = seq_num;
		this_fragmentation->M = seq_num;
	}
	else
	{
		Mmin = this_bundle->members[0]->last_seq;
		for (i = 1; i < this_bundle->num_of_links; i++)
		{
			uint32_t s_seq = this_bundle->members[i]->last_seq;
			if (s_seq < Mmin)
				Mmin = s_seq;
		}
		this_fragmentation->M = Mmin;
	}

	// calculate M offset of the M seq in the bundle
	int M_offset = (int) (Mmin - this_fragmentation->start_seq);

	if (M_offset >= MAXFRAGNUM)
	{
		// There have a long break of the link !!!!!!!!
		// M_offset is bigger that the fragmentation buffer size
		LOG(3, pppSession->pppoeSession, "MPPP: M_offset out of range, min:%d, begin_seq:%d\n", Mmin, this_fragmentation->start_seq);

		// Calculate the new start index, the previous frag are lost
		begin_index = (M_offset + this_fragmentation->start_index) & MAXFRAGNUM_MASK;

		// Set new Start sequence
		this_fragmentation->start_index = begin_index;
		this_fragmentation->start_seq = Mmin;
		M_offset = 0;
		// recalculate the fragment offset from the new begin seq in the bundle
		frag_offset = (int) (seq_num - Mmin);
	}

	// discard this fragment if the packet comes before the start sequence
	if (frag_offset < 0)
	{
		// this packet comes before the next
		LOG(3, pppSession->pppoeSession, "MPPP: (COMES BEFORE) the next, seq:%d, begin_seq:%d, size_frag:%d, flags:%02X is LOST\n", seq_num, this_fragmentation->start_seq, l, flags);
		return;
	}

	// discard if frag_offset is bigger that the fragmentation buffer size
	if (frag_offset >= MAXFRAGNUM)
	{
		// frag_offset is bigger that the fragmentation buffer size
		LOG(3, pppSession->pppoeSession, "MPPP: Index out of range, seq:%d, begin_seq:%d\n", seq_num, this_fragmentation->start_seq);
		return;
	}

	//caculate received fragment's index in the fragment array
	frag_index = (frag_offset + this_fragmentation->start_index) & MAXFRAGNUM_MASK;

	// insert the frame in it's place
	fragmentt *this_frag = &this_fragmentation->fragment[frag_index];

	if (this_frag->length > 0)
		// This fragment is lost, It was around the buffer and it was never completed the packet.
		LOG(3, this_frag->pppSession->pppoeSession, "MPPP: (INSERT) seq_num:%d frag_index:%d flags:%02X is LOST\n",
			this_frag->seq, frag_index, this_frag->flags);

	this_frag->length = l;
	this_frag->pppSession = pppSession;
	this_frag->flags = flags;
	this_frag->seq = seq_num;
	this_frag->jitteravg = pppSession->jitteravg;
	memcpy(this_frag->data, p, l);

	LOG(4, pppSession->pppoeSession, "MPPP: seq_num:%d frag_index:%d INSERTED flags: %02X\n",  seq_num, frag_index, flags);

	//next frag index
	frag_index_next = (frag_index + 1) & MAXFRAGNUM_MASK;
	//previous frag index
	frag_index_prev = (frag_index - 1) & MAXFRAGNUM_MASK;
	// next seq
	seq_num_next = seq_num + 1;
	// previous seq
	seq_num_prev = seq_num - 1;

	// Clean the buffer and log the lost fragments
	if ((frag_index_next != this_fragmentation->start_index) && this_fragmentation->fragment[frag_index_next].length)
	{
		// check if the next frag is a lost fragment
		if (this_fragmentation->fragment[frag_index_next].seq != seq_num_next)
		{
			// This fragment is lost, It was around the buffer and it was never completed the packet.
			LOG(3, this_fragmentation->fragment[frag_index_next].pppSession->pppoeSession,
				"MPPP: (NEXT) seq_num:%d frag_index:%d flags:%02X is LOST\n",
				this_fragmentation->fragment[frag_index_next].seq, frag_index_next,
				this_fragmentation->fragment[frag_index_next].flags);
			// this frag is lost
			this_fragmentation->fragment[frag_index_next].length = 0;
			this_fragmentation->fragment[frag_index_next].flags = 0;

			if (begin_frame && (!end_frame)) return; // assembling frame failed
		}
	}

	// Clean the buffer and log the lost fragments
	if ((frag_index != this_fragmentation->start_index) && this_fragmentation->fragment[frag_index_prev].length)
	{
		// check if the next frag is a lost fragment
		if (this_fragmentation->fragment[frag_index_prev].seq != seq_num_prev)
		{
			// This fragment is lost, It was around the buffer and it was never completed the packet.
			LOG(3, this_fragmentation->fragment[frag_index_prev].pppSession->pppoeSession,
				"MPPP: (PREV) seq_num:%d frag_index:%d flags:%02X is LOST\n",
				this_fragmentation->fragment[frag_index_prev].seq, frag_index_prev,
				this_fragmentation->fragment[frag_index_prev].flags);

			this_fragmentation->fragment[frag_index_prev].length = 0;
			this_fragmentation->fragment[frag_index_prev].flags = 0;

			if (end_frame && (!begin_frame)) return; // assembling frame failed
		}
	}

find_frame:
	begin_index = this_fragmentation->start_index;
	uint32_t b_seq = this_fragmentation->start_seq;
	// Try to find a Begin sequence from the start_seq sequence to M sequence
	while (b_seq < Mmin)
	{
		if (this_fragmentation->fragment[begin_index].length)
		{
			if (b_seq == this_fragmentation->fragment[begin_index].seq)
			{
				if (this_fragmentation->fragment[begin_index].flags & MP_BEGIN)
				{
					int isfoundE = 0;
					// Adjust the new start sequence and start index
					this_fragmentation->start_index = begin_index;
					this_fragmentation->start_seq = b_seq;
					// Begin Sequence found, now try to found the End Sequence to complete the frame
					end_index = begin_index;
					while (b_seq < Mmin)
					{
						if (this_fragmentation->fragment[end_index].length)
						{
							if (b_seq == this_fragmentation->fragment[end_index].seq)
							{
								if (this_fragmentation->fragment[end_index].flags & MP_END)
								{
									// The End sequence was found and the frame is complete
									isfoundE = 1;
									break;
								}
							}
							else
							{
								// This fragment is lost, it was never completed the packet.
								LOG(3, this_fragmentation->fragment[end_index].pppSession->pppoeSession,
									"MPPP: (FIND END) seq_num:%d frag_index:%d flags:%02X is LOST\n",
									this_fragmentation->fragment[end_index].seq, begin_index,
									this_fragmentation->fragment[end_index].flags);
								// this frag is lost
								this_fragmentation->fragment[end_index].length = 0;
								this_fragmentation->fragment[end_index].flags = 0;
								// This frame is not complete find the next Begin
								break;
							}
						}
						else
						{
							// This frame is not complete find the next Begin if exist
							break;
						}
						end_index = (end_index +1) & MAXFRAGNUM_MASK;
						b_seq++;
					}

					if (isfoundE)
						// The End sequence was found and the frame is complete
						break;
					else
						// find the next Begin
						begin_index = end_index;
				}
			}
			else
			{
				// This fragment is lost, it was never completed the packet.
				LOG(3, this_fragmentation->fragment[begin_index].pppSession->pppoeSession,
					"MPPP: (FIND BEGIN) seq_num:%d frag_index:%d flags:%02X is LOST\n",
					this_fragmentation->fragment[begin_index].seq, begin_index,
					this_fragmentation->fragment[begin_index].flags);
				// this frag is lost
				this_fragmentation->fragment[begin_index].length = 0;
				this_fragmentation->fragment[begin_index].flags = 0;
			}
		}
		begin_index = (begin_index +1) & MAXFRAGNUM_MASK;
		b_seq++;
	}

assembling_frame:
	// try to assemble the frame that has the received fragment as a member
	// get the beginning of this frame
	begin_index = end_index = this_fragmentation->start_index;
	if (this_fragmentation->fragment[begin_index].length)
	{
		if (!(this_fragmentation->fragment[begin_index].flags & MP_BEGIN))
		{
			LOG(3, this_fragmentation->fragment[begin_index].pppSession->pppoeSession,
				"MPPP: (NOT BEGIN) seq_num:%d frag_index:%d flags:%02X\n",
				this_fragmentation->fragment[begin_index].seq, begin_index,
				this_fragmentation->fragment[begin_index].flags);
			// should occur only after an "M_Offset out of range"
			// The start sequence must be a begin sequence
			this_fragmentation->start_index = (begin_index +1) & MAXFRAGNUM_MASK;
			this_fragmentation->start_seq++;
			return; // assembling frame failed
		}
	}
	else
		return; // assembling frame failed

	// get the end of his frame
	while (this_fragmentation->fragment[end_index].length)
	{
		if (this_fragmentation->fragment[end_index].flags & MP_END)
			break;

		end_index = (end_index +1) & MAXFRAGNUM_MASK;

		if (end_index == this_fragmentation->start_index)
			return; // assembling frame failed
	}

	// return if a lost fragment is found
	if (!(this_fragmentation->fragment[end_index].length))
		return; // assembling frame failed

	// assemble the packet
	//assemble frame, process it, reset fragmentation
	uint16_t cur_len = 4;   // This is set to 4 to leave 4 bytes for function processipin

	LOG(4, pppSession->pppoeSession, "MPPP: processing fragments from %d to %d\n", begin_index, end_index);
	// Push to the receive buffer

	for (i = begin_index;; i = (i + 1) & MAXFRAGNUM_MASK)
	{
		this_frag = &this_fragmentation->fragment[i];
		if(cur_len + this_frag->length > MAXETHER)
		{
			LOG(2, pppSession->pppoeSession, "MPPP: discarding reassembled frames larger than MAXETHER\n");
			break;
		}

		memcpy(this_fragmentation->reassembled_frame+cur_len, this_frag->data, this_frag->length);
		LOG(5, pppSession->pppoeSession, "MPPP: processing frame at %d, with len %d\n", i, this_frag->length);

		cur_len += this_frag->length;
		if (i == end_index)
		{
			this_fragmentation->re_frame_len = cur_len;
			this_fragmentation->re_frame_begin_index = begin_index;
			this_fragmentation->re_frame_end_index = end_index;
			// Process the resassembled frame
			LOG(5, pppSession->pppoeSession, "MPPP: Process the reassembled frame, len=%d\n",cur_len);
			processmpframe(pppSession, this_fragmentation->reassembled_frame, this_fragmentation->re_frame_len, 1);
			break;
		}
	}

	// Set reassembled frame length to zero after processing it
	this_fragmentation->re_frame_len = 0;
	for (i = begin_index;; i = (i + 1) & MAXFRAGNUM_MASK)
	{
		this_fragmentation->fragment[i].length = 0;      // Indicates that this fragment has been consumed
		this_fragmentation->fragment[i].flags = 0;
		if (i == end_index)
			break;
	}

	// Set the new start_index and start_seq
	this_fragmentation->start_index = (end_index + 1) & MAXFRAGNUM_MASK;
	this_fragmentation->start_seq = this_fragmentation->fragment[end_index].seq + 1;
	LOG(4, pppSession->pppoeSession, "MPPP after assembling: start index is = %d, start seq=%d\n", this_fragmentation->start_index, this_fragmentation->start_seq);

	begin_index = this_fragmentation->start_index;
	if ((this_fragmentation->fragment[begin_index].length) &&
		(this_fragmentation->fragment[begin_index].seq != this_fragmentation->start_seq))
	{
		LOG(3, this_fragmentation->fragment[begin_index].pppSession->pppoeSession,
				"MPPP: (START) seq_num:%d frag_index:%d flags:%02X is LOST\n",
				this_fragmentation->fragment[begin_index].seq, begin_index,
				this_fragmentation->fragment[begin_index].flags);
			this_fragmentation->fragment[begin_index].length = 0;
			this_fragmentation->fragment[begin_index].flags = 0;
	}

	if (this_fragmentation->start_seq <= Mmin)
		// It's possible to find other complete frame or lost frame.
		goto find_frame;
	else if ((this_fragmentation->fragment[begin_index].length) &&
			  (this_fragmentation->fragment[begin_index].flags & MP_BEGIN))
		// may be that the next frame is completed
		goto assembling_frame;

	return;
}
