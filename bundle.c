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

#include "common.h"
#include "ppp.h"
#include "bundle.h"
#include "log.h"

PPPBundle bundle[MAXBUNDLE];
fragmentationt frag[MAXBUNDLE];

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
			bundle[i].num_of_links = 1;
			bundle[i].last_check = time_now;        // Initialize last_check value
			bundle[i].state = BUNDLEOPEN;
			bundle[i].current_ses = NULL;     // This is to enforce the first session 0 to be used at first
			memset(&frag[i], 0, sizeof(fragmentationt));
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

