/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:
 */

#ifndef MAIN_H_
#define MAIN_H_


#include "typedefs.h"
#include "libmalflare.h"

/**
 * Functions
 */
static CPU_STATE *		mft_get_data(MFT_H *, MFT_IDT *, char);
static uint32			mft_ids_length(MFT_H *);

#endif /* MAIN_H_ */
