#ifndef LIBMALFLARE_H_
#define LIBMALFLARE_H_

#include "typedefs.h"

/**
 * Functions
 */

// General handling
MFT_H * 		mft_open(const char *, int);
void 			mft_close(MFT_H *);
uint32 			mft_get_offset(MFT_H *);
int 			mft_set_offset(MFT_H *, uint32);

// Write tracefile
void			mft_add_eip(MFT_H *, uint32);
void 			mft_add_data(MFT_H *, uint8, ...);

// Read tracefile
CPU_STATE *		mft_get_initial_state(MFT_H  *);
CPU_STATE *		mft_next_cpu_state(MFT_H *, int);
CPU_STATE * 	mft_get_cpu_state(MFT_H *, uint32, int);


// Error handling
const char * 	mft_get_last_error();


#endif /* LIBMALFLARE_H_ */
