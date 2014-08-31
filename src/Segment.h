/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			30.03.2011
 * Dependencies:
 */

#ifndef SEGMENT_H_
#define SEGMENT_H_

#include "ida.hpp"
#include "kernwin.hpp"
#include "segment.hpp"
#include "bytes.hpp"
#include "GlobalIncludes.h"


/*
 * Class to create and modify a segment.
 * */
class Segment {
public:
	Segment(const char *segment_name);

	bool write_data(uint32 start, const char* data, uint32 length,
			bool backup_old_data, bool print_log);
	bool restore_data(uint32 start, uint32 length, bool print_log);

	uint32 get_start_address();
	uint32 get_end_address();

private:
	char name[128];
	uint32 start_address;
	uint32 end_address;
	segment_t *mft_segment;
};

#endif /* SEGMENT_H_ */
