/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			14.06.2011
 * Dependencies:
 */

#ifndef SEGMENTMANAGER_H_
#define SEGMENTMANAGER_H_

#include "ida.hpp"
#include "segment.hpp"
#include "segment.h"
#include <list>

using namespace std;

/*
 * Class to handle malflare and ida segments
 * */
class SegmentManager {
public:
	// Sigleton construct
	static SegmentManager * Instance();

	bool write_data(uint32 start, const char* data, uint32 length, bool backup_old_data, bool print_log);
	bool restore_data(uint32 start, uint32 length, bool print_log);

private:
	SegmentManager();

	// Keeping copy constructor and assignment operator private
	SegmentManager(SegmentManager const&){};
	SegmentManager& operator=(SegmentManager const&){};

	//funcs
	void migrate_segments();
	Segment * get_segment(uint32 start, uint32 length);
	void print_segment(Segment *s);
	Segment * create_new_segment();


	//vars
	static SegmentManager *instance;
	static int segment_number;
	list<Segment> segments;

};

#endif /* SEGMENTMANAGER_H_ */
