/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			30.03.2011
 * Dependencies:
 */

#include "Segment.h"

/*
 * Create a new segment in the IDA Pro database.
 * */
Segment::Segment(const char *segment_name) {
	start_address = 0;
	end_address = 0;
	//name = segment_name;
	qstrncpy(name, segment_name, sizeof(name));
	mft_segment = get_segm_by_name(name);
	if (mft_segment != NULL) {
		// Segment already exist.
		start_address = mft_segment->startEA;
		end_address = mft_segment->endEA;
		msg(
				"%s-segment already exist. Segment start = '0x%08x'. Segment end = '0x%08x'\n",
				name, start_address, end_address);
	}
}

/*
 * Write bytes to the segment
 * */
bool Segment::write_data(uint32 start, const char* data, uint32 length,
		bool backup_old_data, bool print_log) {
	if ((!start_address) && (!end_address)) {
		//create new segment
		int returnVal = add_segm(0, start, // start (inclusive)
				start + length, //end (exclusive)
				name, "DATA");
		if (returnVal) {
			start_address = start;
			end_address = start + length;
		} else {
			return false;
		}
	}

	// Check the start address
	if (start_address > start) {
		if (set_segm_start(start_address, start, 0)) { // move_segm_start
			start_address = start;
			// don't write by init
			if (print_log) {
				msg("Set new %s-Segment start to 0x%08x\n", name, start_address);
			}
		} else {
			msg(
					"Error by write data to memory address 0x%08x. Can't move %s-Segment start\n",
					start, name);
			return false;
		}
	}
	// Check the end address
	if (end_address < (start + length)) {
		if (set_segm_end(end_address - 1, start + length, 0)) {
			end_address = start + length;
			// don't write by init
			if (print_log) {
				msg("Set new %s-Segment end to 0x%08x\n", name, end_address);
			}
		} else {
			msg(
					"Error by write data to memory address 0x%08x. Can't move %s's end from 0x%08x to 0x%08x\n",
					start + length, name, end_address, start + length);
			return false;
		}
	}
	// Write data to segment
	if (backup_old_data) {
		patch_many_bytes(start, data, length);
		if (print_log) {
			msg(
					"Write Memory from 0x%08x to 0x%08x (%i Bytes) with data '%s'\n",
					start, start + length, length, data);
		}
	} else {
		put_many_bytes(start, data, length);
	}

	return true;
}

/*
 * Restore data.
 * */
bool Segment::restore_data(uint32 start, uint32 length, bool print_log) {
	if ((start < start_address) || (start + length > end_address))
		return false;

	for (uint32 addr = start; addr < start + length; addr++) {
		put_byte(addr, get_original_byte(addr));
	}
	if (print_log) {
		msg("Restore Memory from 0x%08x to 0x%08x (%i Bytes)\n", start,
				start + length, length);
	}
	return true;
}

/*
 * Getters
 */
uint32 Segment::get_end_address() {
	return end_address;
}

uint32 Segment::get_start_address() {
	return start_address;
}
