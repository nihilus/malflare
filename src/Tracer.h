/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:	libmalflare
 */

#ifndef TRACER_H_
#define TRACER_H_

//-----------------------------------------------------------------------------
// Includes
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_STANDARD_FILE_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS

#include "ida.hpp"
#include "ua.hpp"
#include "kernwin.hpp"
#include "GlobalIncludes.h"
#include "BinaryTree.h"
#include "LoopDetection.h"

//extern "C" {
#include "libmalflare.h"
//}

/*
 * Tracer class
 * */
class Tracer {
public:
	Tracer();
	virtual ~Tracer();

	char* read_tracefile(char* tracefilePath);
	void get_initialized_data(
			void(*callback)(CPU_STATE *cpu_state, uint32 repetition));
	uint32 get_eip_repetition(uint32 eip, bool full);
	uint32 get_eip_repetition(Idt* idt);
	CPU_STATE* read_next_element();
	CPU_STATE* read_previous_element(CPU_STATE **act_cpu_state,
			uint32 *previous_eip);
	Loop* get_loop_information();
	bool calculate_cycles(Loop* loop, uint32 *execution, uint32 *iteration);
	//	int32 calculate_offset_to_execution(uint32 execution, Loop* loop);
	uint32 get_iterations(uint32 execution, Loop* loop);
	uint32 get_offset_from_iteration(uint32 execution, uint32 iteration,
			Loop* loop);
	Idt* get_iteration_idt(int32 offset, char position);
	Idt* get_execution_idt(int32 offset, Loop* loop);
	void write_loop_information();

	//TODO delete
	uint32 get_actual_eip();
	Idt* get_previous_idt(Idt* idt);
	Idt* act_idt;

protected:
	char* open();
	void close();
	CPU_STATE* get_cpu_state();
	CPU_STATE* read_previous_idt(uint32 eip);

	MFT_H *mft_h;
	char* tracefile;
	BinaryTree *bTree;
	LoopDetection *loopDetection;
};

#endif /* TRACER_H_ */
