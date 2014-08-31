/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			27.04.2011
 * Dependencies:
 */

#ifndef LOOPDETECTION_H_
#define LOOPDETECTION_H_
#define add_popup add_custom_viewer_popup_item
#define FORWARD 	0
#define BACKWARD 	1
#define UNKNOWN    	2

#include <windef.h>
#include <map>
#include <list>
#include <exception>

#include "ida.hpp"
#include "idp.hpp"
#include "allins.hpp"
#include "kernwin.hpp"

#include "BinaryTree.h"
#include "GlobalIncludes.h"

using namespace std;

/**
 * Loop iteration
 * */
class LoopIteration {
public:
	Idt* start_idt;
	Idt* end_idt;
	LoopIteration(Idt* start, Idt* end);
};

/**
 * Loop execution
 * */
class LoopExecution {
public:
	bool completed;
	list<LoopIteration> iterations;
	LoopExecution(Idt* start, Idt* end);
};

/**
 * Loop
 * */
class Loop {
public:
	bool direction;
	Idt* start_idt; // doesn't work for all loop-types
	//Idt* end_idt; the end idt if found in the last iteration of the last execution.
	Idt* lowest_node_idt;
	Idt* greatest_node_idt;

	uint32 iterations_min;
	uint32 iterations_average;
	uint32 iterations_max;

	list<LoopExecution> executions;
	Loop(Idt* start, Idt* end, bool loop_direction);
};

/**
 * Loop detection
 * */
class LoopDetection {
public:
	LoopDetection();

	void read_data(BinaryTree *bTree);
	void write_information();
	Loop* get_information(Idt* idt);
	uint32 get_iterations(uint32 execution, Loop* loop);
	bool calculate_cycles(Idt* idt, Loop* loop, uint32 *execution,
			uint32 *iteration);
	uint32 get_offset_from_iteration(uint32 execution, uint32 iteration,
			Loop* loop);
	Idt* get_start_idt(Idt* idt, uint32 start_eip);
	Idt* get_end_idt(Idt* idt, Loop* loop, bool *end_execution);

protected:
	char get_loop_direction(Idt* idt, BinaryTree *bTree);
	uint32 get_target_of_instruction(uint32 current_eip);

	bool is_call(uint32 eip);
	bool is_jump(uint32 eip);
	bool is_return(uint32 eip);

	map<uint32, Loop> *loops;
};

#endif /* LOOPDETECTION_H_ */
