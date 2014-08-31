/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			27.04.2011
 * Dependencies:
 */

#include "LoopDetection.h"

using namespace std;

/**
 * Loop execution constructor
 * @param t target address
 * @param b branch address
 * */
LoopExecution::LoopExecution(Idt* start, Idt* end) {
	iterations.push_back(LoopIteration(start, end));
	completed = false;
}

/**
 * Loop iteration constructor
 * @param t target idt
 * @param b branch idt
 * */
LoopIteration::LoopIteration(Idt* start, Idt* end) {
	start_idt = start;
	end_idt = end;
}

/**
 * Loop constructor
 * @param t target idt
 * @param b branch idt
 * */
Loop::Loop(Idt* start, Idt* end, bool loop_direction) {
	direction = loop_direction;
	lowest_node_idt = start;
	greatest_node_idt = end;

	if (direction == FORWARD) {
		start_idt = lowest_node_idt; // TODO
	} else if (direction == BACKWARD) {
		Idt* tmp_idt = end->previous;
		do {
			if ((tmp_idt->eip < start->eip) || (tmp_idt->eip > end->eip)) {
				start_idt = tmp_idt->next;
				break;
			}
			tmp_idt = tmp_idt->previous;
		} while (tmp_idt != NULL);
	}
	executions.push_back(LoopExecution(start, end));
}

/**
 * Loop detection constructor
 * */
LoopDetection::LoopDetection() {
	loops = new map<uint32, Loop> ;
}

/**
 *
 * */
void LoopDetection::read_data(BinaryTree *bTree) {
	if (bTree == NULL) {
		return;
	}
	try {
		Idt* idt = bTree->root_idt;
		do {
			if (is_jump(idt->eip)) {
				// get target of instruction
				uint32 target_address = get_target_of_instruction(idt->eip);

				// target above the current eip?
				if ((target_address != 0) && (target_address < idt->eip)) {
					// check if target exists
					map<uint32, Loop>::iterator loopIterator = loops->find(
							target_address);

					// target doesn't exists in the map
					if (loopIterator == loops->end()) {
						// the jump is taken?
						if (target_address == idt->next->eip) {
							// record a iteration and execution
							bool direction = get_loop_direction(idt, bTree);
							Idt* start_idt = NULL;
							Idt* end_idt = NULL;
							if (direction == BACKWARD) {
								end_idt = idt;
								start_idt = get_start_idt(idt, idt->next->eip);
							} else { // FORWARD
								bool end_execution = false;
								end_idt
										= get_end_idt(idt, NULL, &end_execution);
								start_idt = idt->next;
							}

							if ((end_idt != NULL) && (start_idt != NULL)) {
								loops->insert(
										pair<uint32, Loop> (
												start_idt->eip, // target_address
												Loop(start_idt, end_idt,
														direction)));
							}
						}
					} else { // already in map
						// the jump is taken?
						if (target_address == idt->next->eip) {
							bool end_execution = false;
							Idt* start_idt = NULL;
							Idt* end_idt = NULL;

							if (loopIterator->second.direction == BACKWARD) {
								end_idt = idt;
								start_idt = get_start_idt(idt, idt->next->eip);
							} else if (loopIterator->second.direction
									== FORWARD) {
								end_idt = get_end_idt(idt,
										&loopIterator->second, &end_execution);
								start_idt = idt->next;
							}

							// record a iteration
							if (loopIterator->second.executions.back().completed
									== true) {
								// create new execution and iteration
								loopIterator->second.executions.push_back(
										LoopExecution(start_idt, end_idt));

							} else {
								// create new iteration
								loopIterator->second.executions.back().iterations.push_back(
										LoopIteration(start_idt, end_idt));
							}

							if (end_execution) {
								loopIterator->second.executions.back().completed
										= true;
							}
							// update greatest end idt
							if (idt->eip
									> loopIterator->second.greatest_node_idt->eip) {
								loopIterator->second.greatest_node_idt = idt;
							}
						} else {
							if (loopIterator->second.direction == FORWARD
									|| BACKWARD) {
								loopIterator->second.executions.back().completed
										= true;
							}
						}
					}
				}
			}
			idt = idt->next;
		} while ((idt != NULL) && (idt->next != NULL));
	} catch (...) {
		msg("Class:LoopDetection->Method:add_data. Exception: unknown\n");
	}
}

/**
 * Get the loop direction
 * @return 0 = forward, 1 = backward
 * */
char LoopDetection::get_loop_direction(Idt* idt, BinaryTree *bTree) {
	uint32 repetition = bTree->get_repetition(idt->next->eip, 0);
	uint32 act_repetition = bTree->get_repetition(idt->next);

	if (repetition == 1) {
		return UNKNOWN;
	}
	if (act_repetition == 1) {
		return FORWARD;
	} else if (act_repetition > 1) {
		return BACKWARD;
	}
	return UNKNOWN;
}

/**
 * Run forward to the end
 * @return the Idt
 * */
Idt* LoopDetection::get_end_idt(Idt* idt, Loop* loop, bool *end_execution) {
	if (idt == NULL) {
		return NULL;
	}
	*end_execution = false;
	Idt* tmp_idt = idt->next;
	do {
		if (tmp_idt->eip == idt->eip) {
			return tmp_idt;
		}

		if (loop == NULL) {
			if ((tmp_idt->eip < idt->next->eip) || (tmp_idt->eip > idt->eip)) {
				*end_execution = true;
				return tmp_idt->previous;
			}
		} else {
			if ((tmp_idt->eip < loop->lowest_node_idt->eip) || (tmp_idt->eip
					> loop->greatest_node_idt->eip)) {
				*end_execution = true;
				return tmp_idt->previous;
			}
		}

		tmp_idt = tmp_idt->next;
	} while (tmp_idt != NULL);
	return NULL;
}

/**
 * Run back to the idt and return the idt
 * @return the Idt
 * */
Idt* LoopDetection::get_start_idt(Idt* idt, uint32 start_eip) {
	if (idt == NULL) {
		return NULL;
	}
	Idt* tmp_idt = idt->previous;
	do {
		if (tmp_idt->eip == start_eip) {
			return tmp_idt;
		}
		tmp_idt = tmp_idt->previous;
	} while (tmp_idt != NULL);
	return NULL;
}

/**
 * Prints the loop information
 * */
void LoopDetection::write_information() {
	try {
		if ((loops == NULL) || (loops->size() == 0)) {
			return;
		}
		for (map<uint32, Loop>::iterator loopIterator = loops->begin(); loopIterator
				!= loops->end(); ++loopIterator) {
			uint32 execution = loopIterator->second.executions.size();

			msg(
					"Loop detected (%08x - %08x) with %i executions and the following iterations: (",
					loopIterator->second.lowest_node_idt->eip,
					loopIterator->second.greatest_node_idt->eip, execution);

			for (list<LoopExecution>::iterator executionIterator =
					loopIterator->second.executions.begin(); executionIterator
					!= loopIterator->second.executions.end(); ++executionIterator) {
				if (executionIterator->completed) {
					if (executionIterator
							!= loopIterator->second.executions.begin()) {
						msg(";");
					}
					msg("%i", executionIterator->iterations.size());
				}
			}
			msg(")\n");
		}
	} catch (...) {
		msg(
				"Class:LoopDetection->Method:write_information. Exception: unknown\n");
	}
}

/**
 * Gets loops information about an eip
 * @param idt actual idt
 * @return reference to the loop object.
 * */
Loop* LoopDetection::get_information(Idt* idt) {
	if (idt == NULL) {
		return NULL;
	}
	try {
		Loop* loop_ptr = NULL;
		for (map<uint32, Loop>::iterator loopIterator = loops->begin(); loopIterator
				!= loops->end(); ++loopIterator) {

			// find loop containing the eip
			if ((idt->eip >= loopIterator->second.lowest_node_idt->eip)
					&& (idt->eip <= loopIterator->second.greatest_node_idt->eip)) {

				// find idt in loop
				for (list<LoopExecution>::iterator executionItarator =
						loopIterator->second.executions.begin(); executionItarator
						!= loopIterator->second.executions.end(); ++executionItarator) {
					for (list<LoopIteration>::iterator iterationItarator =
							executionItarator->iterations.begin(); iterationItarator
							!= executionItarator->iterations.end(); ++iterationItarator) {
						Idt* tmp_idt = iterationItarator->start_idt;
						do {
							if (tmp_idt == idt) {
								if (loop_ptr == NULL) {
									loop_ptr = &loopIterator->second;
								} else {
									if ((loop_ptr->lowest_node_idt->eip
											< loopIterator->second.lowest_node_idt->eip)
											&& (loop_ptr->greatest_node_idt->eip
													> loopIterator->second.lowest_node_idt->eip)) {
										// innermost, overwrite reference
										loop_ptr = &loopIterator->second;
									}
								}
								break;
							}
							tmp_idt = tmp_idt->next;
						} while (tmp_idt != iterationItarator->end_idt->next);
					} // end iteration for
				} // end execution for
			}
		} // end loop for

		if (loop_ptr != NULL) {
			// populate object with additional data
			uint32 iterations_min = 0xffffff, iterations_max = 0, iterations =
					0;
			for (list<LoopExecution>::iterator executionIterator =
					loop_ptr->executions.begin(); executionIterator
					!= loop_ptr->executions.end(); ++executionIterator) {
				if (iterations_max < executionIterator->iterations.size()) {
					iterations_max = executionIterator->iterations.size();
				}
				if (iterations_min > executionIterator->iterations.size()) {
					iterations_min = executionIterator->iterations.size();
				}
				iterations += executionIterator->iterations.size();
			}
			loop_ptr->iterations_min = iterations_min;
			loop_ptr->iterations_max = iterations_max;
			loop_ptr->iterations_average = iterations
					/ loop_ptr->executions.size();
		}
		return loop_ptr;
	} catch (exception& e) {
		msg("Class:LoopDetection->Method:get_information. Exception: %s\n",
				e.what());
	} catch (...) {
		msg("Class:LoopDetection->Method:get_information. Exception: unknown\n");
	}
	return NULL;
}

/**
 * Calculate the execution and the iteration
 * @param idt actual idt
 * @param loop reference to the loop object
 * @param execution reference to a variable execution
 * @param iteration reference to a variable iteration
 * @return true if no error
 * */
bool LoopDetection::calculate_cycles(Idt* idt, Loop* loop, uint32 *execution,
		uint32 *iteration) {
	if (loop == NULL) {
		return false;
	}

	uint32 execution_ctr = 0;
	for (list<LoopExecution>::iterator executionIterator =
			loop->executions.begin(); executionIterator
			!= loop->executions.end(); ++executionIterator) {
		execution_ctr++;

		uint32 iteration_ctr = 0;
		for (list<LoopIteration>::iterator iterationIterator =
				executionIterator->iterations.begin(); iterationIterator
				!= executionIterator->iterations.end(); ++iterationIterator) {
			iteration_ctr++;

			Idt* tmp_idt = iterationIterator->start_idt;
			do {
				if (tmp_idt == idt) {
					*execution = execution_ctr;
					*iteration = iteration_ctr;
					return true;
				}
				if (tmp_idt == iterationIterator->end_idt) {
					break;
				}
				tmp_idt = tmp_idt->next;
			} while (tmp_idt != NULL);
		}
	}
	return false;
}

/**
 * Gets the offset from iteration
 * @param execution actual execution
 * @param iteration actuel iteration
 * @param loop reference to the loop object
 * */
uint32 LoopDetection::get_offset_from_iteration(uint32 execution,
		uint32 iteration, Loop* loop) {
	if (loop == NULL) {
		return 0;
	}

	uint32 cumulated_iterations = 0, execution_ctr = 0;

	for (list<LoopExecution>::iterator executionIterator =
			loop->executions.begin(); executionIterator
			!= loop->executions.end(); ++executionIterator) {
		execution_ctr++;
		if (execution == execution_ctr) {
			return (cumulated_iterations + iteration);
		}
		cumulated_iterations += executionIterator->iterations.size();
	}
	return 0;
}

/**
 * Gets the iterations in the execution
 * @return iterations in the execution
 * */
uint32 LoopDetection::get_iterations(uint32 execution, Loop* loop) {
	list<LoopExecution>::iterator executionIterator = loop->executions.begin();
	advance(executionIterator, execution - 1); // move iterator i to index
	return executionIterator->iterations.size();
}

/**
 * Is instruction at eip a jump?
 * @param eip eip to the instruction
 * @return true if at eip is a jump
 * */
bool LoopDetection::is_jump(uint32 eip) {
	if ((is_call(eip)) || (is_return(eip))) {
		return false;
	}
	uint32 address = get_target_of_instruction(eip);
	if (address == 0) {
		return false;
	} else {
		return true;
	}
}

/**
 * Is instruction at eip a call?
 * @param eip eip to the instruction
 * @return true if at eip is a call
 * */
bool LoopDetection::is_call(uint32 eip) {
	try {
		bool is_call = is_call_insn(eip);
		return is_call;
	} catch (...) {
		return false;
	}
}

/**
 * Is instruction at eip a return?
 * @param eip eip to the instruction
 * @return true if at eip is a return
 * */
bool LoopDetection::is_return(uint32 eip) {
	try {
		bool is_ret = is_ret_insn(eip);
		return is_ret;
	} catch (...) {
		return false;
	}
}

/**
 * Gets the target of a jump, call, or return
 * @param eip of the instruction
 * @return the target address of the instruction at eip
 * */
uint32 LoopDetection::get_target_of_instruction(uint32 eip) {
	decode_insn(eip);
	if ((cmd.itype >= NN_ja) && (cmd.itype <= NN_jmpshort)) {

		for (uint32 i = 0; i < UA_MAXOP; i++) {
			if ((cmd.Operands[i].type == o_near) || (cmd.Operands[i].type
					== o_far)) {
				if (cmd.Operands[i].addr != 0) {
					return cmd.Operands[i].addr;
				}
			} else {
				return 0;
			}
		}
	}
	return 0;
}
