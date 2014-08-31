/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:
 */

#include "SyscallInterpretation.h"

using namespace std;

/**
 * SyscallInterpretation constructor. Here we need to fill the syscalls list with systemcall information
 */
SyscallInterpretation::SyscallInterpretation(){
	SyscallInfo s_malloc("malloc"), s_free("free"), s_fopen("fopen"), s_fwrite("fwrite"), s_fclose("fclose"), s_printf("printf") ;

	/**
	 * Printf
	 * NOTE: FMT_STRING is not complete implementetd
	 */
	s_printf.arg_types.push_back(ARG_TYPE_FMT_STRING);
	// s_printf.arg_types.push_back(ARG_TYPE_MORE);
	s_printf.arg_info.push_back("fmt string");
	// s_printf.arg_info.push_back("...");
	syscalls.push_back(s_printf);

	/**
	 * Malloc
	 */
	s_malloc.arg_types.push_back(ARG_TYPE_INT);
	s_malloc.arg_info.push_back("size");
	syscalls.push_back(s_malloc);


	/**
	 * Free
	 */
	s_free.arg_types.push_back(ARG_TYPE_POINTER);
	s_free.arg_info.push_back("ptr");
	syscalls.push_back(s_free);

	/**
	 * Fopen
	 */
	s_fopen.arg_types.push_back(ARG_TYPE_STRING);
	s_fopen.arg_types.push_back(ARG_TYPE_STRING);
	s_fopen.arg_info.push_back("filename");
	s_fopen.arg_info.push_back("mode");
	syscalls.push_back(s_fopen);

	/**
	 * Fwrite
	 */
	s_fwrite.arg_types.push_back(ARG_TYPE_POINTER);
	s_fwrite.arg_types.push_back(ARG_TYPE_INT);
	s_fwrite.arg_types.push_back(ARG_TYPE_INT);
	s_fwrite.arg_types.push_back(ARG_TYPE_POINTER);
	s_fwrite.arg_info.push_back("ptr");
	s_fwrite.arg_info.push_back("size");
	s_fwrite.arg_info.push_back("count");
	s_fwrite.arg_info.push_back("stream");
	syscalls.push_back(s_fwrite);

	/**
	 * Fclose
	 */
	s_fclose.arg_types.push_back(ARG_TYPE_POINTER);
	s_fclose.arg_info.push_back("stream");
	syscalls.push_back(s_fclose);
}

/**
 * Gets executed from and after modify_memory. Result of the interpretation will be written as an IDA comment appended to the existing.
 * @param cpuState CPU_STATE to analyze
 */
void SyscallInterpretation::append_interpretation(CPU_STATE *cpuState){
	if (cpuState == NULL)
		return;

	// get a handy shortcut for eip
	ea_t eip = cpuState->eip;

	// only annotate calls
	if (!is_call_insn(eip)){
		return;
	}

	// used for constructing the final string
	stringstream oss;

	// get esp. esp will be changed by an call instruction to remove arguments (usually)
	uint32 esp = 0;
	for (unsigned int i = 0; i < cpuState->data_length; i++){
		DATA *d = &cpuState->data[i];
		if (d->type == ESP){
			esp = (uint32) d->value;
		}
	}

	// no esp change found.
	if (!esp){
		msg("Syscall: ESP not found\n");
		return;
	}

	// incremet by 4 decrements stack by 4
	esp += 4;

	// iterators for next loops
	static list<SyscallInfo>::iterator syscall;
	static list<string>::iterator arg_info;
	static list<enum ARG_TYPES>::iterator arg_type;

	// disasm instruction
	char buf[200];
	decode_insn(eip);

	for (int i = 0; i < UA_MAXOP; i++)	{
		op_t op = cmd.Operands[i];

		if (op.type != o_near && op.type != o_far)
			continue;

		// Get output of command
		buf[0] = 0;
		ua_outop2(eip, buf, 200, i, 0);


		// iterate over all syscalls for searching a match
		for (syscall = syscalls.begin(); syscall != syscalls.end(); syscall++) {
			if (strstr(buf, syscall->name.c_str()) != NULL){

				// Write function header, eg. free(
				oss << syscall->name << "(";

				arg_info = syscall->arg_info.begin();

				// Iterate over arguments
				for (arg_type = syscall->arg_types.begin(); arg_type != syscall->arg_types.end(); arg_type++){
					if (arg_type != syscall->arg_types.begin()){
						oss << ", ";
					}

					// Write arg header, eg. ptr=
					if (arg_info != syscall->arg_info.end()){
						oss << *(arg_info++) << "=";
					}

					// Output strings
					if (*arg_type == ARG_TYPE_FMT_STRING || *arg_type == ARG_TYPE_STRING){
						uint32 ptr = get_32bit(esp);
						string buffer;
						char c;

						oss << "\"";

						int j = 0;
						// Output string to stream. convert newlines and tabs to \n or \t
						while ((c = get_byte(ptr++))){
							switch(c){
							case '\n':
								oss << "\\n";
								break;
							case '\t':
								oss << "\\t";
								break;
							default:
								oss << c;
							}
							
							// Limit string output to 1024 chars
							if (j > 1024){
								oss << "...";
								break;
							}
							j++;
						}

						oss << "\"";

					// Output integers and pointers (void * pointers)
					}else if (*arg_type == ARG_TYPE_INT || *arg_type == ARG_TYPE_POINTER){
							uint32 value = get_32bit(esp);
							oss << "0x" << hex << value;
					}

					// each argument is 4 bytes long
					esp += 4;
				}

				// Finish function header
				oss << ")";
			}
		}
	}

	// Append comment to existing comment
	append_cmt(eip, oss.str().c_str(), false);
}
