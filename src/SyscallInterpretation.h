/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:
 */

#ifndef SYSCALLINTERPRETATION_H_
#define SYSCALLINTERPRETATION_H_

#include <list>
#include <string>
#include <sstream>
//#include <iomanip>

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>

#include "libmalflare.h"

using namespace std;

enum ARG_TYPES {
	ARG_TYPE_FMT_STRING,
	ARG_TYPE_STRING,
	ARG_TYPE_INT,
	ARG_TYPE_MORE,
	ARG_TYPE_POINTER
};

class SyscallInfo {
public:
	SyscallInfo(const string s){
		name = s;
	}
	string name;
	list<enum ARG_TYPES> arg_types;
	list<string> arg_info;
};

class SyscallInterpretation {
public:
	SyscallInterpretation();
	void append_interpretation(CPU_STATE *);

private:
	list<SyscallInfo> syscalls;
};


#endif /* SYSCALLINTERPRETATION_H_ */
