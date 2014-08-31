/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			23.03.2011
 * Dependencies:	IDA Pro 6 + SDK
 */

#ifndef BINARYTREE_H_
#define BINARYTREE_H_

#include "ida.hpp"
#include "kernwin.hpp"
#include <string.h>
#include <iostream>
#include <map>
#include <list>
#include <utility>
#include "GlobalIncludes.h"

using namespace std;

/*
 * IDT class.
 * */
class Idt {
public:
	uint32 offset;
	uint32 eip;
	Idt *previous; // timeline
	Idt *next; // timeline
	// Constructor
	Idt(uint32 offset, uint32 eip, Idt *pPreviousIdt);
};

/*
 * Node class.
 * */
class Node {
public:
	list<Idt> idts;
	Node(uint32 offset, uint32 eip, Idt *pPreviousIdt);
};

/*
 *
 * */
class BinaryTree {
public:
	// Constructor.
	BinaryTree();

	// add node to bTree
	void add(uint32 eip, uint32 offset);
	Idt* get_previous_idt(uint32 eip, uint32 offset);
	Idt* get_previous_idt(Idt* idt);
	uint32 get_repetition(uint32 eip, uint32 offset);
	uint32 get_repetition(Idt* idt);

	Idt* root_idt;
	Idt* end_idt;
	Idt* previous_idt;

	void set_parameter(Idt *idt);
	map<uint32, Node> *bTree;
};

#endif /* BINARYTREE_H_ */
