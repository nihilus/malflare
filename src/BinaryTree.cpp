/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			23.03.2011
 * Dependencies:	IDA Pro 6 + SDK
 */

#include "BinaryTree.h"

using namespace std;

/**
 * Idt constructor.
 * @param o offset in the tracefile
 * @param e eip
 * @param i reference to the previous Idt
 * */
Idt::Idt(uint32 o, uint32 e, Idt *i) {
	offset = o;
	eip = e;
	previous = i;
	next = NULL;
}

/**
 * Node constructor.
 * @param offset in the tracefile
 * @param eip
 * @param previousIdt reference to the previous Idt
 * */
Node::Node(uint32 offset, uint32 eip, Idt *previousIdt) {
	idts.push_front(Idt(offset, eip, previousIdt));
}

/**
 * Binary tree constructor.
 * */
BinaryTree::BinaryTree() {
	bTree = new map<uint32, Node> ;
	root_idt = NULL;
	previous_idt = NULL;
}

/**
 * Adds a item to the tree.
 * @param eip
 * @param offset in the tracefile
 * */
void BinaryTree::add(uint32 eip, uint32 offset) {
	// search eip
	map<uint32, Node>::iterator bTreeIterator = bTree->find(eip);
	if (bTreeIterator != bTree->end()) {
		// insert offset
		bTreeIterator->second.idts.push_back(Idt(offset, eip, previous_idt));
		set_parameter(&bTreeIterator->second.idts.back());
	} else {
		// insert new node.
		bTree->insert(pair<uint32, Node> (eip, Node(offset, eip, previous_idt)));
		bTreeIterator = bTree->find(eip); //TODO andere methode?
		set_parameter(&bTreeIterator->second.idts.back());
	}
}

/**
 * Set the parameter for linking the linked list.
 * @param idt reference to the Idt
 * */
void BinaryTree::set_parameter(Idt *idt) {
	// save root idt
	if (root_idt == NULL) {
		root_idt = idt;
	}

	// write next to old idt
	if (previous_idt != NULL) {
		previous_idt->next = idt;
	}
	// save idt
	previous_idt = idt;

	// overwrite end idt
	end_idt = idt;
}

/**
 * Gets the eip repetition.
 * */
uint32 BinaryTree::get_repetition(Idt *idt) {
	return get_repetition(idt->eip, idt->offset);
}

/**
 * Gets the eip repetition.
 * @param eip
 * @param offset repetition until this offset. if 0, the full repetition is returned
 * @return the repetition of the eip (0xffffffff = 0)
 * */
uint32 BinaryTree::get_repetition(uint32 eip, uint32 offset) {
	map<uint32, Node>::iterator bTreeIterator = bTree->find(eip);
	if (bTreeIterator != bTree->end()) {
		if (offset == 0) {
			return bTreeIterator->second.idts.size();
		} else {
			uint32 repetition = 0;
			for (list<Idt>::iterator lIterator =
					bTreeIterator->second.idts.begin(); lIterator
					!= bTreeIterator->second.idts.end(); ++lIterator) {
				repetition++;
				if (lIterator != bTreeIterator->second.idts.end()) {
					if (lIterator->offset == offset) {
						return repetition;
					} else if (lIterator->offset > offset) {
						if (repetition > 1) {
							return (repetition - 1);
						} else {
							return 0xffffffff;
						}
					}
				} else {
					return bTreeIterator->second.idts.size();;
				}
			}
		}
		return 1;
	}
	return 0;
}

/**
 * Returns reference to the previous idt.
 * @return the previous idt
 * */
Idt* BinaryTree::get_previous_idt(Idt* idt) {
	return get_previous_idt(idt->eip, idt->offset);

}
/**
 * Returns reference to the previous idt from the eip
 * @param eip
 * @param offset
 * @return the previous idt
 * */
Idt* BinaryTree::get_previous_idt(uint32 eip, uint32 offset) {
	map<uint32, Node>::iterator bTreeIterator = bTree->find(eip);
	if (bTreeIterator != bTree->end()) {
		if (bTreeIterator->second.idts.size() < 2) {
			return 0;
		}
		list<Idt> idts = bTreeIterator->second.idts;
		Idt* last_idt = NULL;
		for (list<Idt>::iterator IdtIterator = idts.begin(); IdtIterator
				!= idts.end(); ++IdtIterator) {
			if (offset == IdtIterator->offset) {
				return last_idt;
			}
			last_idt = &(*IdtIterator);
		}
	}
	return 0;
}
