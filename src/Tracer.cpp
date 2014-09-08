/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:	libmalflare
 */

//-----------------------------------------------------------------------------
// Includes
//-----------------------------------------------------------------------------
#include <windows.h>
#include "Tracer.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/param.h>
#endif

#include "main.h"

/**
 * Here are all error msgs defined
 */
#define ERR_FILE_DOES_NOT_EXIST 0
#define ERR_FILE_MAGIC 1
#define ERR_FILE_VERSION 2
#define ERR_FILE_INFO_MISS 3
#define ERR_FILE_CREATE_FOLDER 4

/**
 * \brief Containing all error msgs
 */
char *errors[] = {
		"This file doesn't exist.",
		"This is not a valid malflare tracefile.",
		"The tracefile version did not match.",
		"The info file is missing.",
		"Couldn't create folder."
};

/**
 * \brief Used to store last error
 */
char *last_error = "";

/**
 * \brief Returns the last error message
 */
const char * mft_get_last_error(){
	return last_error;
}

/**
 * \brief Opens a tracefile for further reading. If the create flag is set, an empty file will be created
 * \param dst Folderpath of the tracefile to open
 * \param create Create a new file if set to true, otherwise read only
 */
MFT_H * mft_open(const char *dst, int create){
	struct stat St;
	int rc;
	char *mode;

	if ( stat( dst, &St ) != 0){
		if (create){
			#ifdef WIN32
				rc = mkdir(dst);
			#else
				rc = mkdir(dst, 0755);
			#endif

			if (rc){
				last_error = errors[ERR_FILE_CREATE_FOLDER];
				return null;
			}

			mode = "wb";
		}else{
			last_error = errors[ERR_FILE_DOES_NOT_EXIST];
			return null;
		}
	}else{
		mode = "rb";
	}


	// Create MFT handle
	MFT_H *mft_h = (MFT_H *) malloc(sizeof(MFT_H));

	if (!mft_h){
		// no mem left
		return null;
	}


	// Change dir
	char current_path[QMAXPATH];
	getcwd(current_path, QMAXPATH);

	chdir(dst);

	// Open files in the given directory
	mft_h->info = fopen("info", mode);
	mft_h->idt = fopen("idt", mode);
	mft_h->ids = fopen("ids", mode);

	// Change dir back
	chdir(current_path);

	// Writing or verify info
	MFT_INFO info;
	if (*mode == 'w'){
		strncpy(info.id, MFT_ID, sizeof(info.id));
		info.version = MFT_VERSION;
		info.reg_len = MFT_REG32;
		fwrite(&info, sizeof(MFT_INFO), 1, mft_h->info);
	}else{
		if (!mft_h->info){
			last_error = errors[ERR_FILE_INFO_MISS];
			return null;
		}

		// check validity of file
		fread(&info, sizeof(MFT_INFO), 1, mft_h->info);
		if (strncmp(info.id, MFT_ID, sizeof(info.id))){
			// not a valid tracefile, <-- MFT magic bytes not found
			last_error = errors[ERR_FILE_MAGIC];
			return null;
		}else if (info.version != MFT_VERSION){
			// not the right version
			last_error = errors[ERR_FILE_VERSION];
			return null;
		}
	}

    return mft_h;
}

/**
 * \brief Closes the mft tracefile, merging files together
 * \param mft_h Handle given by mft_open
 */
void mft_close(MFT_H *mft_h){
	if (!mft_h) return;

	/* Closing files */
	fclose(mft_h->info);
	fclose(mft_h->idt);
	fclose(mft_h->ids);

	/* Freeing up structures used before */
	free(mft_h);
}

/**
 * \brief Switch for the first data written per eip
 */
char data_written = false;

/**
 * \brief Switch for initial state
 */
char initial_state = true;

/**
 * \brief Add an eip to the tracefile
 * \param mft_h Handle given by mft_open
 * \param eip EIP-value to save into tracefile
 */
void mft_add_eip(MFT_H *mft_h, uint32 eip){
	MFT_IDT idt_e;
	idt_e.eip = eip;
	idt_e.idso = NO_IDS;
	fwrite((void *)&idt_e, sizeof(MFT_IDT), 1, mft_h->idt);

	// End IDS data with END if data were written before
	if (data_written){
		mft_add_data(mft_h, END);
	}

	// (re)set flags
	data_written = false; // set
	initial_state = false; // reset
}

/**
 * \brief Add data to an eip
 * \param mft_h Handle given by mft_open
 * \param type Type to add (EAX, EBX, ..., MEM), specifies next parameters. For registers only a value parameter need to be added. Memory changes need type MEM, value, length offset
 * \param ... void *value, uint32 length, uint32 offset
 */
void mft_add_data(MFT_H *mft_h, unsigned char type, .../* void *value, uint32 length, uint32 offset */ ){
	// Init variable args
	va_list list;
	va_start(list, type);

	// If this is the first data, write pointer into IDT (don't do that if we write initial stuff)
	if (!data_written && !initial_state){
		// Get current position of IDS
		unsigned int offset = ftell(mft_h->ids);

		// write position [EIP][PIDS] <-- here
		fseek(mft_h->idt, -4, SEEK_CUR);
		fwrite(&offset, sizeof(unsigned int), 1, mft_h->idt);
	}

	// set data_written, next add_eip will write IDS END
	data_written = true;

	// write type
	fwrite(&type, sizeof(unsigned char), 1, mft_h->ids);

	if (type != END && type != BASIC_BLOCK){ // FIXME: Dont define types explicit, make a marker for non value fields

		void *value = va_arg(list, void*);

		if (type < REG){
			// Write regs
			fwrite(value, sizeof(unsigned int), 1 , mft_h->ids);
		}else if (type == STR){
			// Write strings
			uint32 length = strlen((const char*) value);
			fwrite(&length, sizeof(length), 1, mft_h->ids);
			fputs((const char*) value, mft_h->ids);
		}else if (type == MEM){
			// Write memory
			uint32 length = va_arg(list, uint32);
			uint32 offset = va_arg(list, uint32);
			fwrite(&length, sizeof(length), 1, mft_h->ids);
			fwrite(&offset, sizeof(offset), 1, mft_h->ids);
			fwrite(value, length, 1, mft_h->ids);
		}
	}

	// clean up list
	va_end(list);
}

/**
 * \brief Get idt offset
 * \param mft_h Handle given by mft_open
 * \return IDT-Offset
 */
uint32 mft_get_offset(MFT_H *mft_h){
	return ftell(mft_h->idt)-sizeof(MFT_IDT);
}

/**
 * \brief Set idt offset
 * \param mft_h Handle given by mft_open
 * \param offset IDT-Offset to set
 */
int mft_set_offset(MFT_H *mft_h, uint32 offset){
	return fseek(mft_h->idt, offset, SEEK_SET);
}

/**
 * \brief Get length of an ids
 * \param mft_h Handle given by mft_open
 */
static uint32 mft_ids_length(MFT_H *mft_h){
	uint32 length = 0;
	uint32 ids_pos = ftell(mft_h->ids);

	uint8 type = 0;
	while(true){
		// Read type, break on end of file or type = END
		if (!fread(&type, sizeof(type), 1, mft_h->ids) || type == END)
			break;

		// Increment length
		length++;

		// TYPE VALUE
		if(type < REG){
			// skip next 4 bytes, break on error
			if (fseek(mft_h->ids, 4, SEEK_CUR))
				break;

		// TYPE LENGTH VALUE
		} else if (type == STR || type == MEM){ // FIXME: make marker for tlv and tlpv
			uint32 length;
			fread(&length, sizeof(length), 1, mft_h->ids);

			// Skip position
			if (type == MEM) // FIXME: make tlpv marker
				fseek(mft_h->ids, sizeof(uint32), SEEK_CUR);

			// Skip value with [length] size
			if (fseek(mft_h->ids, length, SEEK_CUR))
				break;
		}
	}

	fseek(mft_h->ids, ids_pos, SEEK_SET);
	return length;
}

/**
 * \brief Load data from ids
 * \param mft_h Handle given by mft_open
 * \param idt_e if not initial, load data from this idt
 * \param initial Load initial data instead of data from an idt
 * \return Complete cpu state with initial data (if initial is set) or changed data of an idt (if initial is not set but idt_e is set)
 */
static CPU_STATE *mft_get_data(MFT_H *mft_h, MFT_IDT *idt_e, char initial){
	CPU_STATE *cpu_state;

	// Seek to the right position
	if (!initial){
		fseek(mft_h->ids, idt_e->idso, SEEK_SET);
	}else{
		fseek(mft_h->ids, 0, SEEK_SET);

	}

	// get ids length
	uint32 ids_length = mft_ids_length(mft_h);

	cpu_state = (CPU_STATE *) malloc(sizeof(CPU_STATE) + sizeof(DATA) * ids_length);

	if (!cpu_state) return null;

	cpu_state->data_length = ids_length;

	uint32 i;
	DATA *data;

	for(i = 0; i < cpu_state->data_length; i++) {
		data = &cpu_state->data[i];

		if (!fread(&data->type, sizeof(data->type), 1, mft_h->ids)){
			break;
		}

		if (data->type < REG){
			fread(&data->value, 4, 1, mft_h->ids);

		}else if (data->type == STR){
			fread(&data->length, sizeof(data->length), 1, mft_h->ids);

			data->value = malloc(data->length + 1);

			if (!data->value) return null;

			fread(data->value, data->length, 1, mft_h->ids);
			((char *)data->value)[data->length] = 0;
		}else if (data->type == MEM){
			fread(&data->length, sizeof(data->length), 1, mft_h->ids);
			fread(&data->offset, sizeof(data->offset), 1, mft_h->ids);

			data->value = malloc(data->length);

			if (!data->value) return null;

			fread(data->value, data->length, 1, mft_h->ids);
		}
	}
	return cpu_state;
}


/**
 * \brief Get the initial state.
 * \param mft_h Handle given by mft_open
 * \return Cpu state structur containing all initial data (Registers, mem). cpu_state->eip is always 0.  (needs to be freed)
 */
CPU_STATE *mft_get_initial_state(MFT_H  *mft_h){
	CPU_STATE *cpu_state;
	MFT_IDT idt_e;

	// save idt pos & seek to 0
	uint32 idt_pos = ftell(mft_h->idt);
	fseek(mft_h->idt, 0, SEEK_SET);

	// find the first idt entry with data
	while(true){
		// return null on read errors
		if (!fread(&idt_e, sizeof(MFT_IDT), 1, mft_h->idt)) return null;

		// first idt with data found -> break
		if (idt_e.idso != NO_IDS) break;
	}

	// be sure that its not 0 (0 = no initial data)
	if (idt_e.idso == 0) return null;

	// save ids pos
	uint32 ids_pos = ftell(mft_h->ids);

	cpu_state = mft_get_data(mft_h, &idt_e, true);

	// restore ids pos
	fseek(mft_h->ids, ids_pos, SEEK_SET);


	// restore idt pos
	fseek(mft_h->idt, idt_pos, SEEK_SET);

	return cpu_state;
}

/**
 * \brief Get next cpu state iterates over the whole tracefile.
 * \param mft_h Handle given by mft_open
 * \param load_data Defines if linked data need to be load from tracefile. If true, the caller needs to free up things for himself.
 * \return Next cpu state structure containing all changed data (needs to be freed)
 */
CPU_STATE *mft_next_cpu_state(MFT_H *mft_h, int load_data){
	MFT_IDT idt_e;

	// Is there more to read?!
	if (!fread(&idt_e, sizeof(MFT_IDT), 1, mft_h->idt))
		return null;

	CPU_STATE *cpu_state;

	// Do we need to load the ids?!
	if (idt_e.idso != NO_IDS && load_data){
		cpu_state = mft_get_data(mft_h, &idt_e, false);

	}else{
		// NO DATA
		cpu_state = (CPU_STATE *) malloc(sizeof(CPU_STATE));

		if (!cpu_state) return null;

		//cpu_state->data = null;
		cpu_state->data_length = 0;
	}
	cpu_state->eip = idt_e.eip;

	return cpu_state;

}

/**
 * \brief Returns the cpu_state of an eip
 * \param mft_h Handle given by mft_open
 * \param eip EIP to search for
 * \param load_data If data should be loaded too
 * \return Changed cpu state of given EIP  (needs to be freed)
 */
CPU_STATE * mft_get_cpu_state(MFT_H *mft_h, uint32 eip, int load_data){
	MFT_IDT idt_e;
	CPU_STATE *cpu_state = null;

	// store offset for restoring later
	// then, seek to 0
	uint32 pos = ftell(mft_h->idt);
	fseek(mft_h->idt, 0, SEEK_SET);

	while (null != fread(&idt_e, sizeof(MFT_IDT), 1, mft_h->idt)){
		if (idt_e.eip == eip){
			// We found the correct
			// seek backwards so we can use mft_next_cpu_state
			fseek(mft_h->idt, -sizeof(MFT_IDT), SEEK_CUR);

			cpu_state = mft_next_cpu_state(mft_h, load_data);
		}
	}

	// restore offset
	fseek(mft_h->idt, pos, SEEK_SET);
	return cpu_state;
}


/**
 * Constructor
 * */
Tracer::Tracer() {
	mft_h = null;
	bTree = new BinaryTree();
	loopDetection = new LoopDetection();
	act_idt = NULL;
}

/**
 * Deconstructor
 * */
Tracer::~Tracer() {
	if (mft_h != null) {
		close();
	}
}

//-----------------------------------------------------------------------------
// Methodes
//-----------------------------------------------------------------------------

/**
 * Read the full tracefile
 * @param tracefilePath the tracefile path
 * @return NULL or a error string
 * */
char* Tracer::read_tracefile(char* tracefilePath) {
	msg("start reading tracefile %s\n", tracefilePath);

	// save to instance
	tracefile = tracefilePath;

	char* error = open();
	if (error != NULL) {
		return error;
	}

	CPU_STATE *cpu_state;
	while (null != (cpu_state = mft_next_cpu_state(mft_h, false))) {
		bTree->add(cpu_state->eip, mft_get_offset(mft_h));
		free(cpu_state); // TODO free Data?
	}

	close();

	loopDetection->read_data(bTree);

	msg("end reading tracefile\n");
	return NULL;
}

/**
 *
 * */
void Tracer::write_loop_information() {
	loopDetection->write_information();
}

/**
 * Get loop information about a eip.
 * @return Reference to loop inforamtion object.
 * */
Loop* Tracer::get_loop_information() {
	if (loopDetection != NULL) {
		return loopDetection->get_information(act_idt);
	} else {
		return NULL;
	}
}

/**
 *
 * */
bool Tracer::calculate_cycles(Loop* loop, uint32 *execution, uint32 *iteration) {
	return loopDetection->calculate_cycles(act_idt, loop, execution, iteration);
}

/**
 *
 * */
//int32 Tracer::calculate_offset_to_execution(uint32 execution, Loop* loop) {
//	return loopDetection->calculate_offset_to_execution(act_idt,
//			get_eip_repetition(act_idt), execution, loop);
//}

/**
 *
 * */
uint32 Tracer::get_iterations(uint32 execution, Loop* loop) {
	return loopDetection->get_iterations(execution, loop);
}

/**
 *
 * */
uint32 Tracer::get_offset_from_iteration(uint32 execution, uint32 iteration,
		Loop* loop) {
	return loopDetection->get_offset_from_iteration(execution, iteration, loop);
}

/**
 * Get the initial data
 * @param callback callbackfunction which calls multiple for the initialized data.
 * */
void Tracer::get_initialized_data(
		void(*callback)(CPU_STATE *cpu_state, uint32 repetition)) {
	if (ENABLE_TRACER)
		msg("Tracer::get_initialized_data\n");

	open();

	CPU_STATE *cpu_state = mft_get_initial_state(mft_h);
	if (callback != NULL) {
		if (cpu_state != null) {
			callback(cpu_state, 0);
			free(cpu_state);
		}
	}

	for (map<uint32, Node>::iterator iterator = bTree->bTree->begin(); iterator
			!= bTree->bTree->end(); ++iterator) {
		if (mft_set_offset(mft_h, iterator->second.idts.front().offset)) {
			// error by set offset
			msg("Error by set mft offset\n");
			cpu_state = null;
		} else {
			cpu_state = mft_next_cpu_state(mft_h, true);
			if (callback != NULL) {
				if (cpu_state != null) {
					callback(cpu_state,
							get_eip_repetition(cpu_state->eip, true));
					free(cpu_state);
				}
			}
		}
	}
}

/**
 * Read the previous element from tracefile and write data to the segment
 * @param act_cpu_state address to a pointer which contains the actual cpu state.
 * @param previous_eip address to a variable which contains the previous eip.
 * @return reference to the previous cpu state
 * */
CPU_STATE* Tracer::read_previous_element(CPU_STATE **act_cpu_state,
		uint32 *previous_eip) {
	// read actual cpu state
	if (act_idt == NULL) {
		*act_cpu_state = NULL;
		*previous_eip = 0;
		return NULL;
	} else {
		*act_cpu_state = get_cpu_state();
	}
	// read previous idt cpu state
	CPU_STATE *previous_idt_cpu_state =
			read_previous_idt((*act_cpu_state)->eip);

	// read previous eip
	if (act_idt == bTree->root_idt) {
		*previous_eip = 0;
	} else {
		act_idt = act_idt->previous;
		*previous_eip = act_idt->eip;
	}
	return previous_idt_cpu_state;
}

/*
 * Read previous idt from actual node.
 * @param eip from actual node
 * @return reference to the next cpu state
 * */
CPU_STATE* Tracer::read_previous_idt(uint32 eip) {
	Idt* idt = bTree->get_previous_idt(eip, act_idt->offset);
	if (idt != NULL) {
		mft_set_offset(mft_h, idt->offset); // read previous idt data
		return mft_next_cpu_state(mft_h, true);
	}
	return NULL;
}

/**
 * Read the next element from tracefile and write data to the segment.
 * @return reference to the next cpu state
 * */
CPU_STATE* Tracer::read_next_element() {
	if (act_idt == NULL) {
		act_idt = bTree->root_idt;
	} else {
		if (act_idt == bTree->end_idt)
			return NULL;
		act_idt = act_idt->next;
	}
	if (act_idt == NULL) {
		return NULL;
	}
	return get_cpu_state();
}

/**
 * Gets the cpu state.
 * @return reference to the actual cpu state
 * */
CPU_STATE* Tracer::get_cpu_state() {
	if ((mft_h != null) && (act_idt != NULL)) {
		mft_set_offset(mft_h, act_idt->offset);
		CPU_STATE *cpu_state = mft_next_cpu_state(mft_h, true);
		if (cpu_state == null) {
			return NULL;
		} else {
			return cpu_state;
		}

		//return mft_next_cpu_state(mft_h);
	} else {
		return NULL;
	}
}

/**
 * Gets the eip repetition.
 * @return the eip repetition
 * */
uint32 Tracer::get_eip_repetition(Idt* idt) {
	return bTree->get_repetition(idt);
}

/**
 * Gets the eip repetition.
 * @param full if true, the full repetition is returned, otherwise, the actual repetition is returned
 * @return the eip repetition
 * */
uint32 Tracer::get_eip_repetition(uint32 eip, bool full) {
	if (full) {
		return bTree->get_repetition(eip, 0);
	} else {
		return bTree->get_repetition(eip, act_idt->offset);
	}
}

/**
 * Gets the actual eip.
 * @return the actual eip
 * */
uint32 Tracer::get_actual_eip() {
	return act_idt->eip;
}

Idt* Tracer::get_previous_idt(Idt* idt) {
	return bTree->get_previous_idt(idt);
}

/**
 * Get idt from act+offset iteration.
 * @param position 0= this position or start, 1=start, 2=end
 * */
Idt* Tracer::get_iteration_idt(int32 offset, char position) {
	if (act_idt == NULL) {
		return NULL;
	}
	Loop *loop = loopDetection->get_information(act_idt);
	if (loop != NULL) {
		uint32 act_execution = 0, act_iteration = 0;
		list<LoopExecution>::iterator executionIterator =
				loop->executions.begin();

		if (calculate_cycles(loop, &act_execution, &act_iteration)) {
			advance(executionIterator, act_execution - 1); // move iterator

			if (executionIterator->iterations.size() < (act_iteration + offset)) {
				msg("Error: offset %i not in range (actual iteration %i)\n",
						offset, act_iteration);
				return NULL;
			}
			list<LoopIteration>::iterator iterationIterator =
					executionIterator->iterations.begin();
			advance(iterationIterator, act_iteration - 1 + offset); // move iterator

			if (position == 2) { // end
				return iterationIterator->end_idt;
			} else if (position == 1) { //start
				return iterationIterator->start_idt;
			} else { // position if exist
				//search for eip
				Idt* tmp_idt = iterationIterator->start_idt;
				do {
					if (tmp_idt->eip == act_idt->eip) {
						return tmp_idt;
					}
					tmp_idt = tmp_idt->next;
				} while ((tmp_idt != NULL) && (tmp_idt
						!= iterationIterator->end_idt));
				return iterationIterator->start_idt;
			}
		}
	}
	return NULL;
}

/**
 *
 * */
Idt* Tracer::get_execution_idt(int32 offset, Loop* loop) {
	if ((act_idt == NULL) || (loop == NULL)) {
		return NULL;
	}
	uint32 act_execution = 0, act_iteration = 0;
	list<LoopExecution>::iterator executionIterator = loop->executions.begin();
	if (calculate_cycles(loop, &act_execution, &act_iteration)) {
		if (loop->executions.size() < (act_execution + offset)) {
			msg("Error: offset not in range\n");
			return NULL;
		}
		advance(executionIterator, act_execution - 1 + offset); // move iterator
		return executionIterator->iterations.begin()->start_idt;
	}
	return NULL;
}

/**
 * Open tracefile.
 * @return NULL or a error string
 * */
char* Tracer::open() {
	if (mft_h != null)
		close();
	if (mft_h == null) {
		mft_h = mft_open(tracefile, false);
		if (mft_h == null) {
			return (char*) mft_get_last_error();
		}
	}
	return NULL;
}

/**
 * Close tracefile.
 * */
void Tracer::close() {
	if (mft_h != null) {
		mft_close(mft_h);
		mft_h = null;
	}
}

//-----------------------------------------------------------------------------
// end of code
//-----------------------------------------------------------------------------
