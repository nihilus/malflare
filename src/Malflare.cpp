/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:	IDA Pro 6 + SDK
 */

//-----------------------------------------------------------------------------
// Includes
//-----------------------------------------------------------------------------
#include "Malflare.h"

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------
#define PLUGINFILE        "malflare.plw"
#define GUI_X_START_POSITION   		  5
#define GUI_Y_START_POSITION   		  5
#define GUI_WIDTH_SPACE				  5
#define GUI_CONTROL_WIDTH           110
#define GUI_CONTROL_WIDTH_MEDIUM     50
#define GUI_CONTROL_WIDTH_SMALL      30
#define GUI_CONTROL_HEIGHT           25
#define GUI_CONTROL_LABEL_HEIGHT     20
#define GUI_BTN_STYLE                WS_CHILD | WS_VISIBLE | BS_TEXT | BS_LEFT | BS_PUSHBUTTON
#define GUI_BTN_STYLE_CENTER         WS_CHILD | WS_VISIBLE | BS_TEXT | BS_PUSHBUTTON
#define GUI_BTN_CHECKBOX             WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX

#define BUT_NUMBERS                   3
#define COLOR_BLUE             0xc7b482
#define COLOR_LIGHTBLUE        0xf0d9a1

#define BTN_BROWS                   100
#define BTN_READ                    101
#define BTN_SETINITDATA             102
#define BTN_DUMP_MEM				103

#define BTN_RUN_FORWARD    			200
#define BTN_RUN_BACKWARD            201
#define BTN_STEP_FORWARD            202
#define BTN_STEP_BACKWARD           203

#define BTN_START_EXEC              300
#define BTN_MINUS_EXEC              301
#define BTN_PLUS_EXEC               302
#define BTN_END_EXEC                303
#define BTN_GOTO_EXEC   			304

#define BTN_START_ITER              400
#define BTN_MINUS_ITER              401
#define BTN_PLUS_ITER               402
#define BTN_END_ITER                403
#define BTN_GOTO_ITER 				404

#define READSTATE_INIT                0
#define READSTATE_BREAK               1
#define READSTATE_STEP                2

//-----------------------------------------------------------------------------
// Variables
//-----------------------------------------------------------------------------
Tracer* Malflare::tracer;
SegmentManager *Malflare::segment_manager;
SyscallInterpretation *Malflare::syscall_interpretation;

TForm* Malflare::formA;
TForm* Malflare::formMalflareHex;
TForm* Malflare::formMalflare;
HINSTANCE Malflare::hInstance;
WNDPROC Malflare::oldIDAWindowWndProc;
qthread_t Malflare::thread_h;
uint32 Malflare::last_pressed_key;

char Malflare::szTraceFilePath[256];
ea_t Malflare::debug_mark;

HWND Malflare::hIDAWindow;
HWND Malflare::hLblTracefileUrl;
HWND Malflare::hBtnBrows;
HWND Malflare::hTboTracefileUrl;
HWND Malflare::hBtnRead;
HWND Malflare::hBtnSetInitData;
HWND Malflare::hCboDumpMem;
LRESULT Malflare::CboDumpMemState;

HWND Malflare::hBtnRunBackward;
HWND Malflare::hBtnStepBackward;
HWND Malflare::hLblDebugEip;
HWND Malflare::hBtnStepForward;
HWND Malflare::hBtnRunForward;

Loop* Malflare::loop;
HWND Malflare::hLblLoopDetection;
HWND Malflare::hLblExec;
HWND Malflare::hLblExecStartToEnd;
HWND Malflare::hBtnStartExec;
HWND Malflare::hBtnMinusExec;
HWND Malflare::hLblCyclesExec;
HWND Malflare::hBtnPlusExec;
HWND Malflare::hBtnEndExec;
HWND Malflare::hBtnGotoExec;
HWND Malflare::hLblActualCycleExec;
HWND Malflare::hLblSpacerExec;
HWND Malflare::hLblAllCyclesExec;

HWND Malflare::hLblCyclesIter;
HWND Malflare::hLblIterStartToEnd;
HWND Malflare::hBtnStartIter;
HWND Malflare::hBtnMinusIter;
HWND Malflare::hBtnPlusIter;
HWND Malflare::hBtnEndIter;
HWND Malflare::hBtnGotoIter;
HWND Malflare::hLblActualCycleIter;
HWND Malflare::hLblSpacerIter;
HWND Malflare::hLblAllCyclesIter;

HWND Malflare::hLblIterationsPerCycle;
HWND Malflare::hLblIterationsMin;
HWND Malflare::hLblIterationsMinVal;
HWND Malflare::hLblIterationsAverage;
HWND Malflare::hLblIterationsAverageVal;
HWND Malflare::hLblIterationsMax;
HWND Malflare::hLblIterationsMaxVal;

using namespace std;

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------
typedef struct ThreadData {
	char* pszTracefilepath;
} THREAD_DATA, *P_THREAD_DATA;

/**
 * Constructor
 * */
Malflare::Malflare() {
	tracer = new Tracer();
	segment_manager = SegmentManager::Instance();
	syscall_interpretation = new SyscallInterpretation();
	debug_mark = 0;
	thread_h = NULL;
	loop = NULL;
	last_pressed_key = 0;
}

//////////////////////////////////////////////////////////////////////
// Methodes
//////////////////////////////////////////////////////////////////////

/**
 * Plugin initialization.
 * */
int Malflare::ida_init(void) {
	// "metapc" represents x86 architecture
	if ((callui(ui_get_hwnd).vptr == NULL) || (strncmp(inf.procName, "metapc",
			6) != 0) || (inf.filetype != f_PE)) {
		error("Only PE binary type compiled for the x86 platform is supported.");
		return PLUGIN_SKIP;
	}
	return PLUGIN_OK;
}

/**
 * Cyclic part of the plugin.
 * */
void Malflare::ida_run(int arg) {
	msg("*------------------------------------------------------*\n");
	msg("*-----------------------Malflare-----------------------*\n");
	msg("*-------------(c) D. Fischer / D. Jordi----------------*\n");
	msg("*------------------------------------------------------*\n");

	create_ida_subwindows();
}

/**
 * Cleanup part of the Plugin.
 * */
void Malflare::ida_exit(void) {
	unhook_from_notification_point(HT_UI, ida_subwindow_callback);
}

/**
 * Creates the subwindows in the IDA Pro.
 * */
void Malflare::create_ida_subwindows() {
	hInstance = (HINSTANCE) GetModuleHandle(PLUGINFILE);

	// Get IDA Graph view handle
	formA = find_tform("IDA View-A");
	if (formA == NULL) {
		formA = open_disasm_window("A");
	}

	// Create Hex View-Malflare Window
	formMalflareHex = find_tform("Hex View-Malflare");
	if (formMalflareHex == NULL) {
		formMalflareHex = open_hexdump_window("Malflare");
	}

	// Create Malflare View
	formMalflare = find_tform(GUI_PLUGIN_CAPTION);
	if (formMalflare == NULL) {
		HWND hwnd = NULL;
		formMalflare = create_tform(GUI_PLUGIN_CAPTION, &hwnd);
		if (formMalflare != NULL) {
			hook_to_notification_point(HT_UI, ida_subwindow_callback,
					formMalflare);
			open_tform(formMalflare, PLUGIN_OPTIONS);
		}
	}

	set_dock_pos(GUI_PLUGIN_CAPTION, "IDA View-A", DP_RIGHT); //TODO funzt nicht wie gewollt??
	set_dock_pos("Hex View-Malflare", GUI_PLUGIN_CAPTION, DP_BOTTOM);
}

/**
 * Writes initial data to IDA Pro.
 * @param cpu_state actual cpu state
 * @param repetition the full eip-repetition, use to color the lines
 * */
void Malflare::write_initialized_data_callback(CPU_STATE *cpu_state,
		uint32 repetition) {
	if (cpu_state != NULL) {
		modify_comment(cpu_state, init);
		if (repetition == 0) {
			modify_memory(cpu_state, init, false);
		} else {
			color_line(cpu_state->eip, repetition, init);
		}
	}
}

/**
 * Threaded function to read the tracefile.
 * @param args contains the thread data
 * */
int Malflare::read_tracefile(void *args) {
	show_wait_box("Read Tracefile");

	P_THREAD_DATA pData;
	pData = (P_THREAD_DATA) args;

	char* error = tracer->read_tracefile(pData->pszTracefilepath);
	if (error != NULL) {
		vwarning(error, error);
	}

	hide_wait_box();
	return 0;
}

/**
 * Read full tracefile.
 * */
void Malflare::read_tracefile_threaded() {
	P_THREAD_DATA pThreadData;

	pThreadData = (P_THREAD_DATA) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			sizeof(THREAD_DATA));
	pThreadData->pszTracefilepath = szTraceFilePath;

	thread_h = qthread_create(read_tracefile, pThreadData);
}

/**
 * Write line comment.
 * @param cpuState contains the data
 */
void Malflare::modify_comment(CPU_STATE *cpuState, ModifyState state) {
	if (cpuState == NULL)
		return;
	if (cpuState->eip == 0) {
		return;
	}

	ostringstream oss;

	for (uint32 i = 0; i < cpuState->data_length; i++) {
		DATA *data = &cpuState->data[i];
		string type;
		switch (data->type) {
		case EAX:
			type = "eax";
			break;
		case EBX:
			type = "ebx";
			break;
		case ECX:
			type = "ecx";
			break;
		case EDX:
			type = "edx";
			break;
		case ESI:
			type = "esi";
			break;
		case EDI:
			type = "edi";
			break;
		case ESP:
			type = "esp";
			break;
		case EBP:
			type = "ebp";
			break;
		case EFLAGS:
			type = "efalgs";
			break;
		case MEM:
			type = "mem";
			break;
		}
		if (data->type < REG) {
			if (i > 0)
				oss << endl;

			uint32 reg = (uint32) data->value;
			oss << type << " -> 0x" << hex << reg;

		} else if (data->type == MEM) {
			oss << "mem -> ";

			/*
			 char *mm = (char *) data->value;

			 // Limit mem output to 10 chars
			 for (unsigned int k = 0; k < data->length && k < 10; k++) {
			 if (mm[k] >= ' ' && mm[k] <= '~')
			 oss << static_cast<char> (mm[k]);
			 }*/

			if (data->length == 4) {
				uint32 val = *((uint32 *) data->value);
				oss << "0x" << hex << val;
			} else {
				oss << data->length << " bytes";
			}
		}
	}

	set_cmt(cpuState->eip, oss.str().c_str(), false); // overwrite the old one

	if (state != init) {
		syscall_interpretation->append_interpretation(cpuState);
	}
}

/**
 * Modify memory.
 * @param cpuState contains the data
 * @param state write or restore the memory
 * */
void Malflare::modify_memory(CPU_STATE *cpuState, ModifyState state,
		bool print_log) {
	if (cpuState == NULL) {
		return;
	}

	for (uint32 i = 0; i < cpuState->data_length; i++) {
		DATA *data = &cpuState->data[i];
		switch (data->type) {
		case MEM:
			if (state == cyclic_forward) {
				segment_manager->write_data(data->offset,
						(const char*) data->value, data->length, true,
						print_log);
			} else if (state == cyclic_backward) {
				segment_manager->restore_data(data->offset, data->length,
						print_log);
			} else if (state == init) {
				segment_manager->write_data(data->offset,
						(const char*) data->value, data->length, false,
						print_log);
			}
			if (CboDumpMemState == BST_UNCHECKED) {
				set_ida_cursor(data->offset, mf_hex_window);
			}
			free(data->value);
			break;
		}
	}
}

/**
 * Color the line.
 * @param eip the eip line to color
 * @param repetition of the eip
 * @param state color style state (init or cyclic
 * */
void Malflare::color_line(ea_t eip, uint32 repetition, ModifyState state) {
	static bgcolor_t color_table[5][5] = { //
			{ 0xb8b8b8, 0xa1a19f, 0x8a8a8a, 0x7a7a79, 0x70706f }, // grey
					{ 0xeeeeaf, 0xe6e0b0, 0xe6d8ad, 0xface87, 0xffbf00 }, // blue
					{ 0x90f590, 0x7ff57f, 0x6ef56e, 0x37f037, 0x00ff00 }, // green
					{ 0x6af7f7, 0x57f7f7, 0x47f5f5, 0x27f5f5, 0x00ffff }, // yellow
					{ 0xbcbcf7, 0xadadf7, 0x9999f7, 0x8787f5, 0x6d6df7 } }; // red

	uint32 index = 0, color_index = 1;
	if (eip == 0) {
		return;
	}

	if (state == init) {
		index = 0;
	} else if (state == cyclic_forward) {
		index = 1;
	} else if (state == cyclic_backward) {
		if (repetition != 0xffffffff) {
			index = 1;
		} else {
			index = 0;
			repetition = 1;
		}
	} else if (state == loop_iteration_start) {
		index = 2;
	} else if (state == loop_node) {
		index = 3;
	} else if (state == loop_end) {
		index = 4;
	}

	if (repetition >= 10000) {
		color_index = 4;
	} else if (repetition >= 1000) {
		color_index = 3;
	} else if (repetition >= 100) {
		color_index = 2;
	} else if (repetition >= 10) {
		color_index = 1;
	} else if (repetition >= 1) {
		color_index = 0;
	}

	del_item_color(eip);
	set_item_color(eip, color_table[index][color_index]);
}

///////////////////////////////////////////////////////////////////////////////
// Callbacks
///////////////////////////////////////////////////////////////////////////////

/**
 * Handles the callback from the IDA Pro subwindow.
 * @param user_data
 * @param notification_code
 * @param va
 * */
int Malflare::ida_subwindow_callback(void *user_data, int notification_code,
		va_list va) {
	if (notification_code == ui_tform_visible) {
		TForm *form = va_arg(va, TForm *);
		if (form == user_data) {
			hIDAWindow = va_arg(va, HWND);
			// user defined form is displayed, populate it with controls
			create_gui_controls_callback(hIDAWindow, hInstance);
		}
	} else if (notification_code == ui_tform_invisible) {
		TForm *form = va_arg(va, TForm *);
		if (form == user_data) {
			DestroyWindow(hLblTracefileUrl);
			DestroyWindow(hBtnBrows);
			DestroyWindow(hTboTracefileUrl);
			DestroyWindow(hBtnRead);
			DestroyWindow(hBtnSetInitData);
			DestroyWindow(hBtnRunForward);
			DestroyWindow(hBtnRunBackward);
			DestroyWindow(hBtnStepForward);
			DestroyWindow(hBtnStepBackward);
			DestroyWindow(hLblLoopDetection);
			DestroyWindow(hLblExec);
			DestroyWindow(hBtnMinusExec);
			DestroyWindow(hLblCyclesExec);
			DestroyWindow(hBtnPlusExec);
			DestroyWindow(hBtnGotoExec);
			DestroyWindow(hLblActualCycleExec);
			DestroyWindow(hLblSpacerExec);
			DestroyWindow(hLblAllCyclesExec);
			DestroyWindow(hLblCyclesIter);
			DestroyWindow(hBtnMinusIter);
			DestroyWindow(hBtnPlusIter);
			DestroyWindow(hLblActualCycleIter);
			DestroyWindow(hLblAllCyclesIter);
			// TODO destroy all controls
		}
	}
	return 0;
}

/**
 * Handles the control callbacks from the IDA subwindow.
 * @param hWnd
 * @param message
 * @param wParam
 * @param lParam
 * */
LRESULT CALLBACK Malflare::control_callback(HWND hWnd, UINT message,
		WPARAM wParam, LPARAM lParam) {
	switch (message) {
	//	case WM_CLOSE: {
	//		DestroyWindow(hWnd);
	//	}
	//		break;
	//	case WM_DESTROY: {
	//		PostQuitMessage(0);
	//	}
	//		break;
	case WM_COMMAND: {
		last_pressed_key = wParam;

		switch (wParam) {
		case BTN_BROWS: {

			// <label:field type:maximum chars:field length:help identifier>
			char szForm[] = "Select malflare tracefile\n" //Window Caption
						"<Trace file:A:256:30::>" //String-Label
						"<#Trace file#" //Brows Button Tool-Tip
						"...:B::::>\n" //Brows Button
						"%/" //Form Callback function
						"\n";
			do {
				if (AskUsingForm_c(szForm, szTraceFilePath,
						button_changed_callback, select_tracefile_form_callback)
						== 1) { //Button ok
					if (qstrcmp(szTraceFilePath, "") == 0)
						warning("No trace file selected");
				} else
					return CallWindowProcA(oldIDAWindowWndProc, hWnd, message,
							wParam, lParam); //Button Cancel
			} while (qstrcmp(szTraceFilePath, "") == 0);

			// write Path to Label.
			SetWindowText(hTboTracefileUrl, szTraceFilePath);
			EnableWindow(hBtnRead, true); // enable read Button
		}
			break; // BTN_BROWS


		case BTN_READ: {
			read_tracefile_threaded();
			EnableWindow(hBtnSetInitData, true);
			EnableWindow(hBtnRead, false);
		}
			break; // BTN_READ


		case BTN_SETINITDATA: {
			tracer->get_initialized_data(&write_initialized_data_callback);
			tracer->write_loop_information();

			debug_mark = 0;
			set_user_defined_prefix(1, set_debug_mark);

			// enable forward buttons
			EnableWindow(hBtnRunForward, true);
			EnableWindow(hBtnStepForward, true);

			CPU_STATE *next_cpu_state = tracer->read_next_element();
			if (next_cpu_state != NULL) {
				modify_comment(next_cpu_state, cyclic_forward);
				modify_memory(next_cpu_state, cyclic_forward, false);
				color_line(next_cpu_state->eip,
						tracer->get_eip_repetition(next_cpu_state->eip, false),
						cyclic_forward);
				set_ida_cursor(next_cpu_state->eip, ida_window);
				get_loop_information();
				free(next_cpu_state);
			}
		}
			break; // BTN_SETINITDATA


		case BTN_DUMP_MEM: {
			CboDumpMemState = Button_GetCheck(hCboDumpMem);
		}
			break; // BTN_DUMP_MEM


		case BTN_RUN_FORWARD: {
			show_wait_box("Run forward");
			run_forward(NULL, true);
			hide_wait_box();
		}
			break; // BTN_RUN_FORWARD


		case BTN_STEP_FORWARD: {
			EnableWindow(hBtnRunBackward, true);
			EnableWindow(hBtnStepBackward, true);

			CPU_STATE *next_cpu_state = tracer->read_next_element();
			if (next_cpu_state != NULL) {
				modify_comment(next_cpu_state, cyclic_forward);
				modify_memory(next_cpu_state, cyclic_forward, true);
				color_line(next_cpu_state->eip,
						tracer->get_eip_repetition(next_cpu_state->eip, false),
						cyclic_forward);
				set_ida_cursor(next_cpu_state->eip, ida_window);
				get_loop_information();
				free(next_cpu_state);
			} else {
				// End of file
				EnableWindow(hBtnRunForward, false);
				EnableWindow(hBtnStepForward, false);
			}
		}
			break; // BTN_STEP_FORWARD


		case BTN_RUN_BACKWARD: {
			show_wait_box("Run backward");
			run_backward(NULL, true);
			hide_wait_box();
		}
			break; // BTN_RUN_BACKWARD


		case BTN_STEP_BACKWARD: {
			EnableWindow(hBtnRunForward, true);
			EnableWindow(hBtnStepForward, true);

			CPU_STATE *act_idt_cpu_state = NULL; // use to restore memory
			CPU_STATE *previous_idt_cpu_state = NULL; // use to restore register comment
			uint32 prev_eip = 0; // use to set the debug mark

			previous_idt_cpu_state = tracer->read_previous_element(
					&act_idt_cpu_state, &prev_eip);

			if (previous_idt_cpu_state != NULL) {
				modify_comment(previous_idt_cpu_state, cyclic_backward);
				free(previous_idt_cpu_state);
			}
			if (act_idt_cpu_state != NULL) {
				modify_memory(act_idt_cpu_state, cyclic_backward, true);
				uint32 repetition = tracer->get_eip_repetition(
						act_idt_cpu_state->eip, false);
				if (repetition == 0xffffffff) {
					color_line(
							act_idt_cpu_state->eip,
							tracer->get_eip_repetition(act_idt_cpu_state->eip,
									true), init);
				} else {
					color_line(act_idt_cpu_state->eip, repetition,
							cyclic_backward);
				}

				free(act_idt_cpu_state);
			}
			if (prev_eip != 0) {
				set_ida_cursor(prev_eip, ida_window);
				get_loop_information();
			} else {
				// Start of file
				EnableWindow(hBtnRunBackward, false);
				EnableWindow(hBtnStepBackward, false);
			}
		}
			break; // BTN_STEP_BACKWARD


		case BTN_PLUS_ITER: {
			show_wait_box("Go to next iteration");
			Idt *idt = tracer->get_iteration_idt(1, 0);
			if (idt != NULL) {
				run(idt, false);
			}
			hide_wait_box();
		}
			break; // BTN_PLUS_ITER


		case BTN_PLUS_EXEC: {
			show_wait_box("Go to next execution");
			Idt* idt = tracer->get_execution_idt(1, loop);
			if (idt != NULL) {
				run(idt, false);
			}
			hide_wait_box();
		}
			break; // BTN_PLUS_EXEC


		case BTN_MINUS_ITER: {
			show_wait_box("Go to previous iteration");
			Idt *idt = tracer->get_iteration_idt(-1, 0);
			if (idt != NULL) {
				run(idt, false);
			}
			hide_wait_box();
		}
			break; // BTN_MINUS_ITER


		case BTN_MINUS_EXEC: {
			show_wait_box("Go to previous execution");
			Idt *idt = tracer->get_execution_idt(-1, loop);
			if (idt != NULL) {
				run(idt, false);
			}
			hide_wait_box();
		}
			break; // BTN_MINUS_EXEC


		case BTN_GOTO_ITER: {
			// get new cycle
			char new_iteration_str[32];
			SendMessage(hLblActualCycleIter, WM_GETTEXT,
					sizeof(new_iteration_str), (ULONG) new_iteration_str);
			uint32 new_iteration = atoi(new_iteration_str);

			uint32 execution = 0, iteration = 0;
			if (tracer->calculate_cycles(loop, &execution, &iteration)) {
				uint32 iterations = tracer->get_iterations(execution, loop);

				if ((new_iteration > iterations) || (new_iteration == 0)) {
					warning(
							"%i is out of range. Possible range is from 1 to %i",
							new_iteration, iterations);
					break;
				}
				if (new_iteration == iteration) {
					break;
				}

				char position = 0;
				if (new_iteration == iterations) {
					position = 2;
				} else if (iterations == 1) {
					position = 1;
				}
				Idt* idt = tracer->get_iteration_idt(new_iteration - iteration,
						position);

				if (idt == NULL) {
					break;
				}
				if (new_iteration > iteration) {
					show_wait_box("Go forward to iteration %i", new_iteration);
				} else {
					show_wait_box("Go backward to iteration %i", new_iteration);
				}
				run(idt, false);
				hide_wait_box();

			}
		}
			break; // BTN_GOTO_ITER


		case BTN_START_ITER: {
			uint32 execution = 0, iteration = 0;
			if (tracer->calculate_cycles(loop, &execution, &iteration)) {
				Idt *idt = tracer->get_iteration_idt((iteration - 1) * (-1), 1);
				if (idt == NULL) {
					break;
				}
				show_wait_box("Go backward to first iteration");
				run(idt, false);
				hide_wait_box();
			}
		}
			break; // BTN_START_ITER


		case BTN_END_ITER: {
			uint32 execution = 0, iteration = 0;
			if (tracer->calculate_cycles(loop, &execution, &iteration)) {
				uint32 iterations = tracer->get_iterations(execution, loop);
				Idt *idt = tracer->get_iteration_idt(iterations - iteration, 2);
				if (idt == NULL) {
					break;
				}
				show_wait_box("Go forward to last iteration");
				run(idt, false);
				hide_wait_box();
			}
		}
			break; // BTN_END_ITER


		case BTN_GOTO_EXEC: {
			// get new cycle
			char new_execution_str[32];
			SendMessage(hLblActualCycleExec, WM_GETTEXT,
					sizeof(new_execution_str), (ULONG) new_execution_str);
			uint32 new_execution = atoi(new_execution_str);

			uint32 execution = 0, iteration = 0;
			if (tracer->calculate_cycles(loop, &execution, &iteration)) {

				if ((new_execution > loop->executions.size()) || (new_execution
						== 0)) {
					warning(
							"%i is out of range. Possible range is from 1 to %i",
							new_execution, execution);
					break;
				}
				if (new_execution == execution) {
					break;
				}

				Idt *idt = tracer->get_execution_idt(new_execution - execution,
						loop);
				if (idt == NULL) {
					break;
				}
				if (new_execution > execution) {
					show_wait_box("Go forward to execution %i", new_execution);
				} else {
					show_wait_box("Go backward to execution %i", new_execution);
				}
				run(idt, false);
				hide_wait_box();
			}
		}
			break; // BTN_GOTO_EXEC


		case BTN_START_EXEC: {
			uint32 execution = 0, iteration = 0;
			if (tracer->calculate_cycles(loop, &execution, &iteration)) {
				Idt *idt = tracer->get_execution_idt((execution * (-1)) + 1, loop);
				if (idt == NULL) {
					break;
				}
				show_wait_box("Go backward to first execution");
				run(idt, false);
				hide_wait_box();
			}
		}
			break; // BTN_START_EXEC


		case BTN_END_EXEC: {
			uint32 execution = 0, iteration = 0;
			if (tracer->calculate_cycles(loop, &execution, &iteration)) {
				Idt *idt = tracer->get_execution_idt(
						loop->executions.size() - execution, loop);
				if (idt == NULL) {
					break;
				}
				show_wait_box("Go forward to last execution");
				run(idt, false);
				hide_wait_box();
			}
		}
			break; // BTN_END_EXEC


		default: {
		} // default
		}

	} // WM_COMMAND

		break; // wParam
	default:
		return CallWindowProcA(oldIDAWindowWndProc, hWnd, message, wParam,
				lParam);
	}
	return CallWindowProcA(oldIDAWindowWndProc, hWnd, message, wParam, lParam);
}

/**
 * Run
 * */
void Malflare::run(Idt* idt, bool enable_breakpoints) {
	if (tracer->act_idt->offset > idt->offset) {
		run_backward(idt, enable_breakpoints);
	} else {
		run_forward(idt, enable_breakpoints);
	}
}

/**
 * Run forward
 * */
void Malflare::run_forward(Idt* idt, bool enable_breakpoints) {
	EnableWindow(hBtnRunBackward, true);
	EnableWindow(hBtnStepBackward, true);

	uint32 last_eip = 0;
	CPU_STATE *next_cpu_state = NULL;
	do {
		next_cpu_state = tracer->read_next_element();
		if (next_cpu_state != NULL) {
			last_eip = next_cpu_state->eip;
			modify_comment(next_cpu_state, cyclic_forward);
			modify_memory(next_cpu_state, cyclic_forward, false);
			color_line(next_cpu_state->eip,
					tracer->get_eip_repetition(next_cpu_state->eip, false),
					cyclic_forward);

			if (enable_breakpoints) {
				if (check_bpt(next_cpu_state->eip) > BPTCK_NO) {
					set_ida_cursor(next_cpu_state->eip, ida_window);
					get_loop_information();
					free(next_cpu_state);
					break;
				}
			}
			if (idt != NULL) {
				if (idt == tracer->act_idt) {
					set_ida_cursor(next_cpu_state->eip, ida_window);
					get_loop_information();
					free(next_cpu_state);
					break;
				}
			}
			free(next_cpu_state);
		} else {
			// End of file
			set_ida_cursor(last_eip, ida_window);
			get_loop_information();

			EnableWindow(hBtnRunForward, false);
			EnableWindow(hBtnStepForward, false);
		}
	} while (next_cpu_state != NULL);
}

/**
 *
 * */
void Malflare::run_backward(Idt* idt, bool enable_breakpoints) {
	EnableWindow(hBtnRunForward, true);
	EnableWindow(hBtnStepForward, true);

	CPU_STATE *act_idt_cpu_state = NULL; // use to restore memory
	CPU_STATE *previous_idt_cpu_state = NULL; // use to restore register comment
	uint32 previous_eip = 0; // use to set the debug mark
	do {
		previous_idt_cpu_state = tracer->read_previous_element(
				&act_idt_cpu_state, &previous_eip);

		if (previous_idt_cpu_state != NULL) {
			modify_comment(previous_idt_cpu_state, cyclic_backward);
			free(previous_idt_cpu_state);
		}
		if (act_idt_cpu_state != NULL) {
			modify_memory(act_idt_cpu_state, cyclic_backward, false);
			uint32 rep = tracer->get_eip_repetition(act_idt_cpu_state->eip,
					false);
			if (rep == 0xffffffff) {
				color_line(
						act_idt_cpu_state->eip,
						tracer->get_eip_repetition(act_idt_cpu_state->eip, true),
						init);
			} else {
				color_line(act_idt_cpu_state->eip, rep, cyclic_backward);
			}

			if (previous_eip != 0) {
				if (enable_breakpoints) {
					if (check_bpt(previous_eip) > BPTCK_NO) {
						set_ida_cursor(previous_eip, ida_window);
						get_loop_information();
						break;
					}
				}
				if (idt != NULL) {
					if (idt == tracer->act_idt) {
						set_ida_cursor(previous_eip, ida_window);
						get_loop_information();
						break;
					}
				}
			} else {
				// Start of file
				if (act_idt_cpu_state != NULL) {
					set_ida_cursor(act_idt_cpu_state->eip, ida_window);
					get_loop_information();
				}
				EnableWindow(hBtnRunBackward, false);
				EnableWindow(hBtnStepBackward, false);
			}

			free(act_idt_cpu_state);
		}
	} while (previous_eip != 0);
}

/**
 * Gets the loop information.
 * */
void Malflare::get_loop_information() {
	EnableWindow(hBtnPlusExec, true);
	EnableWindow(hBtnMinusExec, true);
	EnableWindow(hBtnGotoExec, true);
	EnableWindow(hBtnStartExec, true);
	EnableWindow(hBtnEndExec, true);
	EnableWindow(hBtnPlusIter, true);
	EnableWindow(hBtnMinusIter, true);
	EnableWindow(hBtnGotoIter, true);
	EnableWindow(hBtnStartIter, true);
	EnableWindow(hBtnEndIter, true);

	uint32 executions = 0;
	char lbl_executions[16];
	char lbl_act_executions[16];
	char lbl_exec_range[64];

	uint32 iteration = 0;
	char lbl_iteration[16];
	char lbl_act_iteration[16];
	char lbl_iter_range[64];

	Loop* tmp_loop = loop;

	loop = tracer->get_loop_information();

	// restore color
	if (tmp_loop != NULL) {
		if ((tmp_loop != loop) || (loop == NULL)) {
			Idt * tmp_idt = tmp_loop->lowest_node_idt;
			do {
				uint32 repetition = tracer->get_eip_repetition(tmp_idt->eip,
						true);
				if (repetition == 0xffffffff) {
					color_line(tmp_idt->eip, repetition, init);
				} else {
					color_line(tmp_idt->eip, repetition, cyclic_forward);
				}
				if (tmp_idt == tmp_loop->greatest_node_idt) {
					break;
				}
				tmp_idt = tmp_idt->next;
			} while (tmp_idt != NULL);
		}
	}

	if (loop == NULL) {
		SetWindowText(hLblActualCycleExec, "1");
		SetWindowText(hLblAllCyclesExec, "1");
		SetWindowText(hLblActualCycleIter, "1");
		SetWindowText(hLblAllCyclesIter, "1");
		SetWindowText(hLblIterationsMinVal, "-");
		SetWindowText(hLblIterationsAverageVal, "-");
		SetWindowText(hLblIterationsMaxVal, "-");
		SetWindowText(hLblExecStartToEnd, "(-)");
		SetWindowText(hLblIterStartToEnd, "(-)");

		EnableWindow(hBtnPlusExec, false);
		EnableWindow(hBtnMinusExec, false);
		EnableWindow(hBtnGotoExec, false);
		EnableWindow(hBtnStartExec, false);
		EnableWindow(hBtnEndExec, false);
		EnableWindow(hBtnPlusIter, false);
		EnableWindow(hBtnMinusIter, false);
		EnableWindow(hBtnGotoIter, false);
		EnableWindow(hBtnStartIter, false);
		EnableWindow(hBtnEndIter, false);
		return;
	} else {
		// set additional data
		char lbl_min[16];
		qsnprintf(lbl_min, sizeof(lbl_min), "%i", loop->iterations_min);
		SetWindowText(hLblIterationsMinVal, lbl_min);
		char lbl_average[16];
		qsnprintf(lbl_average, sizeof(lbl_average), "%i",
				loop->iterations_average);
		SetWindowText(hLblIterationsAverageVal, lbl_average);
		char lbl_max[16];
		qsnprintf(lbl_max, sizeof(lbl_max), "%i", loop->iterations_max);
		SetWindowText(hLblIterationsMaxVal, lbl_max);

		// actual repetition of the eip
		uint32 act_execution = 0, act_iteration = 0;
		if (tracer->calculate_cycles(loop, &act_execution, &act_iteration)) {
			executions = loop->executions.size();
			qsnprintf(lbl_executions, sizeof(lbl_executions), "%i", executions);
			SetWindowText(hLblAllCyclesExec, lbl_executions);

			list<LoopExecution>::iterator executionIterator =
					loop->executions.begin();
			advance(executionIterator, act_execution - 1); // move iterator i to index
			iteration = executionIterator->iterations.size();
			qsnprintf(lbl_iteration, sizeof(lbl_iteration), "%i", iteration);
			SetWindowText(hLblAllCyclesIter, lbl_iteration);
			qsnprintf(lbl_exec_range, sizeof(lbl_exec_range),
					"(from %08x to %08x)",
					executionIterator->iterations.begin()->start_idt->eip,
					executionIterator->iterations.back().end_idt->eip);
			SetWindowText(hLblExecStartToEnd, lbl_exec_range);

			qsnprintf(lbl_act_executions, sizeof(lbl_act_executions), "%i",
					act_execution);
			SetWindowText(hLblActualCycleExec, lbl_act_executions);
			if (act_execution == 1) {
				EnableWindow(hBtnMinusExec, false);
				EnableWindow(hBtnStartExec, false);
			} else if (act_execution == executions) {
				EnableWindow(hBtnPlusExec, false);
				EnableWindow(hBtnEndExec, false);
			}

			list<LoopIteration>::iterator iterationnIterator =
					executionIterator->iterations.begin();
			advance(iterationnIterator, act_iteration - 1); // move iterator i to index
			qsnprintf(lbl_act_iteration, sizeof(lbl_act_iteration), "%i",
					act_iteration);
			SetWindowText(hLblActualCycleIter, lbl_act_iteration);
			qsnprintf(lbl_iter_range, sizeof(lbl_iter_range),
					"(from %08x to %08x)", iterationnIterator->start_idt->eip,
					iterationnIterator->end_idt->eip);
			SetWindowText(hLblIterStartToEnd, lbl_iter_range);

			if (act_iteration == 1) {
				EnableWindow(hBtnStartIter, false);
				if (act_execution == 1) {
					EnableWindow(hBtnMinusIter, false);
				}
			} else if (act_iteration == iteration) {
				EnableWindow(hBtnEndIter, false);
				EnableWindow(hBtnPlusIter, false);
			}

			// color loop
			Idt * tmp_idt = loop->lowest_node_idt->previous;
			do {
				tmp_idt = tmp_idt->next;
				if (tmp_idt == NULL) {
					break;
				}
				color_line(tmp_idt->eip, tracer->get_eip_repetition(tmp_idt),
						loop_node);
			} while (tmp_idt != loop->greatest_node_idt);

			// entry point doesn't work for all loop-types
			color_line(loop->start_idt->eip,
					tracer->get_eip_repetition(loop->lowest_node_idt),
					loop_iteration_start);
			color_line(
					executionIterator->iterations.back().end_idt->eip,
					tracer->get_eip_repetition(
							executionIterator->iterations.back().end_idt),
					loop_end);
		}
	}
}

/**
 * Set the IDA Pro cursor
 * */
void Malflare::set_ida_cursor(uint32 new_eip, Window window) {
	if (new_eip != 0) {
		// store actual window
		//TForm* actual_form = get_current_tform();

		if (window == ida_window) {
			debug_mark = new_eip;
			switchto_tform(formA, false);

			char lbl_eip[16];
			qsnprintf(lbl_eip, sizeof(lbl_eip), "0x%08x", debug_mark);
			SetWindowText(hLblDebugEip, lbl_eip);
		} else if (window == mf_hex_window) {
			switchto_tform(formMalflareHex, false);
		}
		jumpto(new_eip);

		// restore window
		//switchto_tform(actual_form, false);

		refresh_idaview_anyway();
	}
}

/**
 * Set debug mark to IDA Pro.
 * */
void Malflare::set_debug_mark(ea_t ea, int lnnum, int indent, const char *line,
		char *buf, size_t bufsize) {
	if (debug_mark != ea) {
		return;
	}

	if (indent != -1) { // a directive
		return;
	}
	if (line[0] == '\0') { // empty line
		return;
	}
	if (tag_advance(line, 1)[-1] == ash.cmnt[0]) { // comment line...
		return;
	}

	char highlight_prefix[] = { COLOR_INV, '-', '>', COLOR_INV, 0 };
	buf[0] = '\0';
	qstrncpy(buf, highlight_prefix, bufsize);
}

/**
 * Creates the GUI controls on the IDA subwindow.
 * @param parent
 * @param hInst
 * */
void CALLBACK Malflare::create_gui_controls_callback(HWND parent,
		HINSTANCE hInst) {

	int xOffset = GUI_X_START_POSITION;
	int yOffset = GUI_Y_START_POSITION;

	//-------------------------------------------------------------------------
	// Tracefile
	//-------------------------------------------------------------------------
	// Tracefile Url Label.
	hLblTracefileUrl = CreateWindow("STATIC", TEXT("Select tracefile:"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,
			xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH;

	// Tracefile brows button
	hBtnBrows
			= CreateWindow("BUTTON", TEXT("..."),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnBrows, GWL_ID, BTN_BROWS);
	xOffset += GUI_CONTROL_WIDTH_SMALL + 10;

	// Tracefile Url
	hTboTracefileUrl = CreateWindow("STATIC", TEXT("no file selected"),
			WS_CHILD | WS_VISIBLE | BS_TEXT | ES_LEFT | ES_AUTOHSCROLL,
			xOffset,yOffset,
			GUI_CONTROL_WIDTH * 10,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT;

	// read Tracefile
	hBtnRead
			= CreateWindow("BUTTON", TEXT("Read tracefile"),GUI_BTN_STYLE,xOffset,yOffset,
					GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnRead, GWL_ID, BTN_READ);
	EnableWindow(hBtnRead, false);

	xOffset += GUI_CONTROL_WIDTH;

	hBtnSetInitData
			= CreateWindow("BUTTON", TEXT("Set initial data"),GUI_BTN_STYLE,xOffset,yOffset,
					130,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnSetInitData, GWL_ID, BTN_SETINITDATA);
	EnableWindow(hBtnSetInitData, false);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT * 2;

	//-------------------------------------------------------------------------
	// Checkbox dump all Memory
	hCboDumpMem
			= CreateWindow("BUTTON", TEXT("Run without log"),GUI_BTN_CHECKBOX,xOffset,yOffset,
					GUI_CONTROL_WIDTH*3,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hCboDumpMem, GWL_ID, BTN_DUMP_MEM);
	Button_SetCheck(hCboDumpMem, BST_CHECKED);
	CboDumpMemState = BST_CHECKED;

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT * 2;

	//-------------------------------------------------------------------------
	// Pseudo Debugger
	//-------------------------------------------------------------------------
	// Button Run backward
	hBtnRunBackward
			= CreateWindow("BUTTON", TEXT("<"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnRunBackward, GWL_ID, BTN_RUN_BACKWARD);
	EnableWindow(hBtnRunBackward, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// Button step backward.
	hBtnStepBackward
			= CreateWindow("BUTTON", TEXT("-"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnStepBackward, GWL_ID, BTN_STEP_BACKWARD);
	EnableWindow(hBtnStepBackward, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// EIP Label
	hLblDebugEip
			= CreateWindow("STATIC", TEXT("-"),
					WS_CHILD | WS_VISIBLE | SS_CENTER | BS_TEXT ,xOffset,yOffset,
					GUI_CONTROL_WIDTH_MEDIUM*2,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH_MEDIUM * 2;

	// Button step forward.
	hBtnStepForward
			= CreateWindow("BUTTON", TEXT("+"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnStepForward, GWL_ID, BTN_STEP_FORWARD);
	EnableWindow(hBtnStepForward, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// Button Run forward
	hBtnRunForward
			= CreateWindow("BUTTON", TEXT(">"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnRunForward, GWL_ID, BTN_RUN_FORWARD);
	EnableWindow(hBtnRunForward, false);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT * 2;

	//-------------------------------------------------------------------------
	// Loop detection
	//-------------------------------------------------------------------------
	hLblLoopDetection = CreateWindow("STATIC", TEXT("Loop"),
			WS_CHILD | WS_VISIBLE | BS_TEXT, xOffset,yOffset,
			GUI_CONTROL_WIDTH*3,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	yOffset += GUI_CONTROL_HEIGHT;

	hLblExec = CreateWindow("STATIC", TEXT("Executions:"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH;

	hLblExecStartToEnd = CreateWindow("STATIC", TEXT("(-)"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,xOffset,yOffset,
			GUI_CONTROL_WIDTH*3,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT;

	// < Button
	hBtnStartExec
			= CreateWindow("BUTTON", TEXT("<"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnStartExec, GWL_ID, BTN_START_EXEC);
	EnableWindow(hBtnStartExec, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// - Button
	hBtnMinusExec
			= CreateWindow("BUTTON", TEXT("-"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnMinusExec, GWL_ID, BTN_MINUS_EXEC);
	EnableWindow(hBtnMinusExec, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// Actual cyclic label
	hLblActualCycleExec = CreateWindow("EDIT", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_RIGHT | BS_TEXT,xOffset,yOffset,
			GUI_CONTROL_WIDTH_MEDIUM,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH_MEDIUM;

	// Spacer label
	hLblSpacerExec = CreateWindow("STATIC", TEXT("/"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,xOffset,yOffset,
			10,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += 10;

	// Cyclic label
	hLblAllCyclesExec = CreateWindow("STATIC", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH_MEDIUM,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH_MEDIUM;

	// + Button
	hBtnPlusExec
			= CreateWindow("BUTTON", TEXT("+"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnPlusExec, GWL_ID, BTN_PLUS_EXEC);
	EnableWindow(hBtnPlusExec, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// > Button
	hBtnEndExec
			= CreateWindow("BUTTON", TEXT(">"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnEndExec, GWL_ID, BTN_END_EXEC);
	EnableWindow(hBtnEndExec, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// Goto Buttons
	hBtnGotoExec
			= CreateWindow("BUTTON", TEXT("Goto"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL+10,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnGotoExec, GWL_ID, BTN_GOTO_EXEC);
	EnableWindow(hBtnGotoExec, false);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT * 2;

	hLblCyclesIter = CreateWindow("STATIC", TEXT("Cycles:"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH;

	hLblIterStartToEnd = CreateWindow("STATIC", TEXT("(-)"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,xOffset,yOffset,
			GUI_CONTROL_WIDTH*3,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT;

	// < Button
	hBtnStartIter
			= CreateWindow("BUTTON", TEXT("<"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnStartIter, GWL_ID, BTN_START_ITER);
	EnableWindow(hBtnStartIter, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// - Button
	hBtnMinusIter
			= CreateWindow("BUTTON", TEXT("-"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnMinusIter, GWL_ID, BTN_MINUS_ITER);
	EnableWindow(hBtnMinusIter, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// Actual cyclic label
	hLblActualCycleIter = CreateWindow("EDIT", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_RIGHT | BS_TEXT,xOffset,yOffset,
			GUI_CONTROL_WIDTH_MEDIUM,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH_MEDIUM;

	// Spacer label
	hLblSpacerIter = CreateWindow("STATIC", TEXT("/"),
			WS_CHILD | WS_VISIBLE | BS_TEXT,xOffset,yOffset,
			10,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += 10;

	// Cyclic label
	hLblAllCyclesIter = CreateWindow("STATIC", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH_MEDIUM,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH_MEDIUM;

	// + Button
	hBtnPlusIter
			= CreateWindow("BUTTON", TEXT("+"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnPlusIter, GWL_ID, BTN_PLUS_ITER);
	EnableWindow(hBtnPlusIter, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// > Button
	hBtnEndIter
			= CreateWindow("BUTTON", TEXT(">"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnEndIter, GWL_ID, BTN_END_ITER);
	EnableWindow(hBtnEndIter, false);
	xOffset += GUI_CONTROL_WIDTH_SMALL;

	// Goto Button
	hBtnGotoIter
			= CreateWindow("BUTTON", TEXT("Goto"),GUI_BTN_STYLE_CENTER,xOffset,yOffset,
					GUI_CONTROL_WIDTH_SMALL+10,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	SetWindowLong(hBtnGotoIter, GWL_ID, BTN_GOTO_ITER);
	EnableWindow(hBtnGotoIter, false);

	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT * 2;

	// Label for Iteration per Execution
	hLblIterationsPerCycle
			= CreateWindow("STATIC", TEXT("Iterations per Execution"),
					WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
					GUI_CONTROL_WIDTH*3,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	yOffset += GUI_CONTROL_HEIGHT;

	// Minimum
	hLblIterationsMin = CreateWindow("STATIC", TEXT("Minimum"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH;

	hLblIterationsMinVal = CreateWindow("STATIC", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT;

	// Average
	hLblIterationsAverage = CreateWindow("STATIC", TEXT("Average"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH;

	hLblIterationsAverageVal = CreateWindow("STATIC", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset = GUI_X_START_POSITION;
	yOffset += GUI_CONTROL_HEIGHT;

	// Maximum
	hLblIterationsMax = CreateWindow("STATIC", TEXT("Maximum"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);
	xOffset += GUI_CONTROL_WIDTH;

	hLblIterationsMaxVal = CreateWindow("STATIC", TEXT("-"),
			WS_CHILD | WS_VISIBLE | SS_LEFT| BS_TEXT ,xOffset,yOffset,
			GUI_CONTROL_WIDTH,GUI_CONTROL_HEIGHT,parent,NULL,hInst,NULL);

	oldIDAWindowWndProc = (WNDPROC) SetWindowLongPtr(hIDAWindow, GWLP_WNDPROC,
			(LONG_PTR) control_callback);
}

/**
 * Handles the brows button callback in the select tracefile pop up.
 * */
void Malflare::button_changed_callback(TView *tvFields[], int iCode) {
	char *scriptszTraceFilePath;
	scriptszTraceFilePath = askfile_c(0, "*info*", "Select trace file");

	if (scriptszTraceFilePath) {
		qstrncpy(szTraceFilePath, scriptszTraceFilePath,
				sizeof(szTraceFilePath));
		char* ptr = strstr(szTraceFilePath, "/info");
		if (ptr != NULL) {
			qstrncpy(ptr, "\0", 1);
		}
	}
}

/**
 * Handles the select tracefile form callback to write the browsed filepath into the textbox.
 * */
void Malflare::select_tracefile_form_callback(int iField_id,
		form_actions_t &faFormAction) {
	if (iField_id == 1) { //Brows Button
		faFormAction.set_field_value(0, szTraceFilePath); //Set Labeltext
	}
}

//-----------------------------------------------------------------------------
// end of code
//-----------------------------------------------------------------------------
