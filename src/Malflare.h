/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			16.03.2011
 * Dependencies:	IDA Pro 6 + SDK
 */

#ifndef MALFLARE_H_
#define MALFLARE_H_

//-----------------------------------------------------------------------------
// Includes
//-----------------------------------------------------------------------------
//#define USE_STANDARD_FILE_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS
#define add_popup add_custom_viewer_popup_item
#include <windows.h>
#include <windowsx.h>
#include <winuser.h>
#include <wingdi.h>
#include <stdlib.h>
#include <string>
#include <sstream>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <dbg.hpp>
#include <lines.hpp>

#include "GlobalIncludes.h"
#include "Tracer.h"
#include "BinaryTree.h"
#include "Segment.h"
#include "SegmentManager.h"
#include "SyscallInterpretation.h"

//-----------------------------------------------------------------------------
//Constants
//-----------------------------------------------------------------------------
#define GUI_PLUGIN_CAPTION    "Malflare"
#define GUI_PLUGIN_COMMENT 	  "This is the Malflare plugin."
#define GUI_PLUGIN_HELP  	  "Malflare Plugin 1.00"
#define PLUGIN_HOTKEY    	  "Alt-M"
#define PLUGIN_OPTIONS     	  FORM_MDI | FORM_TAB | FORM_MENU | FORM_RESTORE

/*
 * Main class of the IDA Pro Plugin Malflare.
 *
 * */
class Malflare {
public:
	// Constructor
	Malflare();

	enum ModifyState {
		init,
		cyclic_forward,
		cyclic_backward,
		loop_iteration_start,
		loop_node,
		loop_end
	};
	enum Window {
		ida_window, mf_hex_window
	};

	// IDA Pro Plugin functions.
	static int ida_init(void);
	static void ida_run(int arg);
	static void ida_exit(void);

	// Methods.
	static int ida_subwindow_callback(void *user_data, int notification_code,
			va_list va);
	static LRESULT CALLBACK control_callback(HWND hWnd, UINT mesg,
			WPARAM wParam, LPARAM lParam);
	static void button_changed_callback(TView *tvFields[], int iCode);
	static void select_tracefile_form_callback(int iField_id,
			form_actions_t &faFormAction);
	static void
	CALLBACK create_gui_hexview_callback(HWND hwnd, HINSTANCE hInst);
	static void CALLBACK create_gui_controls_callback(HWND hwnd,
			HINSTANCE hInst);

	static void create_ida_subwindows();

	static void write_initialized_data_callback(CPU_STATE *cpu_state,
			uint32 repetition);

	static void run(Idt* idt, bool enable_breakpoints);
	static void run_forward(Idt* idt, bool enable_breakpoints);
	static void run_backward(Idt* idt, bool enable_breakpoints);

	static void color_line(ea_t eip, uint32 repetition, ModifyState state);
	static void modify_comment(CPU_STATE *cpuState, ModifyState state);
	static void modify_memory(CPU_STATE *cpuState, ModifyState state,
			bool print_log);
	static void get_loop_information();

	static void read_tracefile_threaded();
	static int read_tracefile(void *args);

	static void set_ida_cursor(uint32 eip, Window window);
	static void set_debug_mark(ea_t ea, int lnnum, int indent,
			const char *line, char *buf, size_t bufsize);
private:
	// Variables.
	static Tracer *tracer;
	static SegmentManager *segment_manager;
	static SyscallInterpretation *syscall_interpretation;

	static TForm *formA;
	static TForm *formMalflareHex;
	static TForm *formMalflare;
	static HINSTANCE hInstance;
	static WNDPROC oldIDAWindowWndProc;
	static qthread_t thread_h;
	static uint32 last_pressed_key;

	static char szTraceFilePath[256];
	static ea_t debug_mark;

	static HWND hIDAWindow;
	static HWND hLblTracefileUrl;
	static HWND hBtnBrows;
	static HWND hTboTracefileUrl;
	static HWND hBtnRead;
	static HWND hBtnSetInitData;
	static HWND hCboDumpMem;
	static LRESULT CboDumpMemState;

	static HWND hBtnRunBackward;
	static HWND hBtnStepBackward;
	static HWND hLblDebugEip;
	static HWND hBtnStepForward;
	static HWND hBtnRunForward;

	static Loop* loop;
	static HWND hLblLoopDetection;
	static HWND hLblExec;
	static HWND hLblExecStartToEnd;
	static HWND hBtnStartExec;
	static HWND hBtnMinusExec;
	static HWND hLblCyclesExec;
	static HWND hBtnPlusExec;
	static HWND hBtnEndExec;
	static HWND hBtnGotoExec;
	static HWND hLblActualCycleExec;
	static HWND hLblSpacerExec;
	static HWND hLblAllCyclesExec;

	static HWND hLblCyclesIter;
	static HWND hLblIterStartToEnd;
	static HWND hBtnStartIter;
	static HWND hBtnMinusIter;
	static HWND hBtnPlusIter;
	static HWND hBtnEndIter;
	static HWND hBtnGotoIter;
	static HWND hLblActualCycleIter;
	static HWND hLblSpacerIter;
	static HWND hLblAllCyclesIter;

	static HWND hLblIterationsPerCycle;
	static HWND hLblIterationsMin;
	static HWND hLblIterationsMinVal;
	static HWND hLblIterationsAverage;
	static HWND hLblIterationsAverageVal;
	static HWND hLblIterationsMax;
	static HWND hLblIterationsMaxVal;
};

#endif /* MALFLARE_HPP_ */
