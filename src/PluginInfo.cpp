/*
 * Project:			Malflare
 * Authors:			Dominic Fischer / Daniel Jordi
 * Date:			14.06.2011
 * Dependencies:	IDA Pro 6 + SDK
 */

//-----------------------------------------------------------------------------
// Includes
//-----------------------------------------------------------------------------
#include "Malflare.h"

// Creates the Malflare object.
Malflare mf;

/**
 * Object for the IDA Pro plugin handler.
 */
plugin_t PLUGIN = { IDP_INTERFACE_VERSION, // IDA version plug-in is written for
		PLUGIN_MOD, // Plugin modus
		&mf.ida_init, // Initialisation function
		&mf.ida_exit, // Clean-up function
		&mf.ida_run, // Main plug-in body
		GUI_PLUGIN_COMMENT, // Comment
		GUI_PLUGIN_HELP, // As above
		GUI_PLUGIN_CAPTION, // Plug-in name shown in Edit->Plugins menu
		PLUGIN_HOTKEY // Hot key to run the plug-in
		};

//-----------------------------------------------------------------------------
//End of Code
//-----------------------------------------------------------------------------
