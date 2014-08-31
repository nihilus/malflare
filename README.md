malflare
========

https://www.hex-rays.com/contests/2011/

Dominic Fischer and Daniel Jordi from Bern University of Applied Sciences with the Malfare plugin
A quote from the documentation:

The plugin merges dynamic information with the information of the static analysis given by IDA. Those dynamic information are gathered with another plugin for TEMU (http://bitblaze.cs.berkeley.edu/temu.html) and containing executed instructions, memory and registers. With both, dynamic and static data, our plugin is able to detect loops, to reconstruct memory and registers at any given time and to annotate systemcalls with its arguments. In addition we created a pseudo debugger, which can navigate (forwards and backwards) through the binary and its data collected from the dynamic analysis.
Our comments: Dominic and Daniel's idea is very nice. We tried the pre-compiled plugin with the sample trace file and we could trace the recorded execution of the program from start to end. Unfortunately we had difficulties compiling the plugin from the sources and later encountered runtime errors. The plugin could have been a winner if the pseudo-debugger was actually a debugger module for IDA and would be more robust
