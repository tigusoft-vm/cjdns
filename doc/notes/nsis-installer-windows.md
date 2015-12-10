Hey, today we will make some windows... installer using nsis :)

First clone:
$ git clone https://github.com/interfect/cjdns-installer

And install Nullsoft Scriptable Install System:
(*help me a lot):
    http://blog.alejandrocelaya.com/2014/02/01/compile-nsis-scripts-in-linux/

sudo aptitude install nsis
    ?sudo aptitude install nsis-pluginapi // not nessesary

You could test nsis by call: 
$ makensis 
    You shold see output:

		MakeNSIS v2.46-10 - Copyright 1995-2009 Contributors
		See the file COPYING for license details.
		Credits can be found in the Users Manual.

		Usage:
		  makensis [option | script.nsi | - [...]]
		   options are:
			-CMDHELP item prints out help for 'item', or lists all commands
			-HDRINFO prints information about what options makensis was compiled with
			-LICENSE prints the makensis software license
			-VERSION prints the makensis version and exits
			-Px sets the compiler process priority, where x is 5=realtime,4=high,
				3=above normal,2=normal,1=below normal,0=idle
			-Vx verbosity where x is 4=all,3=no script,2=no info,1=no warnings,0=none
			-Ofile specifies a text file to log compiler output (default is stdout)
			-PAUSE pauses after execution
			-NOCONFIG disables inclusion of <path to makensis.exe>/nsisconf.nsh
			-NOCD disabled the current directory change to that of the .nsi file
			-Ddefine[=value] defines the symbol "define" for the script [to value]
			-Xscriptcmd executes scriptcmd in script (i.e. "-XOutFile poop.exe")
		   parameters are processed by order (-Ddef ins.nsi != ins.nsi -Ddef)
		   for script file name, you can use - to read from the standard input
		   you can use a double-dash to end options processing: makensis -- -ins.nsi




$ cd cjdns-installer
$ makensis installer.nsi
    (if you have you own compiled version of cjdroute.exe, you could replace it with cjdns-installer/installation/cjdroute.exe first)
    Linux build:
        SYSTEM=win32 CROSS_COMPILE=i686-w64-mingw32- ./cross-do   // command for cross compile cjdroute.exe on linux

* error: Invaild command: SimpleSC::StopService
Here you can download precompile .dll that provide missing function:
http://nsis.sourceforge.net/NSIS_Simple_Service_Plugin
http://nsis.sourceforge.net/mediawiki/images/c/c9/NSIS_Simple_Service_Plugin_1.30.zip

Move .dll to your nsis/Plugins directory:
you can find it by:
$ find /usr -type d -name "Plugins" | grep nsis

$ mv SimpleSC.dll /usr/share/nsis/Plugins/
    // /usr/share/nsis/Plugins/

another makensis error: ShellLink::SetRunAsAdministrator
Download from:
http://nsis.sourceforge.net/ShellLink_plug-in (ShellLink_plug-in)
http://nsis.sourceforge.net/mediawiki/images/6/6c/Shelllink.zip

Move .dll to nsis/Plugins directory:
mv ShellLink.dll to /usr/share/nsis/Plugins

Compiling success!

		Processed 1 file, writing output:
		Adding plug-ins initializing function... Done!
		Processing pages... Done!
		Removing unused resources... Done!
		Generating language tables... Done!
		Generating uninstaller... Done!

		Output: "cjdns-installer-0.5-proto16.exe"
		Install: 7 pages (448 bytes), 8 sections (8384 bytes), 568 instructions (15904 bytes), 266 strings (40228 bytes), 1 language table (350 bytes).
		Uninstall: 6 pages (384 bytes), 
		2 sections (2096 bytes), 461 instructions (12908 bytes), 217 strings (3811 bytes), 1 language table (322 bytes).
		Datablock optimizer saved 195947 bytes (~6.2%).

		Using zlib compression.

		EXE header size:               75776 / 70656 bytes
		Install code:                  17204 / 65690 bytes
		Install data:                2794904 / 7565530 bytes
		Uninstall code+data:           56025 / 59899 bytes
		CRC (0x71103B0F):                  4 / 4 bytes

		Total size:                  2943913 / 7761779 bytes (37.9%)
