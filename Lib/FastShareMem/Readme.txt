
FastSharemem
------------


 A fast, lightweight Sharemem replacement for Delphi.
 Diverts all heap calls from multiple DLLs/EXE into a
 single heap. Say goodbye to Sharemem/Borlndmm.dll.


AUTHOR: emil santos (ems@codexterity.com)


VERSION: 2.10

OS: Windows 95, Windows 95 OSR2, Windows 98, Windows 98SE, Windows ME,
    Windows NT, 2000, XP, 2003.

Delphi Version: 2-7

FEATURES

	* no runtime DLL required
	* no performance penalty
	* fixes some pointer-related dll errors.

USAGE

  Windows:
    Must be the first unit listed in the project file's USES section
    for both dll and exe projects. If you install a memory manager for
    leak detection, it should be listed immediately after this unit.
  Linux:
    Not needed. May be commented out using conditional directives:

    	uses {$IFDEF WIN32} FastShareMem, {$ENDIF}



USE OF FASTSHAREMEM WITH A LEAK DETECTOR

  If you use a leak detector which also replaces the default
  memory manager, include it immediately after FastSharemem
  for all projects.


FEEDBACK

  Please send bug reports and comments to fastsharemem@codexterity.com.
  To be notified of updates by email, subscribe to the site alerter
  facility (http://www.codexterity.com).
  


REVISION HISTORY


 Version 2.10:

 * Added GetAllocMemCount and GetAllocMemSize functions. 
   From a contribution by Andrey Nikolayevich Aban'shin (andrey@ecobank.san.ru).

 
 Version 2.00:

 * Version 2.0 released. Complete rewrite; now uses a window class
   to exchange data between modules. Safer, and *much* simpler.
   The code is also much shorter. Now works with all 32-Delphi versions
   (Delphi 2 and above).


 Version 1.23:

 * Removed reference to SysUtils. This was causing subtle bugs.
   Update by Alex Blach (entwicklung@zmi.de)


 Version 1.22:

 * Fixed "Combining signed and unsigned types" warning. Replaced 
   integers with longword where appropriate. Added Linux usage.
   Thanks to Nagy Krisztián (chris@manage.co.hu)


 Version 1.21:

 * Separated MEM_DECOMMIT and MEM_RELEASE calls. Thanks to Maurice Fletcher.


 Version 1.2:

 * Thanks to Ai Ming (aiming@ynxx.com) for his changes:
   Modified to work with Windows NT/2000/XP.
   Added reference-counting mechanism.


 Version 1.01:

 * Rewrote address-computation code to better match windows 98
   allocation. VirtualAlloc may round down requested address *twice*.
   Replaced ASSERTs with (lower-level) Win32 MessageBox calls.
   (Thanks to Darryl Strickland (DStrickland@carolina.rr.com))




COPYRIGHT

  FastSharemem is copyrighted (c) 2003 by Emil M. Santos. You may
  use and modify the software as you wish, as long as this copyright 
  is retained. Please give credit where it is due.
 

STANDARD DISCLAIMER

  The author has taken all possible care to ensure the software is
  error-free, however the author disavows any potential liability
  arising from any use of the software.  Use of the software is
  entirely at your own risk.



