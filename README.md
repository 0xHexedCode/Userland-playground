# Userland-playground

My own personal codes for userland stuff. Samples of use will come later.

## Content

* NTHeader.h : nearly all definitions I need to code windows stuff + some functions I wrote. Header will be expanded with time.

### Personal Functions :

* ToLowerW
* ToLowerA
* StringLengthA
* StringLengthW
* CompareUnicode
* CompareAnsi
* Separator
* StringMatches 
* StringMatchesA
* NtCurrentPeb
* NtCurrentTIBOrTEB
* FastSysCallWoW64
* GetModuleBaseAddress
* GetProcedureAddressNt
* MallocCustom
* ReverseSeparator
* CharToWCharT
* GetProcedureAddress
* IsHookedNtDLL
* PatchNTDllSection

### Windows Functions :

* CSRGETPROCESSID
* DBGPRINT
* LDRGETPROCEDUREADDRESS
* LDRLOADDLL
* MEMSET
* NTALERTHREAD
* NTALLOCATEVIRTUALMEMORY
* NTCLOSE
* NTCREATEPROCESS
* NTCREATEPROCESSEX
* NTCREATESECTION
* NTCREATESECTIONEX
* NTCREATETHREAD
* NTCREATETHREADEX
* NTCREATEUSERPROCESS
* NTDELAYEXECUTION
* NTDELETEFILE
* NTEXTENDSECTION
* NTFREEVIRTUALMEMORY
* NTGETCONTEXTTHREAD
* NTINITIATEPOWERACTION
* NTMAPVIEWOFSECTION
* NTMAPVIEWOFSECTIONEX
* NTOPENFILE
* NTOPENPROCESS
* NTOPENTHREAD
* NTPROTECTVIRTUALMEMORY
* NTQUERYINFORMATIONBYNAME
* NTQUERYINFORMATIONFILE
* NTQUERYINFORMATIONPROCESS
* NTQUERYSYSTEMINFORMATION
* NTQUEUEAPCTHREAD
* NTQUEUEAPCTHREADEX
* NTRAISEHARDERROR
* NTREADFILE
* NTREADVIRTUALMEMORY
* NTREMOVEPROCESSDEBUG
* NTRESUMEPROCESS
* NTRESUMETHREAD
* NTSETCONTEXTTHREAD
* NTSETINFORMATIONFILE
* NTSETINFORMATIONPROCESS
* NTSETSYSTEMPOWERSTATE
* NTSETTHREADEXECUTIONSTATE
* NTSHUTDOWNSYSTEM
* NTSUSPENDPROCESS
* NTSUSPENDTHREAD
* NTTERMINATEPROCESS
* NTTESTALERT
* NTUNMAPVIEWOFSECTION
* NTUNMAPVIEWOFSECTIONEX
* NTWRITEVIRTUALMEMORY
* RTLCREATEPROCESSPARAMETERSEX
* RTLCREATEUSERPROCESSEX
* RTLACQUIREPRIVILEGE
* RTLADJUSTPRIVILEGE
* RTLCREATEHEAP
* RTCREATETAGHEAP
* RTLCREATEMEMORYZONE
* RTLINITANSISTRING
* RTLINITUNICODESTRING
* RTLGETNTGLOBALFLAGS
* RTLQUERYELEVATIONFLAGS
* RTLREMOTECALL

## Sources

* [Windows Types](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types)
* [Offsets in fs & gs registers](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
* [SystemInformer aka processhacker](https://github.com/processhacker/phnt)
* [SystemInformer aka processhacker](https://github.com/winsiderss/systeminformer/tree/master/phnt/include)
* [CaptMeelo](https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html)
* [ReactOS](https://github.com/reactos/reactos)
* [AdamHlt](https://github.com/adamhlt/Manual-DLL-Loader)
* [VX](https://github.com/vxunderground/VX-API)
* [Arbiter34](https://github.com/arbiter34/GetProcAddress/blob/master/GetProcAddress/GetProcAddress.cpp)
