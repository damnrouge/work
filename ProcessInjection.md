Process Injection:

Process injection is a technique used in Windows to execute arbitrary code within the address space of another process. This can be used for legitimate purposes, such as debugging, but it's also a common tactic employed by malware to evade detection. Here's a step-by-step explanation of the process injection technique with the Windows APIs involved:

1. **Process Enumeration**: The first step is to identify the target process into which the code will be injected. This is typically done using the `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next` APIs to enumerate through the running processes².

2. **Open Process**: Once the target process is identified, a handle to the process is obtained using the `OpenProcess` API. This handle is necessary for further operations on the target process².

3. **Memory Allocation**: The next step is to allocate memory within the target process's address space. This is done using the `VirtualAllocEx` API, which reserves a region of memory within the context of the target process⁴.

4. **Memory Writing**: After allocating memory, the next step is to write the code or payload into the allocated space. This is achieved with the `WriteProcessMemory` API, which copies the code from the injector to the target process's memory⁴.

5. **Adjust Memory Protections**: Before executing the injected code, it's often necessary to change the memory protection of the allocated region to execute permissions. The `VirtualProtectEx` API is used for this purpose¹.

6. **Remote Thread Creation**: Finally, to execute the injected code, a new thread is created within the target process using the `CreateRemoteThread` API. This thread will begin execution at the start of the injected code¹.

Each of these steps involves careful planning and execution to ensure that the code is injected and executed without causing the target process to crash or behave unexpectedly. It's important to note that process injection techniques are complex and can vary depending on the specific method used and the goal of the injection. The above steps provide a high-level overview of a typical process injection scenario.


In the context of process injection on Windows, "Set Memory Protection" refers to changing the memory protection of the allocated space to allow the execution of code. When memory is allocated in a process using `VirtualAllocEx`, it's typically marked as nonexecutable by default for security reasons. This means you can read from and write to this memory, but you cannot execute code that resides there.

To execute injected code, the memory protection must be changed to allow execution. This is done using the `VirtualProtectEx` API. Here's what happens step-by-step:

1. **Memory Allocation**: Memory is allocated in the target process with `VirtualAllocEx`, which typically sets the protection level to `PAGE_READWRITE`, allowing reading and writing but not execution.

2. **Memory Protection Change**: Before the injected code can be run, the protection level of the allocated memory must be changed to `PAGE_EXECUTE_READWRITE` using `VirtualProtectEx`. This allows the memory to be read, written, and executed.

3. **Code Execution**: With the protection level set to `PAGE_EXECUTE_READWRITE`, the injected code can now be executed by the process.

PROCESS HOLLOWING:
Process hollowing is a code injection technique that involves creating a new process in a suspended state, hollowing out its memory, and then running malicious code in the context of the hollowed process. Here's a step-by-step guide with the Windows APIs involved:

1. **Create a Suspended Process**: Start a new instance of a legitimate process using `CreateProcess` with the `CREATE_SUSPENDED` flag. This creates the process in a suspended state without running any of its code.

2. **Unmap the Process Memory**: Use `NtUnmapViewOfSection` to unmap the memory section that contains the original process image. This effectively hollows out the process.

3. **Allocate Memory**: Allocate new memory within the hollowed process using `VirtualAllocEx`, ensuring it's large enough to host the malicious payload.

4. **Write the Payload**: Write the malicious code or payload into the allocated memory using `WriteProcessMemory`.

5. **Set the Context**: Modify the process's context with `GetThreadContext` and `SetThreadContext` to update the entry point of the executable to the location of the injected code.

6. **Resume the Thread**: Finally, resume the suspended process with `ResumeThread`, which will cause the process to run the malicious code.




