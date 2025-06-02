Refer This: https://medium.com/@Manasi_Joshi/dissecting-malware-2911f9d1a118

PE File Structure:
├── DOS Header
│   ├── e_magic: Signature ("MZ") indicating an MS-DOS executable                       IMP
│   ├── e_cblp: Bytes on last page of file (usually 0)
│   ├── e_cp: Pages in file (usually 0)
│   ├── e_crlc: Relocations (usually 0)
│   ├── e_cparhdr: Size of header in paragraphs (usually 4)
│   ├── e_minalloc: Minimum extra paragraphs needed (usually 0)
│   ├── e_maxalloc: Maximum extra paragraphs needed (usually 65535)
│   ├── e_ss: Initial (relative) SS value (usually 0)
│   ├── e_sp: Initial SP value (usually 184)
│   ├── e_csum: Checksum (usually 0)
│   ├── e_ip: Initial IP value (usually 0)
│   ├── e_cs: Initial (relative) CS value (usually 0)
│   ├── e_lfarlc: File address of relocation table (usually 64)
│   ├── e_ovno: Overlay number (usually 0)
│   ├── e_res: Reserved words (usually 4 words of 0)
│   ├── e_oemid: OEM identifier (usually 0)
│   ├── e_oeminfo: OEM information (usually 0)
│   ├── e_res2: Reserved words (usually 10 words of 0)
│   ├── e_lfanew: Offset to the PE header                                              IMP
│   └── ...
├── DOS Stub
│   └── Small MS-DOS 2.0 compatible executable (prints error message)                  IMP
├── NT Headers
│   ├── PE signature: 4-byte signature ("PE\0\0")
│   ├── File Header
│   │   ├── Machine: Target architecture (e.g., x86, x64)                              IMP
│   │   ├── NumberOfSections: Total sections in the file                               IMP
│   │   ├── TimeDateStamp: Creation timestamp                                          IMP
│   │   ├── PointerToSymbolTable: File offset of COFF symbol table (usually 0) 
│   │   ├── NumberOfSymbols: Total number of symbols (usually 0)
│   │   ├── SizeOfOptionalHeader: Size of the optional header (usually 224 bytes for 32-bit PE files)
│   │   ├── Characteristics: Flags indicating various attributes (e.g., whether it's a DLL, executable, etc.) IMP  
│   │   └── ...
│   └── Optional Header
│       ├── Magic: Determines whether it's a 32-bit (PE32) or 64-bit (PE32+) format
│       ├── MajorLinkerVersion: Linker version
│       ├── SizeOfCode: Size of code section
│       ├── SizeOfInitializedData: Size of initialized data section
│       ├── SizeOfUninitializedData: Size of uninitialized data section
│       ├── AddressOfEntryPoint: Entry point (usually `main`)
│       ├── BaseOfCode: Base address of code section
│       ├── BaseOfData: Base address of data section
│       ├── ImageBase: Preferred base address in memory (exe: 0x400000, dll:0x10000000)
│       ├── SectionAlignment: Alignment of sections in memory
│       ├── FileAlignment: Alignment of sections in the file
│       ├── MajorOperatingSystemVersion: OS version
│       ├── MajorImageVersion: Image version
│       ├── MajorSubsystemVersion: Subsystem version
│       ├── Subsystem: Type of application (console, GUI, etc.)
│       ├── SizeOfImage: Total size of the image in memory
│       ├── SizeOfHeaders: Combined size of headers
│       ├── CheckSum: Checksum for integrity validation
│       ├── Subsystem: Type of application (console, GUI, etc.)
│       └── ...
├── Section Table
│   ├── Image Section Headers (one for each section)
│   │   ├── Name: Section name (e.g., `.text`, `.data`)
│   │   ├── VirtualSize: Size in memory
│   │   ├── VirtualAddress: Preferred virtual address
│   │   ├── SizeOfRawData: Size in the file
│   │   ├── PointerToRawData: File offset where section data starts
│   │   ├── Characteristics: Flags specifying section properties (e.g., readable, writable, executable)
│   │   └── ...
│   └── ...
├── Sections
│   ├── .text: Executable code
│   ├── .data: Initialized global/static data
│   ├── .rdata: Read-only, initialized data (constants)
│   └── ...
└── ...
--------------------------------------Important dll-----------------------------------------------------------------------------------------
- kernel32.dll:
    - Role:
        - Core system DLL for Windows.
        - Provides fundamental functions related to memory management, process creation, file I/O, and system time.
        - Used by nearly all Windows programs.
    - Common Functions:
        - CreateFile: Opens or creates a file.
        - ReadFile and WriteFile: Read from or write to a file.
        - CreateProcess: Creates a new process.
        - VirtualAlloc: Allocates memory in the process address space.
        - GetSystemTime: Retrieves the current system time.
- advapi32.dll:
    - Role:
        - Provides advanced Windows services related to security, registry, and event logging.
        - Used for managing user accounts, access control, and cryptographic operations.
    - Common Functions:
        - RegOpenKeyEx: Opens a registry key.
        - CryptAcquireContext: Initializes a cryptographic service provider.
        - LookupAccountSid: Retrieves account information for a given security identifier (SID).
        - ReportEvent: Writes an event to the event log.
- user32.dll:
    - Role:
        - Handles user interface and window management.
        - Provides functions for creating windows, handling messages, and managing input.
    - Common Functions:
        - CreateWindowEx: Creates a window.
        - SendMessage: Sends a message to a window procedure.
        - GetMessage: Retrieves a message from the message queue.
        - SetWindowText: Sets the text of a window.
- gdi32.dll:
    - Role:
        - Provides graphics device interface (GDI) functions for drawing graphics and text.
        - Used for rendering fonts, lines, shapes, and images.
    - Common Functions:
        - CreateFont: Creates a font object.
        - CreatePen: Creates a pen for drawing lines and curves.
        - BitBlt: Performs bit-block transfer of image data.
        - TextOut: Displays text on a device context.
- shell32.dll:
    - Role:
        - Provides functions related to the Windows shell (user interface).
        - Used for file operations, shortcuts, and system icons.
    - Common Functions:
        - ShellExecute: Executes a file or opens a folder.
        - SHGetFolderPath: Retrieves special folder paths (e.g., My Documents).
        - ExtractIcon: Extracts icons from files.
        - SHGetFileInfo: Retrieves file information and icons.
- ole32.dll:
    - Role:
        - Provides functions for Object Linking and Embedding (OLE) technology.
        - Used for compound documents, embedding objects, and inter-process communication.
    - Common Functions:
        - CoCreateInstance: Creates an instance of a COM object.
        - OleInitialize: Initializes the OLE library.
        - OleLoad: Loads an object from a stream.
        - OleSave: Saves an object to a stream.
- comctl32.dll:
    - Role:
        - Provides common controls for Windows applications (buttons, list views, etc.).
        - Used for creating consistent user interfaces.
    - Common Functions:
        - InitCommonControlsEx: Initializes common controls.
        - CreateToolbarEx: Creates a toolbar control.
        - ListView_InsertItem: Inserts an item into a list view.
        - TabCtrl_InsertItem: Inserts an item into a tab control.
- rpcrt4.dll:
    - Role:
        - Provides functions for remote procedure calls (RPC).
        - Used for inter-process communication across a network.
    - Common Functions:
        - RpcStringBindingCompose: Creates a string binding for an RPC interface.
        - RpcBindingFromStringBinding: Converts a string binding to a binding handle.
        - RpcEpRegister: Registers an RPC endpoint.
        - RpcMgmtEpEltInqBegin: Begins enumeration of registered endpoints.
- ntdll.dll:
    - Role:
        - Provides low-level functions for the Windows NT kernel.
        - Used for system calls, memory management, and exception handling.
    - Common Functions:
        - NtCreateFile: Creates or opens a file.
        - NtReadFile and NtWriteFile: Read from or write to a file.
        - NtAllocateVirtualMemory: Allocates memory in the process address space.
        - NtQuerySystemInformation: Retrieves system information.
______________________________________________________________________________Malware-api_________________________________________________________

1. Virus:
   - Functions:
     - `CreateFileA`: Opens or creates a file.
     - `WriteProcessMemory`: Writes data to another process's memory.
     - `CreateProcessA`: Creates a new process.
     - `ExitProcess`: Terminates the current process.

2. Trojan:
   - Functions:
     - `InternetOpenA`: Initializes WinINet functions for internet access.
     - `RegOpenKeyExA`: Opens a registry key.
     - `ShellExecuteA`: Executes other programs or files.
     - `WinExec`: Executes a command-line program.
     - `URLDownloadToFileA`: Downloads files from the internet.

3. Worm:
   - Functions:
     - `WSASocket`: Creates a socket for network communication.
     - `GetAdaptersInfo`: Retrieves network adapter information.
     - `CreateThread`: Creates a new thread.
     - `GetTickCount`: Retrieves system uptime in milliseconds.
     - `GetSystemTime`: Retrieves the current system time.

4. Rootkit:
   - Functions:
     - `NtQuerySystemInformation`: Retrieves system information.
     - `ZwCreateFile`: Creates or opens a file.
     - `ZwReadFile`: Reads data from a file.
     - `ZwWriteFile`: Writes data to a file.
     - `ZwQueryDirectoryFile`: Queries directory information.

5. Remote Access Trojans (RATs):
   - RATs provide remote access to the attacker, allowing control over infected devices.
   - Common RAT functions include:
     - `CreateRemoteThread`: Creates a thread in another process.
     - `VirtualAllocEx`: Allocates memory in a remote process.
     - `WriteProcessMemory`: Writes data to the memory of another process.
     - `CreateProcess`: Creates a new process in a remote system.

6. Ransomware:
   - Ransomware encrypts files on the victim's system and demands payment (usually in cryptocurrency) for decryption.
   - Common ransomware functions include:
     - File encryption using cryptographic algorithms (e.g., AES).
     - Displaying ransom notes with payment instructions.
     - Communication with the attacker's server to obtain decryption keys.
_________________________________________________API_BY_Action________________________________________________________________________________

- File Operations:
    - CreateFile: Used to create or open files, directories, or devices. It returns a handle to the file or device.
    - ReadFile: Reads data from a file.
    - WriteFile: Writes data to a file.
    - CloseHandle: Closes an open handle.
- Process Operations:
    - OpenProcess: Opens an existing process for various access rights.
    - CreateProcess: Creates a new process and its primary thread.
    - WinExec: Executes a command-line program.
    - TerminateProcess: Terminates a process.
- Registry Operations:
    - RegCreateKeyEx: Creates a new registry key or opens an existing one.
    - RegOpenKeyEx: Opens an existing registry key.
    - RegSetValueEx: Sets the value of a registry key.
    - RegQueryValueEx: Retrieves the value of a registry key.
    - RegDeleteKey: Deletes a registry key.
- Network Operations:
    - Winsock: Provides networking functions for socket programming (e.g., creating sockets, sending/receiving data).
    - HTTP/HTTPS APIs: Used for web communication.
    - Net Functions*: Various network-related functions.
Remember that these are just a few examples, and there are many more Windows API functions available for different purposes. If you'd like more detailed information, you can refer to the https://github.com/7etsuo/windows-api-function-cheatsheets  on GitHub. 

Common Packers used by malwares: upx, zlib, deflate


-------------------------------------------------------------------------------------------------------------------------------------

# PE File Structure & Malware API Reference

## Table of Contents
- [PE File Structure](#pe-file-structure)
  - [DOS Header](#dos-header)
  - [NT Headers](#nt-headers)
  - [Section Table](#section-table)
- [Critical Windows DLLs](#critical-windows-dlls)
- [Malware API Cheatsheet](#malware-api-cheatsheet)
  - [By Malware Type](#by-malware-type)
  - [By Function Category](#by-function-category)
- [Analysis Tips](#analysis-tips)
- [Common Packers](#common-packers)

## PE File Structure

### DOS Header
| Field | Importance | Notes |
|-------|------------|-------|
| **e_magic** ("MZ") | ⭐⭐⭐⭐⭐ | First bytes of any PE file. Malware may corrupt this to evade detection. |
| **e_lfanew** | ⭐⭐⭐⭐ | Offset to PE header. Abnormal values may indicate packing. |

### NT Headers
#### File Header
| Field | Importance | Notes |
|-------|------------|-------|
| **Machine** | ⭐⭐⭐⭐ | Target architecture (x86=0x14C, x64=0x8664) |
| **NumberOfSections** | ⭐⭐⭐⭐ | >10 sections suggests packing |
| **Characteristics** | ⭐⭐⭐⭐⭐ | Flags like IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE |

#### Optional Header
| Field | Importance | Notes |
|-------|------------|-------|
| **AddressOfEntryPoint** | ⭐⭐⭐⭐⭐ | Where execution begins. Outside .text? Probably packed. |
| **ImageBase** | ⭐⭐⭐⭐ | Default: 0x400000 (EXE), 0x10000000 (DLL) |
| **Subsystem** | ⭐⭐⭐ | 2=GUI (hides console), 3=Console |
| **DataDirectories** | ⭐⭐⭐⭐⭐ | Import/Export tables critical for analysis |

### Section Table
| Field | Importance | Notes |
|-------|------------|-------|
| **Characteristics** | ⭐⭐⭐⭐⭐ | .text with WRITE or .data with EXECUTE = malicious |
| **VirtualSize** | ⭐⭐⭐ | Much larger than SizeOfRawData? Likely packed |

## Critical Windows DLLs

| DLL | Key Functions | Malware Usage |
|------|----------------|----------------|
| **kernel32.dll** | CreateProcess, VirtualAlloc | Process injection, memory allocation |
| **ntdll.dll** | NtCreateFile, NtAllocateVirtualMemory | Low-level operations avoiding hooks |
| **advapi32.dll** | RegSetValueEx, CryptEncrypt | Persistence, ransomware encryption |
| **ws2_32.dll** | socket, connect | C2 communication |

## Malware API Cheatsheet

### By Malware Type
1. **Viruses**
   - `CreateFileA`, `WriteFile` - File infection
   - `WriteProcessMemory` - Code injection

2. **Trojans**
   - `RegOpenKeyExA` - Registry persistence
   - `URLDownloadToFileA` - Download payloads

3. **Ransomware**
   - `CryptGenKey`, `CryptEncrypt` - File encryption
   - `DeleteFileA` - Remove original files

### By Function Category
| Category | Key APIs |
|----------|----------|
| **Process Injection** | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| **Persistence** | RegCreateKeyEx, CreateService |
| **Evasion** | IsDebuggerPresent, NtQuerySystemInformation |

## Analysis Tips
1. **Import Table Red Flags**
   - Rare APIs like `URLDownloadToFileA` in non-browser software
   - Suspicious combos: `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`

2. **Section Anomalies**
   - Sections with both WRITE and EXECUTE
   - Unusually named sections (e.g., "UPX0", ".axc")

3. **Entry Point Checks**
   - EP in last section (common in packed malware)
   - EP pointing to zero-filled memory (runtime unpacking)

## Common Packers
- UPX
- Themida
- VMProtect
- ASPack
- MPRESS

> **Note:** This reference is designed for malware analysts, reverse engineers, and forensic investigators. Always analyze suspicious files in a sandboxed environment.
