// ConsoleApplication1.cpp : Defines the exported functions for the DLL application.
//

//#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <ntstatus.h>

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING; 
 
typedef struct _OBJECT_NAME_INFORMATION { 
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
 
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolSession = 32,
    PagedPoolSession,
    NonPagedPoolMustSucceedSession,
    DontUseThisTypeSession,
    NonPagedPoolCacheAlignedSession,
    PagedPoolCacheAlignedSession,
    NonPagedPoolCacheAlignedMustSSession
} POOL_TYPE;
 
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16,
} SYSTEM_INFORMATION_CLASS;
 
typedef struct  _SYSTEM_HANDLE_INFORMATION {
    ULONG       ProcessId;
    UCHAR       ObjectTypeNumber;
    UCHAR       Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION,  *PSYSTEM_HANDLE_INFORMATION;
 
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;
 
typedef struct  _OBJECT_BASIC_INFORMATION {
    ULONG           Attributes;
    ACCESS_MASK     GrantedAccess;
    ULONG           HandleCount;
    ULONG           PointerCount;
    ULONG           PagedPoolUsage;
    ULONG           NonPagedPoolUsage;
    ULONG           Reserved    [   3];
    ULONG           NameInformationLength;
    ULONG           TypeInformationLength;
    ULONG           SecurityDescriptorLength;
    LARGE_INTEGER   CreateTime;
} OBJECT_BASIC_INFORMATION,   *POBJECT_BASIC_INFORMATION;
 
typedef struct  _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING  Name;
    ULONG           ObjectCount;
    ULONG           HandleCount;
    ULONG           Reserved1   [   4];
    ULONG           PeakObjectCount;
    ULONG           PeakHandleCount;
    ULONG           Reserved2   [   4];
    ULONG           InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG           ValidAccess;
    UCHAR           Unknown;
    BOOLEAN         MaintainHandleDatabase;
    POOL_TYPE        PoolType;
    ULONG           PagedPoolUsage;
    ULONG           NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION,    *POBJECT_TYPE_INFORMATION;
 
typedef NTSTATUS (_stdcall *PZWQUERYSYSTEMINFORMATION) (
    SYSTEM_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG
);
 
typedef NTSTATUS (_stdcall *PZWDUPLICATEOBJECT) (
    HANDLE,
    HANDLE,
    HANDLE,
    PHANDLE,
    ACCESS_MASK,
    ULONG,
    ULONG
);
 
typedef NTSTATUS (_stdcall *PZWQUERYOBJECT) (
    HANDLE,
    OBJECT_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG
);
 
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define DUPLICATE_SAME_ATTRIBUTES   0x00000004 
#define NtCurrentProcess() ( (HANDLE) -1 )
 
///////////////////////////////////////////////////////////////////////
 
BOOL EnablePrivilege(LPCWSTR name)
{
    TOKEN_PRIVILEGES priv = {1, {0, 0, SE_PRIVILEGE_ENABLED}};
    LookupPrivilegeValue(0, name, &priv.Privileges[0].Luid);
 
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
 
    AdjustTokenPrivileges(hToken, FALSE, &priv, sizeof priv, 0, 0);
    BOOL rv = GetLastError() == ERROR_SUCCESS;
 
    CloseHandle(hToken);
    return rv;
}
// Test method for listing all mutex per process.
void listhandle(DWORD pid)
{
    // provide your process id here.
    //ULONG pid = GetCurrentProcessId();
 
    // adjuat process privileges.
    EnablePrivilege(SE_DEBUG_NAME);
 
    // load dll into memory.
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    if (!hNtDll) return ;
 
    // initial undocumented apis.
    PZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = 
        (PZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtDll, "ZwQuerySystemInformation");
    PZWDUPLICATEOBJECT ZwDuplicateObject = 
        (PZWDUPLICATEOBJECT)GetProcAddress(hNtDll, "ZwDuplicateObject");
    PZWQUERYOBJECT ZwQueryObject = 
        (PZWQUERYOBJECT)GetProcAddress(hNtDll, "ZwQueryObject");
 
    // get system info, list all process info.
    ULONG n = 0x1000;
    PULONG p = new ULONG[n];
	while (ZwQuerySystemInformation(SystemHandleInformation, p, n * sizeof *p, &n) == STATUS_INFO_LENGTH_MISMATCH) {
		printf("Return length : %d\n", n);
		delete[] p, p = new ULONG[n];
	}
    PSYSTEM_HANDLE_INFORMATION h = PSYSTEM_HANDLE_INFORMATION(p + 1);
 
    // try to find target process by matching process id.
    for (ULONG i = 0; i < *p; i++) 
    {
        if (h[i].ProcessId == pid)
        {    
            HANDLE hObject;
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
 
            if (ZwDuplicateObject(hProcess, HANDLE(h[i].Handle), GetCurrentProcess(), 
                    &hObject, 0, 0, DUPLICATE_SAME_ATTRIBUTES)!= STATUS_SUCCESS) 
                continue;
 
            // print basic info of this process.
            OBJECT_BASIC_INFORMATION obi;
            ZwQueryObject(hObject, ObjectBasicInformation, &obi, sizeof obi, &n);
            printf("%p %ld %04hx %6lx %2x %3lx %3ld ",
                   h[i].Object, h[i].ProcessId, h[i].Handle, h[i].GrantedAccess,
                   int(h[i].Flags), obi.Attributes,
                   obi.HandleCount - 1);
 
            // print type info of this process.
            n = obi.TypeInformationLength + 2;
            POBJECT_TYPE_INFORMATION oti = POBJECT_TYPE_INFORMATION(new CHAR[n]);
            ZwQueryObject(hObject, ObjectTypeInformation, oti, n, &n);
            printf("%-14.*ws ", oti[0].Name.Length / 2, oti[0].Name.Buffer);
 
            // print name info of this process.
            n = obi.NameInformationLength == 0
                ? MAX_PATH * sizeof (WCHAR) : obi.NameInformationLength;
            POBJECT_NAME_INFORMATION oni = POBJECT_NAME_INFORMATION(new CHAR[n]);
            NTSTATUS rv = ZwQueryObject(hObject, ObjectNameInformation, oni, n, &n);
			if (NT_SUCCESS(rv)) {
				printf("%.*ws", oni[0].Name.Length / 2, oni[0].Name.Buffer);
				if (oni[0].Name.Length != 0 && wcscmp(oni[0].Name.Buffer, L"\\Sessions\\1\\BaseNamedObjects\\singleton") == 0) {
					printf("try to close it!");
					for (int j = 0; j < obi.HandleCount; j++) {
						CloseHandle(HANDLE(h[i].Handle));
					}
				}
			}
 
            // close handles.
            printf("\n");
            CloseHandle(hObject);
            CloseHandle(hProcess);              
        }
    }
    delete [] p;
}

#pragma pack(push,1)
typedef struct tagRemoteThreadParams
{
    int Param1;
    int Param2;
} RemoteThreadParams, *PRemoteThreadParams;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void closehandle(PRemoteThreadParams params)
{
	DWORD pid = GetCurrentProcessId();
	listhandle(pid);
}
#ifdef __cplusplus
}
#endif
