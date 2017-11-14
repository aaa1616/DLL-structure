#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <atlbase.h>
#include <atlconv.h>

#pragma pack(push,1)
typedef struct tagRemoteThreadParams
{
    int Param1;
    int Param2;
} RemoteThreadParams, *PRemoteThreadParams;
#pragma pack(pop)

DWORD GetProcessIDByName(const char* pName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        return NULL;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		USES_CONVERSION;
        if (strcmp(W2A(pe.szExeFile), pName) == 0) {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
        //printf("%-6d %ws\n", pe.th32ProcessID, pe.szExeFile);
    }
    CloseHandle(hSnapshot);
    return 0;
}

void UninjectDLL(DWORD processid, HANDLE hRemoteProcess, LPCWSTR dll)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processid);  
    MODULEENTRY32 ME32 = {0};  
    ME32.dwSize = sizeof(MODULEENTRY32);  
    BOOL isNext = Module32First(hSnap,&ME32);  
    BOOL flag = FALSE;  
    while(isNext)  {  
        if(wcscmp(ME32.szModule, dll)==0)  {  
            flag = TRUE;  
            break;  
        }  
        isNext = Module32Next(hSnap,&ME32);  
    }

	if (flag == FALSE) {
		printf("Cannot find the DLL\n");
		return ;
	}
	CloseHandle(hSnap);

	LPTHREAD_START_ROUTINE pFun = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("kernel32.dll")),"FreeLibrary");
	HANDLE hThread;
    if ((hThread = CreateRemoteThread(hRemoteProcess, NULL, 0, pFun, ME32.hModule, 0, NULL)) == NULL) {
       printf("CreateRemoteThread error : FreeLibrary\n");
       return ;
    }else {
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread); 
		CloseHandle(hRemoteProcess);
		printf("Uninject is done\n");
    }
}

int main()
{
	DWORD processid;
	HANDLE hRemoteProcess;
	HMODULE hdll;
	char *processname = "CallDLL.exe";
	//LPCWSTR filename = _T("D:\\Documents\\visual studio 2015\\Projects\\Test\\Debug\\CreateDLL.dll");
	LPCWSTR inject_filename = _T("D:\\Documents\\visual studio 2015\\Projects\\Test\\Debug\\CreateInjectDLL.dll");
	//LPCSTR funcname = "add";
	LPCSTR inject_funcname = "inject_add";
	RemoteThreadParams params;

	processid = GetProcessIDByName(processname);
	if (processid == 0) {
		printf("Cannot Find %s", processname);
	}
	if ((hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processid)) == NULL) {
		printf("OpenProcess error\n");
		exit(EXIT_FAILURE);
	}
	//Get LoadLibrary address in dll
    LPTHREAD_START_ROUTINE pFun= (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
    if (pFun == NULL) {
       printf("GetProcAddress error : LoadLibrary\n");
       return -5;
    }else {
       printf("LoadLibrary's Address is 0x%x\n", pFun);
    }

	hdll = LoadLibrary(inject_filename);
	if (hdll == NULL) {
		printf("Cannot load library : %ws\n", inject_filename);
		exit(EXIT_FAILURE);
	}

	LPVOID pParams = VirtualAllocEx(hRemoteProcess, NULL, (wcslen(inject_filename) + 1) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
    if (pParams == NULL) {
       printf("VirtualAllocEx error : dll filename\n");
       return -3;
    }

	DWORD Size;
	if (WriteProcessMemory(hRemoteProcess, pParams, inject_filename, (wcslen(inject_filename) + 1) * sizeof(WCHAR), &Size) == NULL) {
       printf("WriteProcessMemory error : dll filename\n");
       return -4;
    }
    printf("WriteRrmoyrProcess Size is %d\n", Size);

    DWORD dwThreadId;
    HANDLE hThread;
    if ((hThread = CreateRemoteThread(hRemoteProcess, NULL, 0, pFun, pParams, 0, &dwThreadId)) == NULL) {
       printf("CreateRemoteThread error : LoadLibrary\n");
       return -6;
    }else {
		WaitForSingleObject(hThread, INFINITE);
		VirtualFreeEx(hRemoteProcess, pParams, (wcslen(inject_filename) + 1) * sizeof(WCHAR), MEM_RELEASE);  
		printf("dwThreadId is %d\n", dwThreadId);
		printf("Inject is done\n");
    }

	//Get inject_add address in dll
    pFun = (LPTHREAD_START_ROUTINE)GetProcAddress(hdll, "inject_add");
    if (pFun == NULL) {
       printf("GetProcAddress error\n");
       return -5;
    }else {
       printf("inject_add's Address is 0x%x\n", pFun);
    }

	pParams = VirtualAllocEx(hRemoteProcess, NULL, sizeof(RemoteThreadParams), MEM_COMMIT, PAGE_READWRITE);
    if (pParams == NULL) {
       printf("VirtualAllocEx error : parameters\n");
       return -3;
    }
	params.Param1 = 10;
	params.Param2 = 20;
	if (WriteProcessMemory(hRemoteProcess, pParams, &params, sizeof(RemoteThreadParams), &Size) == NULL) {
       printf("WriteProcessMemory error : parameters\n");
       return -4;
    }
    printf("WriteRrmoyrProcess Size is %d\n", Size);
	if ((hThread = CreateRemoteThread(hRemoteProcess, NULL, 0, pFun, pParams, 0, &dwThreadId)) == NULL) {
		printf("Call inject function %s Failure\n", inject_funcname);
		return -5;
	} else {
		WaitForSingleObject(hThread, INFINITE);
		VirtualFreeEx(hRemoteProcess, pParams, sizeof(RemoteThreadParams), MEM_RELEASE);  
		CloseHandle(hThread); 
		printf("Call inject function %s Success\n", inject_funcname);
	}
	UninjectDLL(processid, hRemoteProcess, _T("CreateInjectDLL.dll"));
	UninjectDLL(processid, hRemoteProcess, _T("CreateInjectDLL.dll"));

	return 0;
}
