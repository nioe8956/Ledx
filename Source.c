#include "windows.h"
#include "stdio.h"
#include "stdlib.h"
#include "tlhelp32.h"
#include "TCHAR.H"
#include "string.h"

#pragma warning(disable : 4996)
#define DEF_PROC_NAME ("powershell.exe")

char* Adr_cmdline, *Adr_copy, *Adr_ori;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE OP_BP = 0xCC, OP_Ret = 0xC3;
DWORD dwPID = 0xFFFFFFFF;
LPVOID Adr_original = NULL;
DWORD WINAPI FindProcessID(LPCSTR szProcname);
void DebugLoop();
int main()
{

	DWORD dwThrdParam;
	DWORD dwThreadId;

	HANDLE hThread = CreateThread(NULL, 0, FindProcessID, &dwThrdParam, 0, &dwThreadId);

	dwPID = FindProcessID(DEF_PROC_NAME);

	if (!DebugActiveProcess(dwPID))
	{

		return 1;

	}
	DebugLoop();
}

void DebugLoop()
{

	DEBUG_EVENT de;
	DWORD dwContinueStatus;

	while (WaitForDebugEvent(&de, INFINITE))
	{
		dwContinueStatus = DBG_CONTINUE;

		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			OnCreateProcessDebugEvent(&de);

		}
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
		{
			if (OnExceptionDebugEvent(&de))
				continue;


		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			break;
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}


BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	DWORD dwAddrOfBuffer;

	Adr_cmdline = GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetCurrentProcess");
	Adr_original = GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetCurrentProcess");

	Adr_copy = Adr_cmdline - 6;

	VirtualProtect(Adr_copy, 10, PAGE_EXECUTE_READWRITE, &dwAddrOfBuffer);

	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));

	ReadProcessMemory(g_cpdi.hProcess, Adr_copy, &OP_Ret, 1, NULL);
	WriteProcessMemory(g_cpdi.hProcess, Adr_copy, &OP_BP, 1, NULL); 

	printf("\n[ Install BreakPoint ]  Address : 0x%p OPCODE : 0xC3 -> 0xCC Patched\n", Adr_copy);


	return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	CONTEXT ctx;
	DWORD dwNumOfBytesToCompare;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
	char* str = NULL, buffer = NULL, result = NULL;
	SIZE_T bytesRead;

	if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		if (Adr_copy == per->ExceptionAddress)
		{

			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(g_cpdi.hThread, &ctx);
			WriteProcessMemory(g_cpdi.hProcess, &Adr_copy, &OP_Ret, sizeof(BYTE), NULL);
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Eax), &buffer, 1000, &bytesRead);

			Adr_ori = Adr_copy - 5;

			wprintf(L"Command Line : %s\n", &buffer);

			if ((str = wcsstr(&buffer, L"$env")) == NULL)
			{
				MessageBox(NULL, TEXT("Normal"), TEXT("Alert"), MB_OK | MB_TOPMOST);
				return TRUE;
			}
			else
			{
				MessageBox(NULL, TEXT("malicious String : '$' Detected"), TEXT("Warning"), MB_OK | MB_TOPMOST);
				exit(1);

			}

			if ((str = wcsstr(&buffer, L"iex")) == NULL) 
			{
				MessageBox(NULL, TEXT("Normal"), TEXT("Alert"), MB_OK | MB_TOPMOST);
				return TRUE;
			}
			else
			{
				MessageBox(NULL, TEXT("malicious String : 'iex' Detected"), TEXT("Warning"), MB_OK | MB_TOPMOST);
				exit(1);

			}

			ctx.Eip = (DWORD)Adr_ori;
			SetThreadContext(g_cpdi.hThread, &ctx);

			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
			Sleep(0);

			return TRUE;
		}

	}

	return FALSE;

}

DWORD WINAPI FindProcessID(LPCSTR szProcname)
{
	while (1) {

		HANDLE hSnapShot = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 pe;
		szProcname = "powershell.exe";

		pe.dwSize = sizeof(PROCESSENTRY32);
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

		Process32First(hSnapShot, &pe);
		do
		{
			if (!strcmp(szProcname, pe.szExeFile))
			{
				dwPID = pe.th32ProcessID;
				goto end;
			}

		} while (Process32Next(hSnapShot, &pe));

		WaitForSingleObject(hSnapShot, INFINITE);
	}
end:
	return dwPID;
}
