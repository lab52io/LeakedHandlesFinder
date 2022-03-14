#include <iostream>
#include <windows.h>
#include <tlhelp32.h>


int GetProcessByName(PCWSTR name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (wcscmp(process.szExeFile, name) == 0)
			{
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return NULL;
}

int main()
{
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);


	int pidWinlogon = GetProcessByName(L"winlogon.exe");
	if (pidWinlogon == NULL) {
		printf("[-] Can't open Winlogon, run as system");
	}

	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS,
		TRUE,
		pidWinlogon
	);

	int pidExplorer = GetProcessByName(L"explorer.exe");
	if (pidExplorer == NULL) {
		printf("[-] Can't open Explorer");
	}

	// Call OpenProcess(), print return code and error code
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, pidExplorer);
	if (GetLastError() == NULL)
		printf("[+] OpenProcess() success!\n");
	else
	{
		printf("[-] OpenProcess() Return Code: %i\n", processHandle);
		printf("[-] OpenProcess() Error: %i\n", GetLastError());
	}

	// Call OpenProcessToken(), print return code and error code
	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if (GetLastError() == NULL)
		printf("[+] OpenProcessToken() success!\n");
	else
	{
		printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
		printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
	}

	// Call DuplicateTokenEx(), print return code and error code
	BOOL duplicateToken = DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	if (GetLastError() == NULL)
		printf("[+] DuplicateTokenEx() success!\n");
	else
	{
		printf("[-] DuplicateTokenEx() Return Code: %i\n", duplicateToken);
		printf("[-] DupicateTokenEx() Error: %i\n", GetLastError());
	}

	CloseHandle(processHandle);

	// Call CreateProcessWithTokenW(), print return code and error code
	//BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\notepad.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);
	BOOL createProcess = CreateProcessAsUserW(
		duplicateTokenHandle,
		L"C:\\Windows\\system32\\SndVol.exe",
		NULL,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInformation
	);
	
	if (GetLastError() == NULL)
		printf("[+] Process spawned!\n");
	else
	{
		printf("[-] CreateProcessWithTokenW Return Code: %i\n", createProcess);
		printf("[-] CreateProcessWithTokenW Error: %i\n", GetLastError());
	}




	getchar();
}
