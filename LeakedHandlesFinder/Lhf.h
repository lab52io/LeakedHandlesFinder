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

#pragma once
#include <windows.h>

#define PTR_STR_LEN 25
#define MAXIMUM_FILENAME_LENGTH 256
#define STR_EXPLOITABLE _T("Exploitable Handle")
#define STR_EXPLOITABLE_BUT_NOT_SUPPORTED _T("Handle exploitable but not yet supported")
#define STR_RESEARCH_NEEDED _T("Interesting, further investigation is needed")
#define STR_NON_EXPLOITABLE _T("Handle is not exploitable")

enum IntegrityLevel {
    UNTRUSTED_INTEGRITY,
    LOW_INTEGRITY,
    MEDIUM_INTEGRITY,
    HIGH_INTEGRITY,
    SYSTEM_INTEGRITY,
    PPL_INTEGRITY,
    INTEGRITY_UNKNOWN,
};

enum Exploitability {
    EXPLOITABLE,
    EXPLOITABLE_BUT_NOT_SUPPORTED,
    RESEARCH_NEEDED,
    NON_EXPLOITABLE
};

typedef struct _LHF_HANDLE_DESCRIPTION
{
    ULONG_PTR Handle;
    ULONG GrantedAccess;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR ParentUniqueProcessId;
    ULONG_PTR RemoteProcessId;
    IntegrityLevel ParentProcessIntegrity;
    IntegrityLevel ProcessIntegrity;
    USHORT ObjectTypeIndex;
    LPTSTR TypeString;
    LPTSTR Name;
    LPTSTR GrantedAccessString;
    LPTSTR ParentProcessIntegrityString;
    LPTSTR ProcessIntegrityString;
    Exploitability HExploitability;

} LHF_HANDLE_DESCRIPTION, * LHF_PHANDLE_DESCRIPTION;

typedef struct _LHF_HANDLE_DESCRIPTION_LIST
{
    ULONG NumberOfLhfHandles = 0;
    LHF_PHANDLE_DESCRIPTION Handles;

} LHF_HANDLE_DESCRIPTION_LIST, * LHF_PHANDLE_DESCRIPTION_LIST;

typedef struct _CONF
{
    BOOL AutoPwn;
    BOOL ResearchMode;
    BOOL SingleLine;
    LPTSTR OutputFile;
    LPTSTR SuspendType;
    LPTSTR ExploitCommand;
    BOOL HideUnnamedHandles;

} CONFIG;


struct GetObjectNameThreadStructParams
{
    HANDLE hObject;
    PVOID objectNameInfo;
};