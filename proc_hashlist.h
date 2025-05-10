/*
	Cosmos XDR Driver

    © 2024–2025 Udi Shamir. All Rights Reserved.
    Unauthorized copying of this file, via any medium, is strictly prohibited.
    Proprietary and confidential.

    Author: Udi Shamir
*/

#pragma once

// Comment out for production builds
#define COSMOS_DEBUG_LOGGING 0

#if COSMOS_DEBUG_LOGGING
#define COSMOS_LOG(...) DbgPrint(__VA_ARGS__)
#else
#define COSMOS_LOG(...) do {} while (0)
#endif

#include "cosmos.h"
#include "cosmos_ioctl.h"

#define COSMOS_TAG 'XSMC'


typedef struct _PROCESS_ENTRY {
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG_PTR ImageBase;
    SIZE_T ImageSize;
    UNICODE_STRING ImageFileName;
    BOOLEAN ImageCaptured;
    BOOLEAN Terminated;
    struct _PROCESS_ENTRY* Next;
} PROCESS_ENTRY;

VOID InitProcessTable();
VOID CleanupProcessTable();
VOID CosmosDumpTrackedProcesses();
VOID TrackProcess(HANDLE pid, HANDLE ppid, ULONG_PTR ImageBase, SIZE_T ImageSize, PUNICODE_STRING ImageName, BOOLEAN Create);

NTSTATUS CosmosCopyTrackedProcessesToUser(
    COSMOS_PROC_INFO* UserBuffer,
    ULONG MaxCount,
    ULONG* ReturnedCount
);

PROCESS_ENTRY* CosmosLookupProcessByPid(HANDLE pid);