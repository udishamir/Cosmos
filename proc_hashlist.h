#pragma once
// process_hashlist.h
#pragma once

#include "cosmos.h"
#include "cosmos_ioctl.h"

#define COSMOS_TAG 'XSMC'


typedef struct _PROCESS_ENTRY {
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    UNICODE_STRING ImageFileName;
    BOOLEAN ImageCaptured;
    BOOLEAN Terminated;
    struct _PROCESS_ENTRY* Next;
} PROCESS_ENTRY;

VOID InitProcessTable();
VOID CleanupProcessTable();
VOID CosmosDumpTrackedProcesses();
VOID TrackProcess(HANDLE pid, HANDLE ppid, PUNICODE_STRING ImageName, BOOLEAN Create);

NTSTATUS CosmosCopyTrackedProcessesToUser(
    COSMOS_PROC_INFO* UserBuffer,
    ULONG MaxCount,
    ULONG* ReturnedCount
);

PROCESS_ENTRY* CosmosLookupProcessByPid(HANDLE pid);
