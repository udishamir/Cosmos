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

typedef enum _CAPTURE_SOURCE {
    CAPTURE_SOURCE_NONE = 0,
    CAPTURE_SOURCE_CREATE_NOTIFY,
    CAPTURE_SOURCE_IMAGE_LOAD,
    CAPTURE_SOURCE_LOCATE_FALLBACK
} CAPTURE_SOURCE;

typedef struct _PROCESS_ENTRY {
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG_PTR ImageBase;
    SIZE_T ImageSize;
    BOOLEAN ImageCaptured;
    BOOLEAN Terminated;
    UNICODE_STRING ImageFileName;
    struct _PROCESS_ENTRY* Next;
    CAPTURE_SOURCE CaptureSource;
} PROCESS_ENTRY;

VOID InitProcessTable();
VOID CleanupProcessTable();
VOID CosmosDumpTrackedProcesses();
VOID TrackProcess(
    HANDLE pid,
    HANDLE ppid,
    ULONG_PTR ImageBase,
    SIZE_T ImageSize,
    PUNICODE_STRING ImageName,
    BOOLEAN Create,
    CAPTURE_SOURCE Source
);

NTSTATUS CosmosCopyTrackedProcessesToUser(
    COSMOS_PROC_INFO* UserBuffer,
    ULONG MaxCount,
    ULONG* ReturnedCount
);


PROCESS_ENTRY* CosmosLookupProcessByPid(HANDLE pid);