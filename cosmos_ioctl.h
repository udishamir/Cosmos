/*
	 Cosmos XDR Driver

    © 2024–2025 Udi Shamir. All Rights Reserved.
    Unauthorized copying of this file, via any medium, is strictly prohibited.
    Proprietary and confidential.

    Author: Udi Shamir
*/

#pragma once

#define IOCTL_COSMOS_DUMP_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define COSMOS_MAX_PATH 260

typedef struct _COSMOS_PROC_INFO {
    ULONG_PTR Pid;
    ULONG_PTR Ppid;
    ULONG_PTR ImageBase;
    SIZE_T  ImageSize;
    WCHAR ImageFileName[COSMOS_MAX_PATH]; // null-terminated
} COSMOS_PROC_INFO;
