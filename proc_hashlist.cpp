/*
	Cosmos XDR Driver

     20242025 Udi Shamir. All Rights Reserved.
    Unauthorized copying of this file, via any medium, is strictly prohibited.
    Proprietary and confidential.

    Author: Udi Shamir
*/

#include <ntifs.h>
#include "proc_hashlist.h"
#include "cosmos_ioctl.h"

/*
    Using 1031 prime number with modulus to reduce collisions.

	Using 1031 will help to reduce collision and distribute the data more evenly across the hash table. For short lived
    driver this is not really big of a deal but since this is an XDR driver it will be long lived, as long as the system is up.

    For small process table it is mostly insignificant.

    NOTE: collisions can not be avoided completely but it will be reduced comparing to using power of 2 with large process table.
*/
#define HASH_BUCKETS 1031
#define COSMOS_TAG 'XSMC' // This is Cosmos Marker For The Memory Management 
#define MAX_USER_PROCESSES 1024 // For IOCTL

static PROCESS_ENTRY* g_HashTable[HASH_BUCKETS];
static FAST_MUTEX g_HashTableLock;

/*
    Generating key for the hash table, with less collisions 
    Should be compatible with both x86_64 and x86
*/
static ULONG HashPid(HANDLE pid) {
    return ((ULONG_PTR)pid) % HASH_BUCKETS;
}

// Initializing The Process Table 
VOID InitProcessTable() {
    RtlZeroMemory(g_HashTable, sizeof(g_HashTable));
    // Locking the table 
    ExInitializeFastMutex(&g_HashTableLock);
}

// Cleaning The Process Table
VOID CleanupProcessTable() {
    // Locking the table
    ExAcquireFastMutex(&g_HashTableLock);

    for (int i = 0; i < HASH_BUCKETS; ++i) {
        PROCESS_ENTRY* entry = g_HashTable[i];
        while (entry) {
            PROCESS_ENTRY* next = entry->Next;
            if (entry->ImageFileName.Buffer) {
                // Releasing memory allocated for ImageFileName from PsSetLoadImageNotifyRoutine
                ExFreePoolWithTag(entry->ImageFileName.Buffer, COSMOS_TAG);
            }
			// No ImageFileName allocated, release TAGGED (XSMC) memory
            ExFreePoolWithTag(entry, COSMOS_TAG);
            entry = next;
        }
        g_HashTable[i] = NULL;
    }

    ExReleaseFastMutex(&g_HashTableLock);
}

VOID TrackProcess(
    HANDLE pid,
    HANDLE ppid,
    ULONG_PTR ImageBase,
    SIZE_T ImageSize,
    PUNICODE_STRING ImageName,
    BOOLEAN Create,
    CAPTURE_SOURCE Source
) {
    ULONG idx = HashPid(pid);

    ExAcquireFastMutex(&g_HashTableLock);

    PROCESS_ENTRY* curr = g_HashTable[idx];
    while (curr) {
        if (curr->ProcessId == pid) {
            break;
        }
        curr = curr->Next;
    }

    if (!Create && curr == NULL) {
        ExReleaseFastMutex(&g_HashTableLock);
        return;
    }

    if (Create && !curr) {
        curr = (PROCESS_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_ENTRY), COSMOS_TAG);
        if (!curr) {
            ExReleaseFastMutex(&g_HashTableLock);
            return;
        }

        RtlZeroMemory(curr, sizeof(PROCESS_ENTRY));

        curr->ProcessId = pid;
        curr->ParentProcessId = ppid;
        curr->ImageBase = ImageBase;
        curr->ImageSize = ImageSize;
        curr->ImageCaptured = FALSE;
        curr->Terminated = FALSE;
        curr->CaptureSource = Source;
        curr->Next = g_HashTable[idx];
        g_HashTable[idx] = curr;
    }

    // Make sure to not overwrite existing base/size unless both are zero
    if (ImageBase && curr->ImageBase == 0) {
        curr->ImageBase = ImageBase;
    }

    if (ImageSize && curr->ImageSize == 0) {
        curr->ImageSize = ImageSize;
    }

    if (ImageName && ImageName->Length > 0 && ImageName->Buffer != NULL &&
        (!curr->ImageCaptured || curr->ImageFileName.Buffer == NULL)) {

        SIZE_T allocSize = ImageName->Length + sizeof(WCHAR);
        PWSTR buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, COSMOS_TAG);
        if (buffer) {
            COSMOS_LOG("TrackProcess: Copying image for PID %llu | Source=%d | ImgName=%wZ",
                (ULONG64)pid, Source, ImageName);

            RtlCopyMemory(buffer, ImageName->Buffer, ImageName->Length);
            buffer[ImageName->Length / sizeof(WCHAR)] = L'\0';

            curr->ImageFileName.Buffer = buffer;
            curr->ImageFileName.Length = ImageName->Length;
            curr->ImageFileName.MaximumLength = (USHORT)allocSize;
            curr->ImageCaptured = TRUE;
            curr->CaptureSource = Source;
        }
        else {
            COSMOS_LOG("TrackProcess: Allocation failed for PID %llu | Source=%d", (ULONG64)pid, Source);
        }
    }
    else if (!ImageName || ImageName->Length == 0 || ImageName->Buffer == NULL) {
        COSMOS_LOG("TrackProcess: No image provided for PID %llu | Source=%d", (ULONG64)pid, Source);
    }

    if (!Create && curr) {
        curr->Terminated = TRUE;
    }

    ExReleaseFastMutex(&g_HashTableLock);
}


 
PROCESS_ENTRY* CosmosLookupProcessByPid(HANDLE pid) {  
   ULONG idx = HashPid(pid);  
   ExAcquireFastMutex(&g_HashTableLock);  

   PROCESS_ENTRY* curr = g_HashTable[idx];  
   while (curr) {  
       if (curr->ProcessId == pid) {  
           ExReleaseFastMutex(&g_HashTableLock);  
           return curr;  
       }  
       curr = curr->Next;  
   }  

   ExReleaseFastMutex(&g_HashTableLock);  
   return NULL;  
}

// Being called from IOCTL only
VOID CosmosDumpTrackedProcesses() {

    // Before trying copy hash table content to user space
    ExAcquireFastMutex(&g_HashTableLock);

    // Tracking max user processes
    int count = 0;

    // Making sure we get all process hash table && not exceeding max user process entries
    for (int i = 0; i < HASH_BUCKETS && count < MAX_USER_PROCESSES; ++i) {
        PROCESS_ENTRY* entry = g_HashTable[i];
        while (entry && count < MAX_USER_PROCESSES) {
            if (entry->ImageCaptured && entry->ImageFileName.Buffer) {
                COSMOS_LOG("Cosmos: PID=%llu | PPID=%llu | Base=0x%p | Size=0x%Ix | Image=%wZ\n",
                    (ULONG64)entry->ProcessId,
                    (ULONG64)entry->ParentProcessId,
                    (PVOID)entry->ImageBase,
                    entry->ImageSize,
                    &entry->ImageFileName);
            }
            else {
                COSMOS_LOG("Cosmos: PID=%llu | PPID=%llu | Base=0x%p | Size=0x%Ix | Image=Not Available\n",
                    (ULONG64)entry->ProcessId,
                    (ULONG64)entry->ParentProcessId,
                    (PVOID)entry->ImageBase,
                    entry->ImageSize);
            }

            entry = entry->Next;
            ++count;
        }
    }

    ExReleaseFastMutex(&g_HashTableLock);
}

// Copying tracked processes into user buffer
NTSTATUS CosmosCopyTrackedProcessesToUser(
    COSMOS_PROC_INFO* UserBuffer,
    ULONG MaxCount,
    ULONG* ReturnedCount
) {
    ULONG copied = 0;

    if (!UserBuffer || !ReturnedCount || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_HashTableLock);

    for (int i = 0; i < HASH_BUCKETS && copied < MaxCount; ++i) {
        PROCESS_ENTRY* entry = g_HashTable[i];
        while (entry && copied < MaxCount) {
            RtlZeroMemory(&UserBuffer[copied], sizeof(COSMOS_PROC_INFO));

            UserBuffer[copied].Pid = PtrToUlong(entry->ProcessId);
            UserBuffer[copied].Ppid = PtrToUlong(entry->ParentProcessId);
            UserBuffer[copied].ImageBase = (ULONG_PTR)entry->ImageBase;
            UserBuffer[copied].ImageSize = (SIZE_T)entry->ImageSize;
            UserBuffer[copied].CaptureSource = (ULONG)entry->CaptureSource;

            if (entry->ImageCaptured && entry->ImageFileName.Buffer) {
                USHORT len = entry->ImageFileName.Length / sizeof(WCHAR);

                if (len >= COSMOS_MAX_PATH) {
                    len = COSMOS_MAX_PATH - 1;
                }

                RtlCopyMemory(UserBuffer[copied].ImageFileName,
                    entry->ImageFileName.Buffer,
                    len * sizeof(WCHAR));
                UserBuffer[copied].ImageFileName[len] = L'\0';
            }
            else {
                // Still return struct with null image name
                UserBuffer[copied].ImageFileName[0] = L'\0';
            }

            COSMOS_LOG("CopyToUser: PID=%lu | Base=0x%p | Source=%lu | Captured=%d",
                UserBuffer[copied].Pid,
                (PVOID)UserBuffer[copied].ImageBase,
                UserBuffer[copied].CaptureSource,
                entry->ImageCaptured);

            ++copied;
            entry = entry->Next;
        }
    }

    *ReturnedCount = copied;
    ExReleaseFastMutex(&g_HashTableLock);

    COSMOS_LOG("Cosmos: Returned %lu | Entries (max %lu)", copied, MaxCount);
    return STATUS_SUCCESS;
}