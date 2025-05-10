/*
    Since we lack the option of utilizing extended (Ex) functions such as 
	PsSetCreateProcessNotifyRoutineEx and PsSetCreateThreadNotifyRoutineEx, i need to create enhanced 
	process / thread tracking combining data from PsSetLoadImageNotifyRoutine, this limitation suppose 
	to be lifted once i can sign the driver with Microsoft certificates.

	The process hash table is a simple hash table that stores information about processes.
	It uses a linked list to handle collisions. The hash function is based on the process ID.
	The table is protected by a fast mutex to ensure thread safety.
*/

#include <ntifs.h>
#include "proc_hashlist.h"
#include "cosmos_ioctl.h"

/*
    Using 1031 prime number with modulus to reduce collisions.
	While modulus works well with power of 2 it will be using only the least significant bits of the hash value.
	This is because of the way the bitwise operation works, it tends to align the data in the system memory layout.

	Using 1031 will help to reduce collision and distribute the data more evenly across the hash table. For short lived
    driver this is not really big of a deal but since this is an XDR driver it will be long lived, as long as the system is up.

    NOTE: collisions cannot be avoided completely but it will be reduced comparing to using power of 2.
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

VOID TrackProcess(HANDLE pid, HANDLE ppid, ULONG_PTR ImageBase, SIZE_T ImageSize, PUNICODE_STRING ImageName, BOOLEAN Create) {
    ULONG idx = HashPid(pid);

    ExAcquireFastMutex(&g_HashTableLock);

    // Look up the process entry in the hash table
    PROCESS_ENTRY* curr = g_HashTable[idx];
    while (curr) {
        if (curr->ProcessId == pid) {
            break;
        }
        curr = curr->Next;
    }

    // Event is not create and pid doesn't exist 
    if (!Create && curr == NULL) {
        ExReleaseFastMutex(&g_HashTableLock);
        return;
    }

    // New process, allocate resources and add to the hash table
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
        curr->Next = g_HashTable[idx];
        g_HashTable[idx] = curr;
    }
    
    /*
        Protecting from overwriting ImageBase | curr->ImageBase if both are not 0
    */
    if (ImageBase == 0 && curr->ImageBase == 0) {
        curr->ImageBase = 0;
    }

    /*
        Protecting from overwriting ImageSize | curr->ImageSize if both are not 0
    */
    if (ImageSize == 0 && curr->ImageSize == 0) {
        curr->ImageSize = ImageSize;
    }

    // If Process exist, image name is provided but not initalized, add it
    if (ImageName && curr && !curr->ImageCaptured && curr->ImageFileName.Buffer == NULL) {
        SIZE_T allocSize = ImageName->Length + sizeof(WCHAR);
        PWSTR buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, COSMOS_TAG);
        if (buffer) {
            RtlCopyMemory(buffer, ImageName->Buffer, ImageName->Length);
            buffer[ImageName->Length / sizeof(WCHAR)] = L'\0';

            curr->ImageFileName.Buffer = buffer;
            curr->ImageFileName.Length = ImageName->Length;
            curr->ImageFileName.MaximumLength = (USHORT)allocSize;
            curr->ImageCaptured = TRUE;
        }
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

// Being called from the IOCTL only
VOID CosmosDumpTrackedProcesses() {

    // Before trying copy hash table content to user space
    ExAcquireFastMutex(&g_HashTableLock);

    // Tracking max user processes
    int count = 0;

    // Making sure we get all process hash table && not exceeding max user process entries
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

            UserBuffer[copied].Pid = (ULONG_PTR)entry->ProcessId;
            UserBuffer[copied].Ppid = (ULONG_PTR)entry->ParentProcessId;
            UserBuffer[copied].ImageBase = (ULONG_PTR)entry->ImageBase;
            UserBuffer[copied].ImageSize = (SIZE_T)entry->ImageSize;

            if (entry->ImageCaptured && entry->ImageFileName.Buffer) {
                USHORT len = entry->ImageFileName.Length / sizeof(WCHAR);
                // Making sure there is null termination
                if (len >= COSMOS_MAX_PATH) {
                    len = COSMOS_MAX_PATH - 1;
                }

                RtlCopyMemory(UserBuffer[copied].ImageFileName, entry->ImageFileName.Buffer, len * sizeof(WCHAR));
                UserBuffer[copied].ImageFileName[len] = L'\0';
            }
            else {
                UserBuffer[copied].ImageFileName[0] = L'\0';
            }

            ++copied;
            entry = entry->Next;
        }
    }

    *ReturnedCount = copied;
    ExReleaseFastMutex(&g_HashTableLock);

    COSMOS_LOG("Cosmos: Returned %lu | Entries (max %lu)", copied, MaxCount);

    return STATUS_SUCCESS;
}
