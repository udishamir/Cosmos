#include "cosmos.h"
#include "proc_hashlist.h"

#include "cosmos.h"
#include "proc_hashlist.h"

extern "C"
VOID ImageLoadNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {
    if (!ProcessId || !ImageInfo) {
        return;
    }

    // Skip kernel-mode images
    if (ImageInfo->SystemModeImage) {
        COSMOS_LOG("Cosmos: Skipping kernel-mode image for PID %llu\n", (ULONG64)ProcessId);
        return;
    }

    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0) {
        COSMOS_LOG("Cosmos: Skipping image load with empty name for PID %llu\n", (ULONG64)ProcessId);
        return;
    }

    PROCESS_ENTRY* entry = CosmosLookupProcessByPid(ProcessId);
    /*
        If i got callback from PsSetCreateProcessNotifyRoutine and tracked it (entry == PID),
        however PsSetLoadImageNotifyRoutine was not called yet, add the entry since i got FullImageName
    */

    if (!entry) {
        // First time seeing this PID at all -> create new and capture image
        COSMOS_LOG("Cosmos: Creating and capturing image for PID %llu: %wZ\n", (ULONG64)ProcessId, FullImageName);
        TrackProcess(ProcessId, 0, FullImageName, TRUE);
    }
    else if (!entry->ImageCaptured) {
        // Entry exists, but image wasn't captured yet
        COSMOS_LOG("Cosmos: Updating image for PID %llu: %wZ\n", (ULONG64)ProcessId, FullImageName);
        TrackProcess(ProcessId, 0, FullImageName, FALSE);
    }

}

// Process creation notification callback
extern "C"
VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
) {
    if (Create) {
        COSMOS_LOG("Cosmos: Process Created - PID: %llu, PPID: %llu\n",
            (ULONG64)ProcessId, (ULONG64)ParentId);
        TrackProcess(ProcessId, ParentId, NULL, TRUE);
    }
    else {
        COSMOS_LOG("Cosmos: Process Deleted - PID: %llu\n", (ULONG64)ProcessId);
        TrackProcess(ProcessId, 0, NULL, FALSE);
    }
}


// Thread creation notification callback
extern "C"
VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
) {
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);
    UNREFERENCED_PARAMETER(ProcessId);
    /*
    if (Create) {
        DbgPrint("Cosmos: Thread Created - PID: %llu, TID: %llu\n",
            (ULONG64)ProcessId,
            (ULONG64)ThreadId);
    }
    else {
        DbgPrint("Cosmos: Thread Deleted - PID: %llu, TID: %llu\n",
            (ULONG64)ProcessId,
            (ULONG64)ThreadId);
    }
    */
}