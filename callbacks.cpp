/*
	Cosmos XDR Driver

    © 2024–2025 Udi Shamir. All Rights Reserved.
    Unauthorized copying of this file, via any medium, is strictly prohibited.
    Proprietary and confidential.

    Author: Udi Shamir
*/

#include "cosmos.h"
#include "proc_hashlist.h"

#include "cosmos.h"
#include "proc_hashlist.h"

/*
    PsSetImageLoadNotifyRotuine() is called when DLL / EXE is loaded into process image section and not per process,
    however when new process is being created without loading DLL/Exe into process image,
    PsSetImageLoadNotifyRotuine() wont be triggered.

    Additionally, ephemeral processes might exit before PsSetImageLoadNotifyRoutine() will be called,
    such process can be:
    1. cmd.exe, when running short lived process for example: running logon script
    2.
*/
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
        TrackProcess(ProcessId, 0, (ULONG_PTR)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, TRUE, CAPTURE_SOURCE_IMAGE_LOAD);
    }
    else if (!entry->ImageCaptured) {
        // Entry exists, but image wasn't captured yet
        TrackProcess(ProcessId, 0, (ULONG_PTR)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, FALSE, CAPTURE_SOURCE_IMAGE_LOAD);
    }

}

// Process creation notification callback
extern "C"
VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
) {
  
    /*
        In case process is created however it was not captured by PsSetImageLoadNotifyRoutine, this might 
        happen in the following cases:

        1. Timing, process was created too fast
        2. Is not available due to signing issue

        When this happen im trying to get pointer to EPROCESS abd locating the FullImageName as with PsSetImageLoadNotifyRoutine().
        EPROCESS is undocumented by Microsoft,
        there unofficial EPROCESS struct can be found at: https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html
    
    */
    PEPROCESS eproc = NULL;
    PUNICODE_STRING process_name = NULL;
 
    NTSTATUS process_lookup = STATUS_ACCESS_DENIED;
    NTSTATUS se_locate_process_imagename = STATUS_ACCESS_DENIED;

    if (Create) {
        // Getting EPROCESS, this is when PsSetImageLoadNotifyRoutine() misses newly created process
        process_lookup = PsLookupProcessByProcessId(ProcessId, &eproc);
        if (NT_SUCCESS(process_lookup)) {

            se_locate_process_imagename = SeLocateProcessImageName(eproc, &process_name);
            if (NT_SUCCESS(se_locate_process_imagename) && process_name != NULL) {
                // Adding the process since most likely PsSetImageLoadNotifyRoutine() was never triggered
                TrackProcess(ProcessId, ParentId, 0, 0, process_name, TRUE, CAPTURE_SOURCE_CREATE_NOTIFY);
                /*
                    Need to get both VritualSize and ImageBase from EPROCESS
                    ...
                */

                // If SeLocateProcessImageName return with success we must free process_name
                if (process_name) {
                    ExFreePoolWithTag(process_name, 0);
                }
            }

            // Dereference Object
            ObDereferenceObject(eproc);
        }
        else {
            // Could not get EPROCESS, still register PID
            TrackProcess(ProcessId, ParentId, 0, 0, NULL, TRUE, CAPTURE_SOURCE_CREATE_NOTIFY);
        }

        COSMOS_LOG("Cosmos: Process Created PID: %llu | PPID: %llu\n",
            (ULONG64)ProcessId, (ULONG64)ParentId);
    }
    else {
        COSMOS_LOG("Cosmos: Process Deleted PID: %llu\n", (ULONG64)ProcessId);
        TrackProcess(ProcessId, 0, (ULONG_PTR)0, 0, NULL, FALSE, CAPTURE_SOURCE_NONE);
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