/*
	Cosmos XDR Driver

	© 2025 Udi Shamir. All Rights Reserved.
	Unauthorized copying of this file, via any medium, is strictly prohibited.
	Proprietary and confidential.

	Author: Udi Shamir
*/

#include "cosmos.h"
#include "proc_hashlist.h"

/*
	Kernel Callback Functions for Process, Thread, and Image Monitoring
	
	These callbacks are registered with the Windows kernel to receive notifications
	about system events. They form the core of the Cosmos monitoring system.
	
	Callback Registration Order (in DriverEntry):
	1. PsSetLoadImageNotifyRoutine() - Image/DLL load events
	2. PsSetCreateProcessNotifyRoutine() - Process creation/termination
	3. PsSetCreateThreadNotifyRoutine() - Thread creation/termination
	
	Multi-Source Tracking Strategy:
	The combination of these callbacks addresses Windows process tracking challenges:
	- Short-lived processes (ephemeral cmd.exe, PowerShell scripts)
	- Timing issues between process creation and image loading
	- Processes that bypass normal image loading mechanisms

	Function: ImageLoadNotifyCallback

	Purpose: Called by Windows kernel when any executable image (EXE/DLL) is loaded
	into a process address space. This is our primary source of process
	image information including full file paths.

	Parameters:
	FullImageName - Unicode string containing full path to loaded image
	ProcessId - Handle to the process where image was loaded
	ImageInfo - Detailed information about the loaded image

	Callback Context: PASSIVE_LEVEL IRQL

	Edge Cases Handled:
	- Kernel-mode images (drivers) - Ignored for security
	- Empty image names - Logged and skipped
	- Processes seen before image load - Updates existing entry
	- New processes - Creates new tracking entry

	Security: This callback receives all system image loads, so filtering
	is critical to avoid performance impact and irrelevant data.

	Note: PsSetImageLoadNotifyRoutine() can miss very short-lived processes
	that exit before their main image is fully loaded. ProcessNotifyCallback
	serves as a backup for these cases.
*/
extern "C"
VOID ImageLoadNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {
    // Validate essential parameters
    if (!ProcessId || !ImageInfo) {
        return;
    }

    // Filter out kernel-mode images (drivers, kernel modules)
    // Security: We only track user-mode processes for XDR purposes
    if (ImageInfo->SystemModeImage) {
        COSMOS_LOG("Cosmos: Skipping kernel-mode image for PID %llu\n", (ULONG64)ProcessId);
        return;
    }
    
    // Validate image name availability
    // Note: Some system processes may have empty image names
    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0) {
        COSMOS_LOG("Cosmos: Skipping image load with empty name for PID %llu\n", (ULONG64)ProcessId);
        return;
    }

    // Check if we're already tracking this process
    PROCESS_ENTRY* entry = CosmosLookupProcessByPid(ProcessId);
    
    if (!entry) {
        // Case 1: First time seeing this PID - create new entry with image info
        // This happens when image load notification fires before process creation notification
        COSMOS_LOG("Cosmos: New process detected via image load - PID %llu\n", (ULONG64)ProcessId);
        TrackProcess(ProcessId, 0, (ULONG_PTR)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, TRUE, CAPTURE_SOURCE_IMAGE_LOAD);
    }
    else if (!entry->ImageCaptured) {
        // Case 2: Process exists but image wasn't captured yet - update with image info
        // This happens when process creation notification fired first
        COSMOS_LOG("Cosmos: Updating existing process with image info - PID %llu\n", (ULONG64)ProcessId);
        TrackProcess(ProcessId, 0, (ULONG_PTR)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, FALSE, CAPTURE_SOURCE_IMAGE_LOAD);
    }
    // Case 3: Process already has image captured - ignore (prevents duplicate entries)

}

/*
	Function: ProcessNotifyCallback
	
	Purpose: Called by Windows kernel when processes are created or terminated.
			 Serves as backup detection for processes missed by image load notifications
			 and provides parent-child process relationships.
	
	Parameters:
		ParentId - Handle to parent process (0 for process termination)
		ProcessId - Handle to the process being created or terminated
		Create - TRUE for creation, FALSE for termination
	
	Callback Context: PASSIVE_LEVEL IRQL
	
	Fallback Strategy:
		When image load notifications miss a process (timing, short-lived processes),
		this callback attempts to retrieve process information using:
		1. PsLookupProcessByProcessId() - Get EPROCESS structure
		2. SeLocateProcessImageName() - Extract image name from EPROCESS
	
	Process Termination:
		Marks processes for cleanup in tracking table but doesn't immediately
		remove them to allow userland to retrieve final process state.
	
	Performance: Uses EPROCESS access which is more expensive than image callbacks
				but necessary for comprehensive process coverage.
	
	Security: EPROCESS manipulation requires careful memory management to prevent
			  system crashes from invalid pointers or reference counting errors.
*/
extern "C"
VOID ProcessNotifyCallback(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
) {
    // Variables for EPROCESS-based fallback process information retrieval
    PEPROCESS eproc = NULL;
    PUNICODE_STRING process_name = NULL;
    NTSTATUS process_lookup = STATUS_ACCESS_DENIED;
    NTSTATUS se_locate_process_imagename = STATUS_ACCESS_DENIED;

    if (Create) {
        /*
            Process Creation Fallback Strategy:
            
            When PsSetImageLoadNotifyRoutine() misses a process due to:
            1. Timing issues (process created/destroyed too quickly)
            2. Driver signing restrictions limiting callback registration
            3. Unusual process creation methods that bypass image loading
            
            We attempt to retrieve process information directly from EPROCESS structure.
            
            EPROCESS Structure Access:
            - EPROCESS is an undocumented Windows kernel structure
            - Contains process metadata including image name and memory layout
            - Requires careful reference counting to prevent system instability
            - Reference: https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html
        */
        
        // Attempt to get EPROCESS structure for the new process
        process_lookup = PsLookupProcessByProcessId(ProcessId, &eproc);
        if (NT_SUCCESS(process_lookup)) {
            // Try to extract image name from EPROCESS structure
            se_locate_process_imagename = SeLocateProcessImageName(eproc, &process_name);
            if (NT_SUCCESS(se_locate_process_imagename) && process_name != NULL) {
                // Successfully retrieved process information - track with CREATE_NOTIFY source
                COSMOS_LOG("Cosmos: Process fallback capture successful - PID %llu\n", (ULONG64)ProcessId);
                TrackProcess(ProcessId, ParentId, 0, 0, process_name, TRUE, CAPTURE_SOURCE_CREATE_NOTIFY);
                
                /*
                    TODO: Extract ImageBase and VirtualSize from EPROCESS
                    These values are available in EPROCESS but require careful offset calculations
                    that may vary between Windows versions. For now, we set them to 0.
                */

                // Critical: Free the allocated process name buffer to prevent memory leaks
                if (process_name) {
                    ExFreePoolWithTag(process_name, 0);
                }
            }

            // Critical: Dereference the EPROCESS object to maintain proper reference counting
            ObDereferenceObject(eproc);
        }
        else {
            // EPROCESS lookup failed - still track the PID with minimal information
            // This ensures we don't completely miss the process even in failure cases
            COSMOS_LOG("Cosmos: EPROCESS lookup failed for PID %llu, tracking with minimal info\n", (ULONG64)ProcessId);
            TrackProcess(ProcessId, ParentId, 0, 0, NULL, TRUE, CAPTURE_SOURCE_CREATE_NOTIFY);
        }

        COSMOS_LOG("Cosmos: Process Created PID: %llu | PPID: %llu\n",
            (ULONG64)ProcessId, (ULONG64)ParentId);
    }
    else {
        // Process Termination
        // Mark process for cleanup but don't immediately remove from tracking table
        // This allows userland applications to retrieve final process state
        COSMOS_LOG("Cosmos: Process Terminated PID: %llu\n", (ULONG64)ProcessId);
        TrackProcess(ProcessId, 0, (ULONG_PTR)0, 0, NULL, FALSE, CAPTURE_SOURCE_NONE);
    }
}


/*
	Function: ThreadNotifyCallback
	
	Purpose: Called by Windows kernel when threads are created or terminated.
			 Currently registered but not actively used for process tracking.
	
	Parameters:
		ProcessId - Handle to process owning the thread
		ThreadId - Handle to the thread being created or terminated  
		Create - TRUE for creation, FALSE for termination
	
	Callback Context: PASSIVE_LEVEL IRQL
	
	Current Status: DISABLED
		The implementation is commented out to reduce log noise and performance impact.
		Thread-level monitoring could be enabled for advanced behavioral analysis.
	
	Future Use Cases:
		- Detect thread injection attacks
		- Monitor suspicious threading patterns
		- Track thread-based process hollowing
		- Analyze multi-threaded malware behavior
	
	Performance Consideration:
		Thread creation is extremely frequent in Windows systems. Enabling this
		callback significantly increases log volume and processing overhead.
*/
extern "C"
VOID ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
) {
    // Currently unused - marked to prevent compiler warnings
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);
    UNREFERENCED_PARAMETER(ProcessId);
    
    /*
        Thread Monitoring Implementation (Currently Disabled)
        
        Uncomment the following code to enable thread-level monitoring.
        Warning: This will significantly increase log volume and performance impact.
        
        Potential security use cases:
        - Detect CreateRemoteThread() API abuse (process injection)
        - Monitor abnormal threading patterns in processes
        - Track thread-based evasion techniques
        - Analyze multi-threaded malware behavior
    
    if (Create) {
        COSMOS_LOG("Cosmos: Thread Created - PID: %llu, TID: %llu\n",
            (ULONG64)ProcessId,
            (ULONG64)ThreadId);
        
        // TODO: Add thread tracking logic here
        // - Could maintain per-process thread counts
        // - Track thread creation timing/patterns
        // - Detect suspicious thread creation sources
        
    }
    else {
        COSMOS_LOG("Cosmos: Thread Terminated - PID: %llu, TID: %llu\n",
            (ULONG64)ProcessId,
            (ULONG64)ThreadId);
            
        // TODO: Add thread cleanup logic here
        // - Update thread counts
        // - Detect abnormal thread termination patterns
    }
    */
}
