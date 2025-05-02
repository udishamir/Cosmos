/*
	References: https://github.com/AdaCore/gsh/tree/master/os/src
*/

#include <ntddk.h>
#include <sal.h>
#include <ntstrsafe.h>

// Must have forward declaration otherwise the compiler wont build.
extern "C" void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

VOID ProcessNotifyCallBack(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
) {
	if (Create) {
		// Process being created
		DbgPrint("Cosmos: Process Created - PID: %llu, Parent PID: %llu\n",
			(ULONG64)ProcessId, (ULONG64)ParentId);
	}
	else {
		// Process being terminated
		DbgPrint("Cosmos: Process Terminated - PID: %llu\n", (ULONG64)ProcessId);
	}
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
	//UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = STATUS_SUCCESS;
    
    // Register the PsSetCreateProcessNotifyRoutineEx to point to my callback
	NTSTATUS ProcessMon = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallBack, FALSE);
	if (ProcessMon != status)
	{
		DbgPrint("Cosmos: Failed to register process notification callback (0x%08X)\n", status);
		return ProcessMon;
	}

    // Set the driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("Cosmos: Driver Loaded Successfully!\n");
    // Print a message to the debug output
    DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_INFO_LEVEL, "Cosmos: Driver Loaded Successfully!\n");

    return STATUS_SUCCESS;
}

extern "C"
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
//UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS status = STATUS_SUCCESS;

	NTSTATUS ProcessMon = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallBack, TRUE);
	if (ProcessMon != status) {
		DbgPrint("Cosmos: Failed to unregister process notify callback\n");
		return;
	}
	else {
		DbgPrint("Cosmos: Driver Unloaded Successfully!\n");
	}
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_INFO_LEVEL, "Cosmos: Driver Unloaded Successfully!\n");
}