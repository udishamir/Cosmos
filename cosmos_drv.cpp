#include <ntddk.h>
#include <sal.h>
#include <ntstrsafe.h>

// Must have forward declaration otherwise the compiler wont build.
extern "C" void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
	//UNREFERENCED_PARAMETER(DriverObject);

    // Set the driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("Cosmos: Driver Loaded Successfully!\n");
    // Print a message to the debug output
    DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_INFO_LEVEL, "Cosmos: Driver Loaded Successfully!\n");

    return STATUS_SUCCESS;
}

extern "C"
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("Cosmos: Driver Unloaded Successfully!\n");
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_INFO_LEVEL, "Cosmos: Driver Unloaded Successfully!\n");
}