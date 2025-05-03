/*
	References: 
	https://github.com/AdaCore/gsh/tree/master/os/src

	ObRegisterCallBack & CounterMeasures
	https://douggemhax.wordpress.com/2015/05/27/obregistercallbacks-and-countermeasures/
*/

#include "cosmos.h"

// Forward Declarations
extern "C" void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
extern "C" void ImageLoadNotifyCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
extern "C" void ProcessNotifyCallback(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);
extern "C" void ThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
	/*
		Registering PsSetImageLoadNotifyRoutine() is useful when monitoring DLL/EXE 
		execution. The motivation is to get the ImageFileName since i cannot use PsSetCreateNotifyRoutineEx due to
		Microsoft strict requirements where self signed drivers cannot utilize it.
	*/
	NTSTATUS LoadImageMon = PsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);
	if (!NT_SUCCESS(LoadImageMon)) {
		DbgPrint("Cosmos: Failed to register image load notification callback (0x%08X)\n", LoadImageMon);
		return LoadImageMon;
	}

	// Registering PsSetCreateProcessNotifyRoutine()
	NTSTATUS ProcCreateMon = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(ProcCreateMon)) {
		DbgPrint("Cosmos: Failed to register process create notification callback (0x%08X)\n", ProcCreateMon);
		return ProcCreateMon;
	}

	// Registering PsSetCreateThreadRoutine()
	NTSTATUS ThreadCreateMon = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
	if (!NT_SUCCESS(ThreadCreateMon)) {
		DbgPrint("Cosmos: Failed to register thread create notification callback (0x%08X)\n", ProcCreateMon);
		return ProcCreateMon;
	}

    // Set the driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("Cosmos: Driver Loaded Successfully!\n");
    
    return STATUS_SUCCESS;
}

extern "C"
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	// Unregister from image load notifications
	NTSTATUS UnloadImageMon = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
	if (!NT_SUCCESS(UnloadImageMon)) {
		DbgPrint("Cosmos: Failed to unregister image load notification callback (0x%08X)\n", UnloadImageMon);
	}
	else {
		DbgPrint("Cosmos: Successfully unregistered image load notification callback\n");
	}
	
	// Unregister from process create notifications
	NTSTATUS UnloadCreateProcessMon = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
	if (!NT_SUCCESS(UnloadCreateProcessMon)) {
		DbgPrint("Cosmos: Failed to unregister process create notification callback (0x%08X)\n", UnloadCreateProcessMon);
	}
	else {
		DbgPrint("Cosmos: Successfully unregistered process create notification callback\n");
	}

	// Unregister from process create notifications
	NTSTATUS UnloadCreateThreadMon = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
	if (!NT_SUCCESS(UnloadCreateThreadMon)) {
		DbgPrint("Cosmos: Failed to unregister thread create notification callback (0x%08X)\n", UnloadCreateThreadMon);
	}
	else {
		DbgPrint("Cosmos: Successfully unregistered thread create notification callback\n");
	}

	DbgPrint("Cosmos: Driver Unloaded Successfully!\n");
}