/*
	References: 
	https://github.com/AdaCore/gsh/tree/master/os/src

	ObRegisterCallBack & CounterMeasures
	https://douggemhax.wordpress.com/2015/05/27/obregistercallbacks-and-countermeasures/
*/
#pragma comment(lib, "wdmsec.lib")

#include "cosmos.h"
#include "proc_hashlist.h"
#include "cosmos_ioctl.h"

// Forward Declarations
extern "C" void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
extern "C" void ImageLoadNotifyCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
extern "C" void ProcessNotifyCallback(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);
extern "C" void ThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

NTSTATUS CosmosCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CosmosClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CosmosCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// The IoGetCurrentIrpStackLocation routine returns a pointer to the caller's I/O stack location in the specified IRP.
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR info = 0;

	switch (code)
	{
		case IOCTL_COSMOS_DUMP_PROCESSES:
		{
			ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
			if (outLen < sizeof(COSMOS_PROC_INFO)) {
				status = STATUS_BUFFER_TOO_SMALL;

				break;
			}

			COSMOS_PROC_INFO* outBuf = (COSMOS_PROC_INFO *)Irp->AssociatedIrp.SystemBuffer;
			if (!outBuf) {
				status = STATUS_INVALID_PARAMETER;

				break;
			}

			ULONG maxCount = outLen / sizeof(COSMOS_PROC_INFO);
			ULONG returned = 0;

			status = CosmosCopyTrackedProcessesToUser(outBuf, maxCount, &returned);
			if (NT_SUCCESS(status)) {
				info = returned * sizeof(COSMOS_PROC_INFO);
			}

			break;
		}

		default:
			// No other IOCTL supported yet
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	/*
		Routine Description:
		This routine is called by the Operating System to initialize the driver.

		It creates the device object, fills in the dispatch entry points and
		completes the initialization.

		Arguments:

		DriverObject - a pointer to the object that represents this device
		driver.

		RegistryPath - a pointer to our Services key in the registry.	
	*/
    UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\CosmosDevice");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\CosmosLink");
	PDEVICE_OBJECT deviceObject = NULL;
	// SDDL Permission
	UNICODE_STRING sddlPermission = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	

	/*
		Creating device link to allow user app connecting to the driver
		https://github.com/microsoft/Windows-driver-samples/blob/main/general/ioctl/wdm/sys/sioctl.c
	*/
	// This GUID is artificial, you must never use existing GUID since other driver might need to aquire it.
	static const GUID GUID_DEVCLASS_COSMOSDEVICE =
	{ 0xd2d16b3e, 0x2e46, 0x4a68, { 0xa4, 0x5f, 0xbe, 0xf1, 0x79, 0xc3, 0x4f, 0x51 } };

	/*
		https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects

		Enforcing tight security, only Administrator and SYSTEM can access the device driver.

		https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
		Security Descriptor Defintion Language (SDDL): 
		D: – Discretionary ACL (DACL) begins.
		P – Protected DACL; prevents inheritance.
		(A;;GA;;;SY) – Allow Generic All to System.
		(A;;GA;;;BA) – Allow Generic All to Built-in Administrators.

		Never include entries for:
		WD (Everyone)
		BU (Users)
		IU (Interactive Users)

		IoCreateDeviceSecure require Windows Driver Kit (WDK) and include "wdmsec.h
		Additionally the LINKER must be updated to link against wdmsec.lib.

		If using Vs2022 you can utilize NuGet plugin manager:
		https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget

		Do not use **IoCreateDevice** which is not secure. IoCreateDevice must be hardened from user space usually using INF file 
		which is dangerous, we don't want to leave any open loose ends to user, that's a curve ball later. 
	*/
	NTSTATUS IoDeviceSecureStatus = IoCreateDeviceSecure(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&sddlPermission,
		&GUID_DEVCLASS_COSMOSDEVICE,
		&deviceObject
	);
	if (!NT_SUCCESS(IoDeviceSecureStatus)) {
		DbgPrint("Cosmos: IoCreateDevice failed (0x%08X)\n", IoDeviceSecureStatus);
		return IoDeviceSecureStatus;
	}

	// Less desirable but mandatory if we want user space app to communicate with us.
	NTSTATUS IoCreateSymLink = IoCreateSymbolicLink(&symLink, &deviceName);
	if (!NT_SUCCESS(IoCreateSymLink)) {
		IoDeleteDevice(deviceObject);
		DbgPrint("Cosmos: IoCreateSymbolicLink failed (0x%08X)\n", IoCreateSymLink);
		return IoCreateSymLink;
	}

	/*
		Device CREATE | CLEANUP | CLOSE Callbacks

		IRP_MJ_CREATE (0x00 Called when user calls CreateFile
		IRP_MJ_CLOSE (0x02)	Called when user calls CloseHandle
		IRP_MJ_DEVICE_CONTROL (0x0E) Called when user calls DeviceIoControl
	*/
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CosmosCreate;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CosmosCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CosmosClose;

	/*
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] is an array of function pointers:
		Configure the device to send the Hashtable Content To User
	*/
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;


	/*
		InitProcessTable()

		Initializing the process table, this table keeps track of process Pid, Ppid and ImageFilename.
		Since right now i cannot utilize PsSetCreateProcessNotifyRoutineEx() im creating context using
		hash table to follow process creation + DLL or EXE using the PsSetImageLoadNotifyRoutine().

		Motivation is to to initialize single data structure that will sent data up to user when the user
		app will initiate DeviceIoControl() request.

		If ill manage to get Microsoft signing my driver i could utilize PsSetCreateProcessNotifyRoutineEx() and wont need 
		PsSetImageLoadNotifyRoutine() to extract ImageFileName
	*/
	InitProcessTable();

	
	// Registering PsSetImageLoadNotifyRoutine()
	
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
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\CosmosLink");

	// Removing driver link
	IoDeleteSymbolicLink(&symLink);

	// Remove Device From User
	if (DriverObject->DeviceObject) {
		IoDeleteDevice(DriverObject->DeviceObject);
	}

	// Cleanup the process table
	CleanupProcessTable();

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