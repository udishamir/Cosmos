/*
	Cosmos XDR Driver

	© 2025 Udi Shamir. All rights reserved.
	Unauthorized copying of this file, via any medium, is strictly prohibited.
	Proprietary and confidential.

	Author: Udi Shamir
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

/*
	Function: CosmosCreate

	Purpose: Handles IRP_MJ_CREATE requests when userland applications call CreateFile on our device.
	This is the entry point for establishing communication with the driver.

	Parameters:

	DeviceObject - Pointer to the device object (unused)
	Irp - I/O Request Packet containing the request details

	Returns: STATUS_SUCCESS - Always succeeds to allow userland connection

	Security: Device access is already restricted by SDDL in device creation
*/

NTSTATUS CosmosCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	// Set successful completion status
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	
	// Complete the IRP with no priority boost
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
	Function: CosmosClose

	Purpose: Handles IRP_MJ_CLOSE requests when userland applications call CloseHandle.
	Performs cleanup for the specific file handle being closed.

	Parameters:
	DeviceObject - Pointer to the device object (unused)
	Irp - I/O Request Packet containing the request details

	Returns: STATUS_SUCCESS - Always succeeds

	Note: Currently no per-handle state is maintained, so no cleanup is needed
*/

NTSTATUS CosmosClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	// Set successful completion status
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	
	// Complete the IRP with no priority boost
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
	Function: CosmosCleanup

	Purpose: Handles IRP_MJ_CLEANUP requests when all handles to a file object are closed.
	This is called before IRP_MJ_CLOSE and allows for final cleanup operations.

	Parameters:
	DeviceObject - Pointer to the device object (unused)
	Irp - I/O Request Packet containing the request details

	Returns: STATUS_SUCCESS - Always succeeds

	Note: Currently no file object state is maintained, so no cleanup is needed
*/

NTSTATUS CosmosCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	// Set successful completion status
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	
	// Complete the IRP with no priority boost
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
	Function: DriverDeviceControl

	Purpose: Handles IRP_MJ_DEVICE_CONTROL requests (DeviceIoControl calls from userland).
	This is the main communication interface between the driver and userland applications.

	Parameters:

	DeviceObject - Pointer to the device object (unused)
	Irp - I/O Request Packet containing the IOCTL request and buffers

	Returns: 

	STATUS_SUCCESS - IOCTL was processed successfully
	STATUS_BUFFER_TOO_SMALL - Output buffer is insufficient
	STATUS_INVALID_PARAMETER - Invalid buffer pointer
	STATUS_INVALID_DEVICE_REQUEST - Unsupported IOCTL code

	Supported IOCTLs:
	IOCTL_COSMOS_DUMP_PROCESSES - Retrieves tracked process information

	Security: Access to this function is restricted by device SDDL (Admin/SYSTEM only)
*/

extern "C"
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// Extract the I/O stack location to access IOCTL parameters
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

	// Initialize return values
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR info = 0; // Bytes transferred

	switch (code)
	{
		case IOCTL_COSMOS_DUMP_PROCESSES:
		{
			// Validate output buffer size - must fit at least one process entry
			ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
			if (outLen < sizeof(COSMOS_PROC_INFO)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			// Get the system buffer (METHOD_BUFFERED ensures kernel-accessible memory)
			COSMOS_PROC_INFO* outBuf = (COSMOS_PROC_INFO *)Irp->AssociatedIrp.SystemBuffer;
			if (!outBuf) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			// Calculate maximum number of process entries that fit in the buffer
			ULONG maxCount = outLen / sizeof(COSMOS_PROC_INFO);
			ULONG returned = 0;

			// Copy tracked processes to userland buffer
			status = CosmosCopyTrackedProcessesToUser(outBuf, maxCount, &returned);
			if (NT_SUCCESS(status)) {
				// Set the number of bytes actually written
				info = returned * sizeof(COSMOS_PROC_INFO);
			}

			break;
		}

		default:
			// Unsupported IOCTL code
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	// Complete the IRP with status and information
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
		D:  Discretionary ACL (DACL) begins.
		P  Protected DACL; prevents inheritance.
		(A;;GA;;;SY)  Allow Generic All to System.
		(A;;GA;;;BA)  Allow Generic All to Built-in Administrators.

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
		Process Tracking Initialization
		
		Initialize the hash table that tracks processes by PID, PPID, and ImageFileName.
		
		Multi-source tracking strategy:
		1. PsSetLoadImageNotifyRoutine() - Captures DLL/EXE loads with full image path
		2. PsSetCreateProcessNotifyRoutine() - Captures process creation/termination events
		3. SeLocateProcessImageName() - Fallback for processes missed by image load notifications
		
		This redundant approach ensures we capture short-lived processes that might be missed
		by a single notification mechanism (e.g., ephemeral cmd.exe processes).
		
		Note: With Microsoft code signing, we could use PsSetCreateProcessNotifyRoutineEx()
		which provides image name directly, eliminating the need for image load notifications.
	*/
	InitProcessTable();

	/*
		Register Kernel Callbacks for Process Monitoring
		
		The order of registration is important:
		1. Image load notifications - Primary source of process image information
		2. Process notifications - Captures creation/termination events
		3. Thread notifications - Currently logged but not processed
	*/

	// Register for image/DLL load notifications (primary process detection)
	NTSTATUS LoadImageMon = PsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);
	if (!NT_SUCCESS(LoadImageMon)) {
		DbgPrint("Cosmos: Failed to register image load notification callback (0x%08X)\n", LoadImageMon);
		return LoadImageMon;
	}

	// Register for process creation/termination notifications
	NTSTATUS ProcCreateMon = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(ProcCreateMon)) {
		DbgPrint("Cosmos: Failed to register process create notification callback (0x%08X)\n", ProcCreateMon);
		return ProcCreateMon;
	}

	// Register for thread creation/termination notifications (for future use)
	NTSTATUS ThreadCreateMon = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
	if (!NT_SUCCESS(ThreadCreateMon)) {
		DbgPrint("Cosmos: Failed to register thread create notification callback (0x%08X)\n", ThreadCreateMon);
		return ThreadCreateMon;
	}

    // Set the driver unload routine
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("Cosmos: Driver Loaded Successfully!\n");

    return STATUS_SUCCESS;
}

/*
	Function: DriverUnload

	Purpose: Called by the system when the driver is being unloaded.
	Performs cleanup of all resources allocated during driver operation.

	Parameters:

	DriverObject - Pointer to the driver object being unloaded

	Cleanup Order:

	1. Remove symbolic link (prevents new userland connections)
	2. Delete device object (cleans up device stack)
	3. Cleanup process tracking table (free allocated memory)
	4. Unregister all kernel callbacks (prevents further notifications)

	Note: Proper cleanup order is critical to prevent system crashes during unload
*/
extern "C"
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\CosmosLink");

	// Step 1: Remove symbolic link to prevent new userland connections
	IoDeleteSymbolicLink(&symLink);

	// Step 2: Delete the device object and clean up device stack
	if (DriverObject->DeviceObject) {
		IoDeleteDevice(DriverObject->DeviceObject);
	}

	// Step 3: Cleanup process tracking data structures and free memory
	CleanupProcessTable();

	// Step 4: Unregister all kernel callbacks to stop receiving notifications
	
	// Unregister image load notifications
	NTSTATUS UnloadImageMon = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
	if (!NT_SUCCESS(UnloadImageMon)) {
		DbgPrint("Cosmos: Failed to unregister image load notification callback (0x%08X)\n", UnloadImageMon);
	}
	else {
		DbgPrint("Cosmos: Successfully unregistered image load notification callback\n");
	}
	
	// Unregister process creation notifications (TRUE = remove callback)
	NTSTATUS UnloadCreateProcessMon = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
	if (!NT_SUCCESS(UnloadCreateProcessMon)) {
		DbgPrint("Cosmos: Failed to unregister process create notification callback (0x%08X)\n", UnloadCreateProcessMon);
	}
	else {
		DbgPrint("Cosmos: Successfully unregistered process create notification callback\n");
	}

	// Unregister thread creation notifications
	NTSTATUS UnloadCreateThreadMon = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
	if (!NT_SUCCESS(UnloadCreateThreadMon)) {
		DbgPrint("Cosmos: Failed to unregister thread create notification callback (0x%08X)\n", UnloadCreateThreadMon);
	}
	else {
		DbgPrint("Cosmos: Successfully unregistered thread create notification callback\n");
	}

	DbgPrint("Cosmos: Driver Unloaded Successfully!\n");
}
