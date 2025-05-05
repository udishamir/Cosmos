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

	/*
		Creating device link to allow user app connecting to the driver
		https://github.com/microsoft/Windows-driver-samples/blob/main/general/ioctl/wdm/sys/sioctl.c
	*/
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\CosmosDevice");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\CosmosLink");
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING sddlPermision = RTL_CONSTANT_STRING(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)");


	static const GUID GUID_DEVCLASS_COSMOSDEVICE =
	{ 0xd2d16b3e, 0x2e46, 0x4a68, { 0xa4, 0x5f, 0xbe, 0xf1, 0x79, 0xc3, 0x4f, 0x51 } };

	NTSTATUS IoDeviceSecureStatus = IoCreateDeviceSecure(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&sddlPermision,
		&GUID_DEVCLASS_COSMOSDEVICE,
		&deviceObject
	);
	if (!NT_SUCCESS(IoDeviceSecureStatus)) {
		DbgPrint("Cosmos: IoCreateDevice failed (0x%08X)\n", IoDeviceSecureStatus);
		return IoDeviceSecureStatus;
	}

	NTSTATUS IoCreateSymLink = IoCreateSymbolicLink(&symLink, &deviceName);
	if (!NT_SUCCESS(IoCreateSymLink)) {
		IoDeleteDevice(deviceObject);
		DbgPrint("Cosmos: IoCreateSymbolicLink failed (0x%08X)\n", IoCreateSymLink);
		return IoCreateSymLink;
	}

	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = [](PDEVICE_OBJECT, PIRP Irp) -> NTSTATUS {
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	DriverObject->MajorFunction[IRP_MJ_CREATE] = [](PDEVICE_OBJECT, PIRP Irp) -> NTSTATUS {
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	DriverObject->MajorFunction[IRP_MJ_CLOSE] = [](PDEVICE_OBJECT, PIRP Irp) -> NTSTATUS {
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};

	/*
		InitProcessTable()

		Initializing the process table, this table keeps track of process Pid, Ppid and ImageFilename.
		Since right now i cannot utilize PsSetCreateProcessNotifyRoutineEx() im creating context using
		hash table to follow process creation + loading of DLL or EXE using the PsSetImageLoadNotifyRoutine().

		PsSetImageLoadNotifyRoutine() routine registers a driver-supplied callback ImageLoadNotifyCallback (In my driver),
		that is subsequently notified whenever an image (for example, a DLL or EXE) is loaded (or mapped into memory).

		PsSetImageLoadNotifyRoutine() points to PLOAD_IMAGE_NOTIFY_ROUTINE structure callback which have the following members:

		```
		PLOAD_IMAGE_NOTIFY_ROUTINE PloadImageNotifyRoutine;

		void PloadImageNotifyRoutine(
		  [in, optional] PUNICODE_STRING FullImageName,
		  [in]           HANDLE ProcessId,
		  [in]           PIMAGE_INFO ImageInfo
		)
		```

		hence to correlate Pid, Ppid and ImageFileName into single data structure i need to keep state.

		This single data structure will be sent back to user mode when the user app will initiate call to DeviceIoControl()
	*/
	InitProcessTable();

	/*
		DriverDeviceControl()

		Registering the device control function using MajorFunction[IRP_MD_DEVICE_CONTROL] which points
		the Driver DRIVER_OBJECT.

		DRIVE_OBJECT:
		https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object
		Pointer to the device objects created by the driver. 
		This member is automatically updated when the driver calls IoCreateDevice successfully. 
		A driver can use this member and the NextDevice member of DEVICE_OBJECT 
		to step through a list of all the device objects that the driver created.

		When user code will call DeviceIoControl() function from user space the DriverDeviceControl function will be called.
		
		https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol

		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] is an array of function pointers:
		I
	RP_MJ_CREATE (0x00)	Called when user calls CreateFile
		IRP_MJ_CLOSE (0x02)	Called when user calls CloseHandle
		IRP_MJ_DEVICE_CONTROL (0x0E)	Called when user calls DeviceIoControl
	*/
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

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

	// Removing driver link
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\CosmosLink");
	IoDeleteSymbolicLink(&symLink);

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