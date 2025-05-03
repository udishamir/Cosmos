#include "cosmos.h"

// Image load notification callback
extern "C"
VOID ImageLoadNotifyCallback(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
) {
	if (FullImageName) {
		// Find just the filename part (after last backslash)
		USHORT lastSlash = 0;

		// Make sure the FullImageName does not exceed MAX_PATH which is 256 * 2 since wide char 
		if (FullImageName->Length <= (MAX_PATH * sizeof(WCHAR))) {
			for (USHORT i = 0; i < FullImageName->Length / sizeof(WCHAR); i++) {
				if (FullImageName->Buffer[i] == L'\\') {
					lastSlash = i + 1;
				}
			}

			// Log the image load event
			DbgPrint("Cosmos: Image Loaded - PID: %llu, Name: %wZ\n",
				(ULONG64)ProcessId,
				FullImageName);

			// Log just the filename
			DbgPrint("Cosmos: Image Filename: %.*ws\n",
				(FullImageName->Length / sizeof(WCHAR)) - lastSlash,
				&FullImageName->Buffer[lastSlash]);
		}
		else {
			DbgPrint("Cosmos: Path Is Too Long, Image Loaded - PID: %llu, Name: %wZ\n",
				(ULONG64)ProcessId,
				FullImageName);
		}
	}
	else {
		DbgPrint("Cosmos: Image Loaded PID: %llu, Name: Unknown\n",
			(ULONG64)ProcessId);
	}

	// Log some information about the image
	DbgPrint("Cosmos: Image Base: 0x%p, Size: 0x%lx\n",
		ImageInfo->ImageBase,
		ImageInfo->ImageSize);

	// Check if this is a system DLL
	if (ImageInfo->SystemModeImage) {
		DbgPrint("Cosmos: This is a kernel-mode image\n");
	}
	else {
		DbgPrint("Cosmos: This is a user-mode image\n");
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
		DbgPrint("Cosmos: Process Created - Parent PID: %llu, PID: %llu\n",
			(ULONG64)ParentId,
			(ULONG64)ProcessId);
	}
	else {
		DbgPrint("Cosmos: Process Deleted - PID: %llu\n", (ULONG64)ProcessId);
	}
}

// Thread creation notification callback
extern "C"
VOID ThreadNotifyCallback(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
) {
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
}