#include <ntddk.h>

/*
We dont implement symbolic link. So there is no interface with user mode world.
No usual create/close nor read/write nor ioctl features.

todo: https://vxug.fakedoma.in/translations/FR/cacherdesdriverschargesavecDKOM.html
*/

// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
constexpr auto PROCESS_SUSPEND_RESUME = 0x0800;
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\dsrtk");
PDEVICE_OBJECT DeviceObject = nullptr;

// NtSuspendProcess reimplementation
// easier than locating KeServiceDescriptorTable to find the addr of NtSuspendProcess
// (especially on 64-bits system where it is not exported + patchguard nearby)
// Take a look at the ntoskrnl-ntsuspendprocess.PNG screenshot
typedef NTSTATUS(*pPsSuspendProcess)(PEPROCESS Process);
pPsSuspendProcess fPsSuspendProcess = nullptr;

NTSTATUS NtSuspendProcess(_In_ HANDLE ProcessHandle)
{
	auto status = STATUS_SUCCESS;
	PEPROCESS Process = nullptr;

	if (!ProcessHandle)
		return STATUS_INSUFFICIENT_RESOURCES;

	// access validation on ProcessHandle
	status = ObReferenceObjectByHandle( // WithTag
		ProcessHandle,			// Object handle
		PROCESS_SUSPEND_RESUME, // Not a documented access mask
		*PsProcessType,			// Type of pointer: process
		KernelMode,				// Object lives in the kernel
		(PVOID *)&Process,		// PEPROCESS
		nullptr					// NULL
	);
	if (!NT_SUCCESS(status))
		return status;

	if (!fPsSuspendProcess)
		return STATUS_INSUFFICIENT_RESOURCES;

	status = fPsSuspendProcess(Process); // PsSuspendProcess (ntoskrnl)
	ObDereferenceObject(Process); // free the referenced object
	return status;
}

void OnProcessNotify(_In_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);
	if (!CreateInfo)
		return;

	if (!CreateInfo->FileOpenNameAvailable || !CreateInfo->ImageFileName)
		return;

	DbgPrint("PSHook: process create: %ws\n", CreateInfo->ImageFileName->Buffer);
	if (wcsstr(CreateInfo->ImageFileName->Buffer, L"\\Calculator.exe") == nullptr)
		return;

	DbgPrint("PSHook: nope!\n");
	// CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
	NtSuspendProcess(Process);
}

NTSTATUS CompleteIrp(_In_ PIRP Irp, _In_opt_ NTSTATUS status = STATUS_SUCCESS, _In_opt_ ULONG_PTR info = 0)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(
		Irp,				// Pointer to the IRP to be completed
		IO_NO_INCREMENT		// 0
	);
	return status;
}

NTSTATUS HandleCreateClose(_In_ PDEVICE_OBJECT, _In_ PIRP Irp)
{
	DbgPrint("PSHook: create/close\n");
	return CompleteIrp(Irp);
}

void Unload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	IoDeleteDevice(DeviceObject);
	DbgPrint("PSHook: unloaded\n");
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	auto status = STATUS_SUCCESS;

	// PsSuspendProcess exported by ntoskrnl but undocumented (referenced by Geoff Chappell, undocumented.ntinternals.net, ReactOS)
	UNICODE_STRING PsSuspendProcessName = RTL_CONSTANT_STRING(L"PsSuspendProcess");
	// MmGetSystemRoutineAddress returns a ptr to the requested routine if present in kernel/HAL
	fPsSuspendProcess = (pPsSuspendProcess)MmGetSystemRoutineAddress(&PsSuspendProcessName);
	if (!fPsSuspendProcess)
	{
		DbgPrint("PSHook: cannot find PsSuspendProcess");
		return STATUS_NOT_FOUND;
	}
	
	status = IoCreateDevice(
		DriverObject,			// Pointer to the driver object to which this device belongs to
		0,						// extra bytes to allocate for struct DEVICE_OBJECT
		&DeviceName,			// internal device name (under ’Device’ Object Manager directory)
		FILE_DEVICE_UNKNOWN,	// device type is only relevant to some hardware drivers
		0,						// device characteristics, typically not used for software drivers
		FALSE,					// no exclusive client access
		&DeviceObject			// out ptr for the device object
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PSHook: failed to create device\n");
		return status;
	}

	// Pass /integritycheck linker flag
	status = PsSetCreateProcessNotifyRoutineEx(
		OnProcessNotify,	// Process create/exit notification routine
		FALSE				// We’re registering the callback
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PSHook: failed to register process callback\n");
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->DriverUnload = Unload;
	DbgPrint("PSHook loaded\n");
	return status;
}
