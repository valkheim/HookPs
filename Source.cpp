#include <ntddk.h>

// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
constexpr auto PROCESS_SUSPEND_RESUME = 0x0800;

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\hookps");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\hookps");

PDEVICE_OBJECT DeviceObject = nullptr;

typedef NTSTATUS(*pPsSuspendProcess)(PEPROCESS Process);
pPsSuspendProcess fPsSuspendProcess = nullptr;

NTSTATUS InitializeExports()
{
	UNICODE_STRING PsSuspendProcessName = RTL_CONSTANT_STRING(L"PsSuspendProcess"); // exported by ntoskrnl but undocumented
	fPsSuspendProcess = (pPsSuspendProcess)MmGetSystemRoutineAddress(&PsSuspendProcessName);
	if (!fPsSuspendProcess)
		return STATUS_INSUFFICIENT_RESOURCES;

	return STATUS_SUCCESS;
}

// NtSuspendProcess reimplementation
// easier than locating KeServiceDescriptorTable to find the addr of NtSuspendProcess
// (especially on 64-bits system where it is not exported + patchguard nearby)
NTSTATUS NtSuspendProcess(_In_ HANDLE ProcessHandle)
{
	auto status = STATUS_SUCCESS;
	PEPROCESS Process = nullptr;

	if (!ProcessHandle)
		return STATUS_INSUFFICIENT_RESOURCES;

	// access validation on ProcessHandle
	status = ObReferenceObjectByHandle(
		ProcessHandle,
		PROCESS_SUSPEND_RESUME, // Not a documented access mask
		*PsProcessType,
		KernelMode,
		(PVOID *)&Process,
		nullptr
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

	KdPrint(("PSHook: process create: %ws\n", CreateInfo->ImageFileName->Buffer));
	if (wcsstr(CreateInfo->ImageFileName->Buffer, L"Calculator.exe") == nullptr)
		return;

	DbgPrint(("PSHook: nope!\n"));
	// CreateInfo->CreationStatus = STATUS_ACCESS_DENIED; // access denied popup :(
	NtSuspendProcess(Process);
}

NTSTATUS CompleteIrp(_In_ PIRP Irp, _In_opt_ NTSTATUS status = STATUS_SUCCESS, _In_opt_ ULONG_PTR info = 0)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS HandleCreateClose(_In_ PDEVICE_OBJECT, _In_ PIRP Irp)
{
	DbgPrint(("PSHook: create/close\n"));
	return CompleteIrp(Irp);
}

void Unload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(DeviceObject);
	DbgPrint(("PSHook: unloaded\n"));
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	auto status = STATUS_SUCCESS;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("PSHook: failed to create device\n"));
		return status;
	}

	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(("PSHook: failed to create symlink\n"));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// Pass /integritycheck linker flag
	status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
	if (!NT_SUCCESS(status)) {
		DbgPrint("PSHook: failed to register process callback\n");
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleCreateClose;

	DbgPrint(("PSHook loaded\n"));
	return status;
}