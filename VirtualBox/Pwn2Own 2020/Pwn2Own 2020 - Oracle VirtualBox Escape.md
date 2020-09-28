[TOC]

## Pwn2Own 2020 - Oracle VirtualBox Escape

### Blog

https://starlabs.sg/blog/2020/09/pwn2own-2020-oracle-virtualbox-escape/

### Affected Software

Oracle VirtualBox 6.1.4 and prior versions

### The Vulnerabilities Description

The exploit chain includes 2 vulnerabilities:

- Intel PRO 1000 MT Desktop (E1000) Network Adapter - Out-Of-Bounds Read Vulnerability
  - https://www.zerodayinitiative.com/advisories/ZDI-20-581/
- Open Host Controller Interface (OHCI) USB Controller - Uninitialized Variable
  - https://www.zerodayinitiative.com/advisories/ZDI-20-582/

#### Intel PRO 1000 MT Desktop (E1000) Network Adapter - Out-Of-Bounds Read Vulnerability 

For more information about the inner workings of the E1000 Network Adapter, you can read about it [here](https://github.com/hongphipham95/Vulnerabilities/blob/master/VirtualBox/Oracle%20VirtualBox%20Intel%20PRO%201000%20MT%20Desktop%20-%20Integer%20Underflow%20Vulnerability/Oracle%20VirtualBox%20Intel%20PRO%201000%20MT%20Desktop%20-%20Integer%20Underflow%20Vulnerability.md).

While sending an ethernet frame with the E1000 network adapter, we can control the insertion of the IP checksum by setting the `IXSM` bit in the Data Descriptor Option Field:

*VirtualBox-6.1.4\src\VBox\Devices\Network\DevE1000.cpp:5191*

~~~c++
static bool e1kLocateTxPacket(PE1KSTATE pThis)
{

...    
    
        E1KTXDESC *pDesc = &pThis->aTxDescriptors[i];
        switch (e1kGetDescType(pDesc))
        {

...                
                
            case E1K_DTYP_DATA:

...                
                
                if (cbPacket == 0)
                {
                    /*
                     * The first fragment: save IXSM and TXSM options
                     * as these are only valid in the first fragment.
                     */
                    pThis->fIPcsum  = pDesc->data.dw3.fIXSM;
                    pThis->fTCPcsum = pDesc->data.dw3.fTXSM;
                            fTSE     = pDesc->data.cmd.fTSE;

...                    
                    
}
~~~

With `pThis->fIPcsum` flag enabled, an IP checksum will be inserted to the ethernet frame:

*VirtualBox-6.1.4\src\VBox\Devices\Network\DevE1000.cpp:4997*

~~~c++
static int e1kXmitDesc(PPDMDEVINS pDevIns, PE1KSTATE pThis, PE1KSTATECC pThisCC, E1KTXDESC *pDesc,
                       RTGCPHYS addr, bool fOnWorkerThread)
{

...    

    switch (e1kGetDescType(pDesc))
    {

...            

        case E1K_DTYP_DATA:
        {
            STAM_COUNTER_INC(pDesc->data.cmd.fTSE?
                             &pThis->StatTxDescTSEData:
                             &pThis->StatTxDescData);
            E1K_INC_ISTAT_CNT(pThis->uStatDescDat);
            STAM_PROFILE_ADV_START(&pThis->CTX_SUFF_Z(StatTransmit), a);
            if (pDesc->data.cmd.u20DTALEN == 0 || pDesc->data.u64BufAddr == 0)
            {

...                
                
            }
            else
            {

...                
                
                else if (!pDesc->data.cmd.fTSE)
                {

...                    
                    
                            if (pThis->fIPcsum)
                                e1kInsertChecksum(pThis, (uint8_t *)pThisCC->CTX_SUFF(pTxSg)->aSegs[0].pvSeg, pThis->u16TxPktLen,
                                                  pThis->contextNormal.ip.u8CSO,
                                                  pThis->contextNormal.ip.u8CSS,
                                                  pThis->contextNormal.ip.u16CSE);
                            
                    
...                    
                    
}
~~~

Function `e1kInsertChecksum()` will computes the checksum and puts it in the frame body. The three fields `u8CSO`, `u8CSS` and `u16CSE` of `pThis->contextNormal` can be specified by the Context Descriptor:

*VirtualBox-6.1.4\src\VBox\Devices\Network\DevE1000.cpp:5158*

~~~c++
DECLINLINE(void) e1kUpdateTxContext(PE1KSTATE pThis, E1KTXDESC *pDesc)
{
    if (pDesc->context.dw2.fTSE)
    {

...        
        
    }
    else
    {
        pThis->contextNormal = pDesc->context;
        STAM_COUNTER_INC(&pThis->StatTxDescCtxNormal);
    }

...    
    
}
~~~

The implementation of function `e1kInsertChecksum()`:

*VirtualBox-6.1.4\src\VBox\Devices\Network\DevE1000.cpp:4155*

~~~c++
static void e1kInsertChecksum(PE1KSTATE pThis, uint8_t *pPkt, uint16_t u16PktLen, uint8_t cso, uint8_t css, uint16_t cse)
{
    RT_NOREF1(pThis);

    if (css >= u16PktLen)							// [1]
    {
        E1kLog2(("%s css(%X) is greater than packet length-1(%X), checksum is not inserted\n",
                 pThis->szPrf, cso, u16PktLen));
        return;
    }

    if (cso >= u16PktLen - 1)						// [2]
    {
        E1kLog2(("%s cso(%X) is greater than packet length-2(%X), checksum is not inserted\n",
                 pThis->szPrf, cso, u16PktLen));
        return;
    }

    if (cse == 0)									// [3]
        cse = u16PktLen - 1;
    else if (cse < css)								// [4]
    {
        E1kLog2(("%s css(%X) is greater than cse(%X), checksum is not inserted\n",
                 pThis->szPrf, css, cse));
        return;
    }

    uint16_t u16ChkSum = e1kCSum16(pPkt + css, cse - css + 1);
    E1kLog2(("%s Inserting csum: %04X at %02X, old value: %04X\n", pThis->szPrf,
             u16ChkSum, cso, *(uint16_t*)(pPkt + cso)));
    *(uint16_t*)(pPkt + cso) = u16ChkSum;
}
~~~

- `css` is the offset in the packet to start computing the checksum from, it needs to be less than `u16PktLen` which is the total size of the current packet (check `[1]`).
- `cse` is the offset in the packet to stop computing the checksum.
  - Setting `cse` field to 0 indicates that the checksum will cover from `css` to the end of the packet (check `[3]`).
  - `cse` needs to be larger than `css` (check `[4]`).
- `cso` is the offset in the packet to write the checksum at, it needs to be less than `u16PktLen - 1` (check `[2]`).

Since there is no check against the maximum value of `cse`, we can set this field to be larger than the total size of the current packet, lead to an out-of-bounds access and make `e1kCSum16()` function to calculate the checksum of the data right after the packet body `pPkt`. 

The "overread" checksum will be inserted into the ethernet frame and can be read by the receiver later.

##### Obtain Information Leakage

So if we want to leak some information from an overread checksum, we need a reliable way to know which data is adjacent to the overread buffer. In the emulated E1000 device, the transmit buffer is allocated by `e1kXmitAllocBuf()` function:

*VirtualBox-6.1.4\src\VBox\Devices\Network\DevE1000.cpp:3833*

~~~c++
DECLINLINE(int) e1kXmitAllocBuf(PE1KSTATE pThis, PE1KSTATECC pThisCC, bool fGso)
{

...    
    
    PPDMSCATTERGATHER pSg;
    if (RT_LIKELY(GET_BITS(RCTL, LBM) != RCTL_LBM_TCVR))			// [1]
    {

...        
        
        int rc = pDrv->pfnAllocBuf(pDrv, pThis->cbTxAlloc, fGso ? &pThis->GsoCtx : NULL, &pSg);

...        
        
    }
    else
    {
        /* Create a loopback using the fallback buffer and preallocated SG. */
        AssertCompileMemberSize(E1KSTATE, uTxFallback.Sg, 8 * sizeof(size_t));
        pSg = &pThis->uTxFallback.Sg;
        pSg->fFlags      = PDMSCATTERGATHER_FLAGS_MAGIC | PDMSCATTERGATHER_FLAGS_OWNER_3;
        pSg->cbUsed      = 0;
        pSg->cbAvailable = sizeof(pThis->aTxPacketFallback);
        pSg->pvAllocator = pThis;
        pSg->pvUser      = NULL; /* No GSO here. */
        pSg->cSegs       = 1;
        pSg->aSegs[0].pvSeg = pThis->aTxPacketFallback;				// [2]				
        pSg->aSegs[0].cbSeg = sizeof(pThis->aTxPacketFallback);
    }
    pThis->cbTxAlloc = 0;

    pThisCC->CTX_SUFF(pTxSg) = pSg;
    return VINF_SUCCESS;
}
~~~

The `LBM` (loopback mode) field in the `RCTL` register controls the loopback mode of the ethernet controller,  it affects how the packet buffer is allocated (see `[1]`):

- Without loopback mode: `e1kXmitAllocBuf()` uses  `pDrv->pfnAllocBuf()` callback to allocates the packet buffer, this callback will use either OS allocator or VirtualBox's custom one.
- With loopback mode: the packet buffer is the `aTxPacketFallback` array (see `[2]`).

The `aTxPacketFallback` array is a property of  the `PE1KSTATE pThis` object:

*VirtualBox-6.1.4\src\VBox\Devices\Network\DevE1000.cpp:1024*

~~~c++
typedef struct E1KSTATE
{

...
    
    /** TX: Transmit packet buffer use for TSE fallback and loopback. */
    uint8_t     aTxPacketFallback[E1K_MAX_TX_PKT_SIZE];
    /** TX: Number of bytes assembled in TX packet buffer. */
    uint16_t    u16TxPktLen;

...    
    
} E1KSTATE;
/** Pointer to the E1000 device state. */
typedef E1KSTATE *PE1KSTATE;
~~~

So by enabling the loopback mode:

- The packet receiver is us, we don't need another host to read the overread checksum.
- The packet buffer resided in the `pThis` object structure. So the overread data are the other fields of the `pThis` object.

Now we know which data is adjacent to the packet buffer, we can leak word-by-word with the following steps:

- Send a frame contains the crc16 checksum of `E1K_MAX_TX_PKT_SIZE` bytes, call it `crc0`.
- Send the second frame contains the checksum of `E1K_MAX_TX_PKT_SIZE + 2` bytes, call it `crc1`.
- Since the checksum algorithm is CRC16, by calculating the difference between `crc0` and `crc1`, we would know the value of the two bytes right after the `aTxPacketFallback` array.

Keep increasing the overread size by 2 bytes each time and doing this until we get some interesting data. Fortunately, after the `pThis` object, we can find a pointer to a global variable in the `VBoxDD.dll` module at offset `E1K_MAX_TX_PKT_SIZE + 0x1f7`.  

One small problem is in the `pThis` object, after the `aTxPacketFallback` array, there are other device's counter registers that keep increasing each time a frame is sent, so if we send two frames with a same overread size, it also results in two different checksums, but the counter increment is similar each time so this difference is predictable and can be equalized by adding `0x5a` to the second checksum.

#### Open Host Controller Interface (OHCI) USB Controller - Uninitialized Variable

You can read more about the VirtualBox OHCI device [here](https://github.com/hongphipham95/Vulnerabilities/blob/master/VirtualBox/Oracle%20VirtualBox%20OHCI%20Use-After-Free%20Vulnerability/Oracle%20VirtualBox%20OHCI%20Use-After-Free.md).

While sending a control message URB to the USB device, we can include a setup packet to update the message URB:

*VirtualBox-6.1.4\src\VBox\Devices\USB\VUSBUrb.cpp:834*

~~~c++
static int vusbUrbSubmitCtrl(PVUSBURB pUrb)
{

...    
    
    if (pUrb->enmDir == VUSBDIRECTION_SETUP)
    {
        LogFlow(("%s: vusbUrbSubmitCtrl: pPipe=%p state %s->SETUP\n",
                 pUrb->pszDesc, pPipe, g_apszCtlStates[pExtra->enmStage]));
        pExtra->enmStage = CTLSTAGE_SETUP;
    }

...    

    switch (pExtra->enmStage)
    {
        case CTLSTAGE_SETUP:

...            
            
            if (!vusbMsgSetup(pPipe, pUrb->abData, pUrb->cbData))
            {
                pUrb->enmState = VUSBURBSTATE_REAPED;
                pUrb->enmStatus = VUSBSTATUS_DNR;
                vusbUrbCompletionRh(pUrb);
                break;

...                
                
}
~~~

*VirtualBox-6.1.4\src\VBox\Devices\USB\VUSBUrb.cpp:664*

~~~c++
static bool vusbMsgSetup(PVUSBPIPE pPipe, const void *pvBuf, uint32_t cbBuf)
{
    PVUSBCTRLEXTRA  pExtra = pPipe->pCtrl;
    const VUSBSETUP *pSetupIn = (PVUSBSETUP)pvBuf;

...
    
    if (pExtra->cbMax < cbBuf + pSetupIn->wLength + sizeof(VUSBURBVUSBINT))		// [1]
    {
        uint32_t cbReq = RT_ALIGN_32(cbBuf + pSetupIn->wLength + sizeof(VUSBURBVUSBINT), 1024);
        PVUSBCTRLEXTRA pNew = (PVUSBCTRLEXTRA)RTMemRealloc(pExtra, RT_UOFFSETOF_DYN(VUSBCTRLEXTRA, Urb.abData[cbReq]));							// [2]
        if (!pNew)
        {
            Log(("vusbMsgSetup: out of memory!!! cbReq=%u %zu\n",
                 cbReq, RT_UOFFSETOF_DYN(VUSBCTRLEXTRA, Urb.abData[cbReq])));
            return false;
        }
        if (pExtra != pNew)
        {
            pNew->pMsg = (PVUSBSETUP)pNew->Urb.abData;
            pExtra = pNew;
            pPipe->pCtrl = pExtra;
        }
        pExtra->Urb.pVUsb = (PVUSBURBVUSB)&pExtra->Urb.abData[cbBuf + pSetupIn->wLength]; // [3]
        pExtra->Urb.pVUsb->pUrb = &pExtra->Urb;										  // [4]
        pExtra->cbMax = cbReq;
    }
    Assert(pExtra->Urb.enmState == VUSBURBSTATE_ALLOCATED);

    /*
     * Copy the setup data and prepare for data.
     */
    PVUSBSETUP pSetup = pExtra->pMsg;
    pExtra->fSubmitted      = false;
    pExtra->Urb.enmState    = VUSBURBSTATE_IN_FLIGHT;
    pExtra->pbCur           = (uint8_t *)(pSetup + 1);
    pSetup->bmRequestType   = pSetupIn->bmRequestType;
    pSetup->bRequest        = pSetupIn->bRequest;
    pSetup->wValue          = RT_LE2H_U16(pSetupIn->wValue);
    pSetup->wIndex          = RT_LE2H_U16(pSetupIn->wIndex);
    pSetup->wLength         = RT_LE2H_U16(pSetupIn->wLength);

...
    
    return true;
}
~~~

`pSetupIn` is our URB packet, `pExtra` is the current extra data for a control pipe, if the size of the setup request is larger than the size of the current control pipe extra data (check `[1]`),  `pExtra` will be reallocated with a bigger size at `[2]`. 

The original `pExtra` was allocated and initialized in `vusbMsgAllocExtraData()`:

*VirtualBox-6.1.4\src\VBox\Devices\USB\VUSBUrb.cpp:609*

~~~c++
static PVUSBCTRLEXTRA vusbMsgAllocExtraData(PVUSBURB pUrb)
{
/** @todo reuse these? */
    PVUSBCTRLEXTRA pExtra;
    const size_t cbMax = sizeof(VUSBURBVUSBINT) + sizeof(pExtra->Urb.abData) + sizeof(VUSBSETUP);
    pExtra = (PVUSBCTRLEXTRA)RTMemAllocZ(RT_UOFFSETOF_DYN(VUSBCTRLEXTRA, Urb.abData[cbMax]));
    if (pExtra)
    {

...        
        
        pExtra->Urb.pVUsb = (PVUSBURBVUSB)&pExtra->Urb.abData[sizeof(pExtra->Urb.abData) + sizeof(VUSBSETUP)];
        //pExtra->Urb.pVUsb->pCtrlUrb = NULL;
        //pExtra->Urb.pVUsb->pNext = NULL;
        //pExtra->Urb.pVUsb->ppPrev = NULL;
        pExtra->Urb.pVUsb->pUrb = &pExtra->Urb;
        pExtra->Urb.pVUsb->pDev = pUrb->pVUsb->pDev;		// [5]
        pExtra->Urb.pVUsb->pfnFree = vusbMsgFreeUrb;
        pExtra->Urb.pVUsb->pvFreeCtx = &pExtra->Urb;

...        
        
    }
    return pExtra;
}
~~~

Function `RTMemRealloc()` doesn't perform any initialization so the result buffer will contain two parts:

- Part A: The old and small `pExtra` body.
- Part B: The newly allocated with uninitialized data.

After the reallocation:

- The `pExtra->Urb.pVUsb` object will be updated with a new `pVUsb`, which is resided in part B ( at `[3]`) . 
- But the new `pVUsb` is resided in the uninitialized data and only `pVUsb->pUrb` is updated at `[4]`, 

So the other properties of `pExtra->Urb.pVUsb` object remain uninitialized, include the `pExtra->Urb.pVUsb->pDev` object (see `[5]`).

`pExtra->Urb` object will be used later in `vusbMsgDoTransfer()` function:

*VirtualBox-6.1.4\src\VBox\Devices\USB\VUSBUrb.cpp:752*

~~~c++
static void vusbMsgDoTransfer(PVUSBURB pUrb, PVUSBSETUP pSetup, PVUSBCTRLEXTRA pExtra, PVUSBPIPE pPipe)
{

...    
    
    int rc = vusbUrbQueueAsyncRh(&pExtra->Urb);

...    
    
}
~~~

*VirtualBox-6.1.4\src\VBox\Devices\USB\VUSBUrb.cpp:439*

~~~c++
int vusbUrbQueueAsyncRh(PVUSBURB pUrb)
{

...    
    
    PVUSBDEV pDev = pUrb->pVUsb->pDev;

...    
    
    int rc = pDev->pUsbIns->pReg->pfnUrbQueue(pDev->pUsbIns, pUrb);

...    
    
}
~~~

An access violation would happen while the VM host process dereferencing the uninitialized `pDev`. 

To take advance of the uninitialized object, we can perform a heap spraying before the reallocation then hope the `pDev` object will have resided in our data. 

Since there is a virtual table call and VirtualBox hasn't mitigated with CFG yet so we can combine the vulnerability and heap spraying with faked `pDev` objects to control the host process RIP. 

##### The Code Execution

By reading [this](https://starlabs.sg/blog/2020/04/adventures-in-hypervisor-oracle-virtualbox-research/) article, you would know how to perform a heap spraying and obtain the address range of the VRAM buffer in the host process, we will pick one address within this range as our faked `pDEv` pointer.

Then the full exploit flow will be like:

- Leak the `VBoxDD.dll` module base address using the E1000 vulnerability then collect some ROP gadgets.
- Our faked `pDEv` pointer is pointing to somewhere in the VRAM, so we prepare the VRAM with full of blocks, each block contains:
  - Aligned `PVUSBDEV` objects with fake vtable contain stack pivot gadgets to point the stack pointer to the host's VRAM buffer.
  - The Fake stack consists of a `WinExec` ROP chain.
- Spray the heap, fill the uninitialized memory with our picked VRAM address, which would make the `pExtra->Urb.pVUsb->pDev` object points to one of our faked `PVUSBDEV` objects.
- Trigger the OHCI vulnerability and execute the ROP chain.

### The Patches

- https://www.virtualbox.org/changeset/83613/vbox/trunk/src/VBox/Devices/Network/DevE1000.cpp
- https://www.virtualbox.org/changeset/83617/vbox/trunk/src/VBox/Devices/USB/VUSBUrb.cpp

