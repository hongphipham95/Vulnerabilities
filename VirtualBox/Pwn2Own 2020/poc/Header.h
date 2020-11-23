#define IN_RING0

#include <ntifs.h>
#include <ntddk.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "asm-amd64-x86.h"
#include "VUSBInternal.h"

#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos)	(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define IOCTL_TYPE 40000
#define IOCTL_FUZZZZ CTL_CODE( IOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_POST_EXPLOIT CTL_CODE( IOCTL_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define NT_DEVICE_NAME      L"\\Device\\vboxPwn"
#define DOS_DEVICE_NAME     L"\\DosDevices\\vboxPwn"

typedef struct OHCIBUF
{
    /** Pages involved. */
    struct OHCIBUFVEC
    {
        /** The 32-bit physical address of this part. */
        uint32_t Addr;
        /** The length. */
        uint32_t cb;
    } aVecs[2];
    /** Number of valid entries in aVecs. */
    uint32_t    cVecs;
    /** The total length. */
    uint32_t    cbTotal;
} OHCIBUF, * POHCIBUF;

typedef struct OHCIED
{
    /** Flags and stuff. */
    uint32_t hwinfo;
    /** TailP - TD Queue Tail pointer. Bits 0-3 ignored / preserved. */
    uint32_t TailP;
    /** HeadP - TD Queue head pointer. Bit 0 - Halted, Bit 1 - toggleCarry. Bit 2&3 - 0. */
    uint32_t HeadP;
    /** NextED - Next Endpoint Descriptor. Bits 0-3 ignored / preserved. */
    uint32_t NextED;
} OHCIED, * POHCIED;
typedef const OHCIED* PCOHCIED;

typedef struct OHCITD
{
    uint32_t hwinfo;
    /** CBP - Current Buffer Pointer. (32-bit physical address) */
    uint32_t cbp;
    /** NextTD - Link to the next transfer descriptor. (32-bit physical address, dword aligned) */
    uint32_t NextTD;
    /** BE - Buffer End (inclusive). (32-bit physical address) */
    uint32_t be;
} OHCITD, * POHCITD;
typedef const OHCITD* PCOHCITD;

typedef struct OHCITDENTRY
{
    /** The TD. */
    OHCITD      Td;
    /** The associated OHCI buffer tracker. */
    OHCIBUF     Buf;
    /** The TD address. */
    uint32_t    TdAddr;
    /** Pointer to the next element in the chain (stack). */
    struct OHCITDENTRY* pNext;
} OHCITDENTRY;


/* OHCI Local stuff */
#define OHCI_CTL_CBSR       ((1<<0)|(1<<1)) /* Control/Bulk Service Ratio. */
#define OHCI_CTL_PLE        (1<<2)          /* Periodic List Enable. */
#define OHCI_CTL_IE         (1<<3)          /* Isochronous Enable. */
#define OHCI_CTL_CLE        (1<<4)          /* Control List Enable. */
#define OHCI_CTL_BLE        (1<<5)          /* Bulk List Enable. */
#define OHCI_CTL_HCFS       ((1<<6)|(1<<7)) /* Host Controller Functional State. */
#define  OHCI_USB_RESET         0x00
#define  OHCI_USB_RESUME        0x40
#define  OHCI_USB_OPERATIONAL   0x80
#define  OHCI_USB_SUSPEND       0xc0
#define OHCI_CTL_IR         (1<<8)          /* Interrupt Routing (host/SMI). */
#define OHCI_CTL_RWC        (1<<9)          /* Remote Wakeup Connected. */
#define OHCI_CTL_RWE        (1<<10)         /* Remote Wakeup Enabled. */

#define OHCI_STATUS_HCR     (1<<0)          /* Host Controller Reset. */
#define OHCI_STATUS_CLF     (1<<1)          /* Control List Filled. */
#define OHCI_STATUS_BLF     (1<<2)          /* Bulk List Filled. */
#define OHCI_STATUS_OCR     (1<<3)          /* Ownership Change Request. */
#define OHCI_STATUS_SOC     ((1<<6)|(1<<7)) /* Scheduling Overrun Count. */

/** @name Interrupt Status and Enabled/Disabled Flags
* @{ */
/** SO  - Scheduling overrun. */
#define OHCI_INTR_SCHEDULING_OVERRUN        RT_BIT(0)
/** WDH - HcDoneHead writeback. */
#define OHCI_INTR_WRITE_DONE_HEAD           RT_BIT(1)
/** SF  - Start of frame. */
#define OHCI_INTR_START_OF_FRAME            RT_BIT(2)
/** RD  - Resume detect. */
#define OHCI_INTR_RESUME_DETECT             RT_BIT(3)
/** UE  - Unrecoverable error. */
#define OHCI_INTR_UNRECOVERABLE_ERROR       RT_BIT(4)
/** FNO - Frame number overflow. */
#define OHCI_INTR_FRAMENUMBER_OVERFLOW      RT_BIT(5)
/** RHSC- Root hub status change. */
#define OHCI_INTR_ROOT_HUB_STATUS_CHANGE    RT_BIT(6)
/** OC  - Ownership change. */
#define OHCI_INTR_OWNERSHIP_CHANGE          RT_BIT(30)
/** MIE - Master interrupt enable. */
#define OHCI_INTR_MASTER_INTERRUPT_ENABLED  RT_BIT(31)
/** @} */

#define OHCI_HCCA_SIZE      0x100
#define OHCI_HCCA_MASK      UINT32_C(0xffffff00)

#define OHCI_FMI_FI         UINT32_C(0x00003fff)    /* Frame Interval. */
#define OHCI_FMI_FSMPS      UINT32_C(0x7fff0000)    /* Full-Speed Max Packet Size. */
#define OHCI_FMI_FSMPS_SHIFT 16
#define OHCI_FMI_FIT        UINT32_C(0x80000000)    /* Frame Interval Toggle. */
#define OHCI_FMI_FIT_SHIFT  31

#define OHCI_FR_FRT         RT_BIT_32(31)           /* Frame Remaining Toggle */

#define OHCI_LS_THRESH      0x628                   /* Low-Speed Threshold. */

#define OHCI_RHA_NDP        (0xff)                  /* Number of Downstream Ports. */
#define OHCI_RHA_PSM        RT_BIT_32(8)            /* Power Switching Mode. */
#define OHCI_RHA_NPS        RT_BIT_32(9)            /* No Power Switching. */
#define OHCI_RHA_DT         RT_BIT_32(10)           /* Device Type. */
#define OHCI_RHA_OCPM       RT_BIT_32(11)           /* Over-Current Protection Mode. */
#define OHCI_RHA_NOCP       RT_BIT_32(12)           /* No Over-Current Protection. */
#define OHCI_RHA_POTPGP     UINT32_C(0xff000000)    /* Power On To Power Good Time. */

#define OHCI_RHS_LPS        RT_BIT_32(0)            /* Local Power Status. */
#define OHCI_RHS_OCI        RT_BIT_32(1)            /* Over-Current Indicator. */
#define OHCI_RHS_DRWE       RT_BIT_32(15)           /* Device Remote Wakeup Enable. */
#define OHCI_RHS_LPSC       RT_BIT_32(16)           /* Local Power Status Change. */
#define OHCI_RHS_OCIC       RT_BIT_32(17)           /* Over-Current Indicator Change. */
#define OHCI_RHS_CRWE       RT_BIT_32(31)           /* Clear Remote Wakeup Enable. */

/** @name HcRhPortStatus[n] - RH Port Status register (read).
* @{ */
/** CCS - CurrentConnectionStatus - 0 = no device, 1 = device. */
#define OHCI_PORT_CCS       RT_BIT(0)
/** ClearPortEnable (when writing CCS). */
#define OHCI_PORT_CLRPE     OHCI_PORT_CCS
/** PES - PortEnableStatus. */
#define OHCI_PORT_PES       RT_BIT(1)
/** PSS - PortSuspendStatus */
#define OHCI_PORT_PSS       RT_BIT(2)
/** POCI- PortOverCurrentIndicator. */
#define OHCI_PORT_POCI      RT_BIT(3)
/** ClearSuspendStatus (when writing POCI). */
#define OHCI_PORT_CLRSS     OHCI_PORT_POCI
/** PRS - PortResetStatus */
#define OHCI_PORT_PRS       RT_BIT(4)
/** PPS - PortPowerStatus */
#define OHCI_PORT_PPS       RT_BIT(8)
/** LSDA - LowSpeedDeviceAttached */
#define OHCI_PORT_LSDA      RT_BIT(9)
/** ClearPortPower (when writing LSDA). */
#define OHCI_PORT_CLRPP     OHCI_PORT_LSDA
/** CSC  - ConnectStatusChange */
#define OHCI_PORT_CSC       RT_BIT(16)
/** PESC - PortEnableStatusChange */
#define OHCI_PORT_PESC      RT_BIT(17)
/** PSSC - PortSuspendStatusChange */
#define OHCI_PORT_PSSC      RT_BIT(18)
/** OCIC - OverCurrentIndicatorChange */
#define OHCI_PORT_OCIC      RT_BIT(19)
/** PRSC - PortResetStatusChange */
#define OHCI_PORT_PRSC      RT_BIT(20)
/** The mask of RW1C bits. */
#define OHCI_PORT_CLEAR_CHANGE_MASK     (OHCI_PORT_CSC | OHCI_PORT_PESC | OHCI_PORT_PSSC | OHCI_PORT_OCIC | OHCI_PORT_PRSC)
/** @} */

#define ED_PTR_MASK         (~(uint32_t)0xf)
#define ED_HWINFO_MPS       0x07ff0000
#define ED_HWINFO_ISO       RT_BIT(15)
#define ED_HWINFO_SKIP      RT_BIT(14)
#define ED_HWINFO_LOWSPEED  RT_BIT(13)
#define ED_HWINFO_IN        RT_BIT(12)
#define ED_HWINFO_OUT       RT_BIT(11)
#define ED_HWINFO_DIR       (RT_BIT(11) | RT_BIT(12))
#define ED_HWINFO_ENDPOINT  0x780  /* 4 bits */
#define ED_HWINFO_ENDPOINT_SHIFT 7
#define ED_HWINFO_FUNCTION  0x7f /* 7 bits */
#define ED_HEAD_CARRY       RT_BIT(1)
#define ED_HEAD_HALTED      RT_BIT(0)

uint32_t HcRevision = 0;
uint32_t HcControl = 1;
uint32_t HcCommandStatus = 2;
uint32_t HcInterruptStatus = 3;
uint32_t HcInterruptEnable = 4;
uint32_t HcInterruptDisable = 5;
uint32_t HcHCCA = 6;
uint32_t HcPeriodCurrentED = 7;
uint32_t HcControlHeadED = 8;
uint32_t HcControlCurrentED = 9;
uint32_t HcBulkHeadED = 10;
uint32_t HcBulkCurrentED = 11;
uint32_t HcDoneHead = 12;
uint32_t HcFmInterval = 13;
uint32_t HcFmRemaining = 14;
uint32_t HcFmNumber = 15;
uint32_t HcPeriodicStart = 16;
uint32_t HcLSThreshold = 17;
uint32_t HcRhDescriptorA = 18;
uint32_t HcRhDescriptorB = 19;
uint32_t HcRhStatus = 20;
uint32_t HcRhPortStatus_0 = 21;

/** Error count (EC) shift. */
#define TD_ERRORS_SHIFT         26
/** Error count max. (One greater than what the EC field can hold.) */
#define TD_ERRORS_MAX           4

/** CC - Condition code mask. */
#define TD_HWINFO_CC            (UINT32_C(0xf0000000))
#define TD_HWINFO_CC_SHIFT      28
/** EC - Error count. */
#define TD_HWINFO_ERRORS        (RT_BIT(26) | RT_BIT(27))
/** T  - Data toggle. */
#define TD_HWINFO_TOGGLE        (RT_BIT(24) | RT_BIT(25))
#define TD_HWINFO_TOGGLE_HI     (RT_BIT(25))
#define TD_HWINFO_TOGGLE_LO     (RT_BIT(24))
/** DI - Delay interrupt. */
#define TD_HWINFO_DI            (RT_BIT(21) | RT_BIT(22) | RT_BIT(23))
#define TD_HWINFO_IN            (RT_BIT(20))
#define TD_HWINFO_OUT           (RT_BIT(19))
/** DP - Direction / PID. */
#define TD_HWINFO_DIR           (RT_BIT(19) | RT_BIT(20))
/** R  - Buffer rounding. */
#define TD_HWINFO_ROUNDING      (RT_BIT(18))
/** Bits that are reserved / unknown. */
#define TD_HWINFO_UNKNOWN_MASK  (UINT32_C(0x0003ffff))

/** SETUP - to endpoint. */
#define OHCI_TD_DIR_SETUP       0x0
/** OUT - to endpoint. */
#define OHCI_TD_DIR_OUT         0x1
/** IN - from endpoint. */
#define OHCI_TD_DIR_IN          0x2
/** Reserved. */
#define OHCI_TD_DIR_RESERVED    0x3


#define RCTL_BSEX           UINT32_C(0x02000000)

#include <stdint.h>

#define E1K_DTYP_LEGACY -1
#define E1K_DTYP_CONTEXT 0
#define E1K_DTYP_DATA    1
#define E1K_SPEC_VLAN(s)    (s      & 0xFFF)
#define E1K_SPEC_CFI(s) (!!((s>>12) & 0x1))
#define E1K_SPEC_PRI(s)    ((s>>13) & 0x7)
#define E1K_MAX_TX_PKT_SIZE    0x3fa0

struct E1kTDLegacy
{
    uint64_t u64BufAddr;                     /**< Address of data buffer */
    struct TDLCmd_st
    {
        unsigned u16Length : 16;
        unsigned u8CSO : 8;
        /* CMD field       : 8 */
        unsigned fEOP : 1;
        unsigned fIFCS : 1;
        unsigned fIC : 1;
        unsigned fRS : 1;
        unsigned fRPS : 1;
        unsigned fDEXT : 1;
        unsigned fVLE : 1;
        unsigned fIDE : 1;
    } cmd;
    struct TDLDw3_st
    {
        /* STA field */
        unsigned fDD : 1;
        unsigned fEC : 1;
        unsigned fLC : 1;
        unsigned fTURSV : 1;
        /* RSV field */
        unsigned u4RSV : 4;
        /* CSS field */
        unsigned u8CSS : 8;
        /* Special field*/
        unsigned u16Special : 16;
    } dw3;
};
struct E1kTDContext
{
    struct CheckSum_st
    {
        /** TSE: Header start. !TSE: Checksum start. */
        unsigned u8CSS : 8;
        /** Checksum offset - where to store it. */
        unsigned u8CSO : 8;
        /** Checksum ending (inclusive) offset, 0 = end of packet. */
        unsigned u16CSE : 16;
    } ip;
    struct CheckSum_st tu;
    struct TDCDw2_st
    {
        /** TSE: The total number of payload bytes for this context. Sans header. */
        unsigned u20PAYLEN : 20;
        /** The descriptor type - E1K_DTYP_CONTEXT (0). */
        unsigned u4DTYP : 4;
        /** TUCMD field, 8 bits
        * @{ */
        /** TSE: TCP (set) or UDP (clear). */
        unsigned fTCP : 1;
        /** TSE: IPv4 (set) or IPv6 (clear) - for finding the payload length field in
        * the IP header.  Does not affect the checksumming.
        * @remarks 82544GC/EI interprets a cleared field differently.  */
        unsigned fIP : 1;
        /** TSE: TCP segmentation enable.  When clear the context describes  */
        unsigned fTSE : 1;
        /** Report status (only applies to dw3.fDD for here). */
        unsigned fRS : 1;
        /** Reserved, MBZ. */
        unsigned fRSV1 : 1;
        /** Descriptor extension, must be set for this descriptor type. */
        unsigned fDEXT : 1;
        /** Reserved, MBZ. */
        unsigned fRSV2 : 1;
        /** Interrupt delay enable. */
        unsigned fIDE : 1;
        /** @} */
    } dw2;
    struct TDCDw3_st
    {
        /** Descriptor Done. */
        unsigned fDD : 1;
        /** Reserved, MBZ. */
        unsigned u7RSV : 7;
        /** TSO: The header (prototype) length (Ethernet[, VLAN tag], IP, TCP/UDP. */
        unsigned u8HDRLEN : 8;
        /** TSO: Maximum segment size. */
        unsigned u16MSS : 16;
    } dw3;
};
typedef struct E1kTDContext E1KTXCTX;
struct E1kTDData
{
    uint64_t u64BufAddr;                        /**< Address of data buffer */
    struct TDDCmd_st
    {
        /** The total length of data pointed to by this descriptor. */
        unsigned u20DTALEN : 20;
        /** The descriptor type - E1K_DTYP_DATA (1). */
        unsigned u4DTYP : 4;
        /** @name DCMD field, 8 bits (3.3.7.1).
        * @{ */
        /** End of packet.  Note TSCTFC update.  */
        unsigned fEOP : 1;
        /** Insert Ethernet FCS/CRC (requires fEOP to be set). */
        unsigned fIFCS : 1;
        /** Use the TSE context when set and the normal when clear. */
        unsigned fTSE : 1;
        /** Report status (dw3.STA). */
        unsigned fRS : 1;
        /** Reserved. 82544GC/EI defines this report packet set (RPS).  */
        unsigned fRPS : 1;
        /** Descriptor extension, must be set for this descriptor type. */
        unsigned fDEXT : 1;
        /** VLAN enable, requires CTRL.VME, auto enables FCS/CRC.
        *  Insert dw3.SPECIAL after ethernet header. */
        unsigned fVLE : 1;
        /** Interrupt delay enable. */
        unsigned fIDE : 1;
        /** @} */
    } cmd;
    struct TDDDw3_st
    {
        /** @name STA field (3.3.7.2)
        * @{  */
        unsigned fDD : 1;                       /**< Descriptor done. */
        unsigned fEC : 1;                      /**< Excess collision. */
        unsigned fLC : 1;                        /**< Late collision. */
        /** Reserved, except for the usual oddball (82544GC/EI) where it's called TU. */
        unsigned fTURSV : 1;
        /** @} */
        unsigned u4RSV : 4;                   /**< Reserved field, MBZ. */
        /** @name POPTS (Packet Option) field (3.3.7.3)
        * @{  */
        unsigned fIXSM : 1;                    /**< Insert IP checksum. */
        unsigned fTXSM : 1;               /**< Insert TCP/UDP checksum. */
        unsigned u6RSV : 6;                         /**< Reserved, MBZ. */
        /** @} */
        /** @name SPECIAL field - VLAN tag to be inserted after ethernet header.
        * Requires fEOP, fVLE and CTRL.VME to be set.
        * @{ */
        unsigned u16Special : 16;   /**< VLAN: Id, Canonical form, Priority. */
        /** @}  */
    } dw3;
};
typedef struct E1kTDData E1KTXDAT;
union E1kTxDesc
{
    struct E1kTDLegacy  legacy;
    struct E1kTDContext context;
    struct E1kTDData    data;
};
typedef union  E1kTxDesc E1KTXDESC;

typedef struct VUSBURBHDR
{
    /** List node for keeping the URB in the free list. */
    RTLISTNODE  NdFree;
    /** Size of the data allocated for the URB (Only the variable part including the
    * HCI and TDs). */
    size_t      cbAllocated;
    /** Age of the URB waiting on the list, if it is waiting for too long without being used
    * again it will be freed. */
    uint32_t    cAge;
#if HC_ARCH_BITS == 64
    uint32_t    u32Alignment0;
#endif
    /** The embedded URB. */
    VUSBURB     Urb;
} VUSBURBHDR;
/** Pointer to a URB header. */
typedef VUSBURBHDR* PVUSBURBHDR;

typedef enum VMMDevRequestType
{
    VMMDevReq_InvalidRequest = 0,
    VMMDevReq_GetMouseStatus = 1,
    VMMDevReq_SetMouseStatus = 2,
    VMMDevReq_SetPointerShape = 3,
    VMMDevReq_GetHostVersion = 4,
    VMMDevReq_Idle = 5,
    VMMDevReq_GetHostTime = 10,
    VMMDevReq_GetHypervisorInfo = 20,
    VMMDevReq_SetHypervisorInfo = 21,
    VMMDevReq_RegisterPatchMemory = 22, /**< @since version 3.0.6 */
    VMMDevReq_DeregisterPatchMemory = 23, /**< @since version 3.0.6 */
    VMMDevReq_SetPowerStatus = 30,
    VMMDevReq_AcknowledgeEvents = 41,
    VMMDevReq_CtlGuestFilterMask = 42,
    VMMDevReq_ReportGuestInfo = 50,
    VMMDevReq_ReportGuestInfo2 = 58, /**< @since version 3.2.0 */
    VMMDevReq_ReportGuestStatus = 59, /**< @since version 3.2.8 */
    VMMDevReq_ReportGuestUserState = 74, /**< @since version 4.3 */
    /**
    * Retrieve a display resize request sent by the host using
    * @a IDisplay:setVideoModeHint.  Deprecated.
    *
    * Similar to @a VMMDevReq_GetDisplayChangeRequest2, except that it only
    * considers host requests sent for the first virtual display.  This guest
    * request should not be used in new guest code, and the results are
    * undefined if a guest mixes calls to this and
    * @a VMMDevReq_GetDisplayChangeRequest2.
    */
    VMMDevReq_GetDisplayChangeRequest = 51,
    VMMDevReq_VideoModeSupported = 52,
    VMMDevReq_GetHeightReduction = 53,
    /**
    * Retrieve a display resize request sent by the host using
    * @a IDisplay:setVideoModeHint.
    *
    * Queries a display resize request sent from the host.  If the
    * @a eventAck member is sent to true and there is an unqueried
    * request available for one of the virtual display then that request will
    * be returned.  If several displays have unqueried requests the lowest
    * numbered display will be chosen first.  Only the most recent unseen
    * request for each display is remembered.
    * If @a eventAck is set to false, the last host request queried with
    * @a eventAck set is resent, or failing that the most recent received from
    * the host.  If no host request was ever received then all zeros are
    * returned.
    */
    VMMDevReq_GetDisplayChangeRequest2 = 54,
    VMMDevReq_ReportGuestCapabilities = 55,
    VMMDevReq_SetGuestCapabilities = 56,
    VMMDevReq_VideoModeSupported2 = 57, /**< @since version 3.2.0 */
    VMMDevReq_GetDisplayChangeRequestEx = 80, /**< @since version 4.2.4 */
    VMMDevReq_GetDisplayChangeRequestMulti = 81,
#ifdef VBOX_WITH_HGCM
    VMMDevReq_HGCMConnect = 60,
    VMMDevReq_HGCMDisconnect = 61,
    VMMDevReq_HGCMCall32 = 62,
    VMMDevReq_HGCMCall64 = 63,
# ifdef IN_GUEST
#  if   ARCH_BITS == 64
    VMMDevReq_HGCMCall = VMMDevReq_HGCMCall64,
#  elif ARCH_BITS == 32 || ARCH_BITS == 16
    VMMDevReq_HGCMCall = VMMDevReq_HGCMCall32,
#  else
#   error "Unsupported ARCH_BITS"
#  endif
# endif
    VMMDevReq_HGCMCancel = 64,
    VMMDevReq_HGCMCancel2 = 65,
#endif
    VMMDevReq_VideoAccelEnable = 70,
    VMMDevReq_VideoAccelFlush = 71,
    VMMDevReq_VideoSetVisibleRegion = 72,
    VMMDevReq_GetSeamlessChangeRequest = 73,
    VMMDevReq_QueryCredentials = 100,
    VMMDevReq_ReportCredentialsJudgement = 101,
    VMMDevReq_ReportGuestStats = 110,
    VMMDevReq_GetMemBalloonChangeRequest = 111,
    VMMDevReq_GetStatisticsChangeRequest = 112,
    VMMDevReq_ChangeMemBalloon = 113,
    VMMDevReq_GetVRDPChangeRequest = 150,
    VMMDevReq_LogString = 200,
    VMMDevReq_GetCpuHotPlugRequest = 210,
    VMMDevReq_SetCpuHotPlugStatus = 211,
    VMMDevReq_RegisterSharedModule = 212,
    VMMDevReq_UnregisterSharedModule = 213,
    VMMDevReq_CheckSharedModules = 214,
    VMMDevReq_GetPageSharingStatus = 215,
    VMMDevReq_DebugIsPageShared = 216,
    VMMDevReq_GetSessionId = 217, /**< @since version 3.2.8 */
    VMMDevReq_WriteCoreDump = 218,
    VMMDevReq_GuestHeartbeat = 219,
    VMMDevReq_HeartbeatConfigure = 220,
    VMMDevReq_NtBugCheck = 221,
    VMMDevReq_SizeHack = 0x7fffffff
} VMMDevRequestType;

typedef struct VMMDevRequestHeader
{
    /** IN: Size of the structure in bytes (including body).
    * (VBGLREQHDR uses this for input size and output if reserved1 is zero). */
    uint32_t size;
    /** IN: Version of the structure.  */
    uint32_t version;
    /** IN: Type of the request.
    * @note VBGLREQHDR uses this for optional output size. */
    VMMDevRequestType requestType;
    /** OUT: VBox status code. */
    int32_t  rc;
    /** Reserved field no.1. MBZ.
    * @note VBGLREQHDR uses this for optional output size, however never for a
    *       real VMMDev request, only in the I/O control interface. */
    uint32_t reserved1;
    /** IN: Requestor information (VMMDEV_REQUESTOR_XXX) when
    * VBOXGSTINFO2_F_REQUESTOR_INFO is set, otherwise ignored by the host. */
    uint32_t fRequestor;
} VMMDevRequestHeader;

#define VMMDEV_REQUEST_HEADER_VERSION (0x10001)

#define RCTL_LBM_MASK       UINT32_C(0x000000C0)
#define RCTL_LBM_SHIFT      6
#define RCTL_RDMTS_MASK     UINT32_C(0x00000300)
#define RCTL_RDMTS_SHIFT    8
#define RCTL_LBM_TCVR       UINT32_C(3)    


struct E1kRxDStatus
{
    /** @name Descriptor Status field (3.2.3.1)
    * @{ */
    unsigned fDD : 1;                             /**< Descriptor Done. */
    unsigned fEOP : 1;                               /**< End of packet. */
    unsigned fIXSM : 1;                  /**< Ignore checksum indication. */
    unsigned fVP : 1;                           /**< VLAN, matches VET. */
    unsigned : 1;
    unsigned fTCPCS : 1;       /**< RCP Checksum calculated on the packet. */
    unsigned fIPCS : 1;        /**< IP Checksum calculated on the packet. */
    unsigned fPIF : 1;                       /**< Passed in-exact filter */
    /** @} */
    /** @name Descriptor Errors field (3.2.3.2)
    * (Only valid when fEOP and fDD are set.)
    * @{ */
    unsigned fCE : 1;                      /**< CRC or alignment error. */
    unsigned : 4;    /**< Reserved, varies with different models... */
    unsigned fTCPE : 1;                      /**< TCP/UDP checksum error. */
    unsigned fIPE : 1;                           /**< IP Checksum error. */
    unsigned fRXE : 1;                               /**< RX Data error. */
    /** @} */
    /** @name Descriptor Special field (3.2.3.3)
    * @{  */
    unsigned u16Special : 16;      /**< VLAN: Id, Canonical form, Priority. */
    /** @} */
};
typedef struct E1kRxDStatus E1KRXDST;

struct E1kRxDesc_st
{
    uint64_t u64BufAddr;                        /**< Address of data buffer */
    uint16_t u16Length;                       /**< Length of data in buffer */
    uint16_t u16Checksum;                              /**< Packet checksum */
    E1KRXDST status;
};
typedef struct E1kRxDesc_st E1KRXDESC;

#define CTRL_RESET          UINT32_C(0x04000000)

#define E1K_REG_RCTL 0x00100

#define E1K_REG_RDBAL 0x02800
#define E1K_REG_RDBAH 0x02804
#define E1K_REG_RDH 0x02810
#define E1K_REG_RDT 0x02818

#define E1K_REG_TDBAL 0x03800
#define E1K_REG_TDBAH 0x03804
#define E1K_REG_TDH 0x03810
#define E1K_REG_TDT 0x03818