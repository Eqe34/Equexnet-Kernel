#include <ntifs.h>
#include <ntstrsafe.h>
#define NDIS630
#include <ndis.h>
#include <initguid.h>
#include <guiddef.h>

#pragma warning(push)
#pragma warning(disable:4201)
#include <fwpmk.h>
#include <fwpsk.h>
#pragma warning(pop)

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* SABİTLER */

#define EQUEX_POOL_TAG          'qxEE'
#define EQUEX_DEVICE_NAME       L"\\Device\\EquexNet"
#define EQUEX_SYMLINK_NAME      L"\\DosDevices\\EquexNet"
#define EQUEX_DEVICE_TYPE       0x8000

#define EQUEX_RING_BUFFER_SIZE  256
#define EQUEX_RING_MASK         (EQUEX_RING_BUFFER_SIZE - 1)
#define EQUEX_MAX_PACKET_SIZE   2048
#define EQUEX_TEMP_BUFFER_SIZE  2048

/* EQUEXNET V2 - stability baseline */
/* Packet capture is disabled by default until the WFP lifecycle is verified. */
#define EQUEX_ENABLE_PACKET_CAPTURE 0

#define EQUEX_MAX_BLOCKED_IPS   512
#define EQUEX_HASH_TABLE_SIZE   1024

  /* FWP_E_SUBLAYER_NOT_FOUND yerine STATUS_OBJECT_NAME_NOT_FOUND */
#ifndef FWP_E_SUBLAYER_NOT_FOUND
#define FWP_E_SUBLAYER_NOT_FOUND STATUS_OBJECT_NAME_NOT_FOUND
#endif

#define IOCTL_EQUEX_GET_PACKET      CTL_CODE(EQUEX_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_BLOCK_IP        CTL_CODE(EQUEX_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_UNBLOCK_IP      CTL_CODE(EQUEX_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_START_WFP       CTL_CODE(EQUEX_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_STOP_WFP        CTL_CODE(EQUEX_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_GET_STATS       CTL_CODE(EQUEX_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EQUEX_CLEAR_STATS     CTL_CODE(EQUEX_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* GUID'LER */

DEFINE_GUID(EQUEX_CALLOUT_GUID,
    0xA1B2C3D4, 0xE5F6, 0x7890, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89);

DEFINE_GUID(EQUEX_FILTER_GUID,
    0x98765432, 0x10FE, 0xDCBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA);

DEFINE_GUID(EQUEX_SUBLAYER_GUID,
    0xB3C4D5E6, 0xF7A8, 0x9B0C, 0xDE, 0xF1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD);

/* VERİ YAPILARI */

typedef struct _EQUEX_PACKET_ENTRY {
    volatile LONG    Length;
    UCHAR            Reserved[4];
    UCHAR            Data[EQUEX_MAX_PACKET_SIZE];
} EQUEX_PACKET_ENTRY;

C_ASSERT(sizeof(EQUEX_PACKET_ENTRY)* EQUEX_RING_BUFFER_SIZE < 1024 * 1024);

typedef struct _EQUEX_IP_ENTRY {
    LIST_ENTRY    ListEntry;
    ULONG         IpAddress;
    LARGE_INTEGER TimeAdded;
    volatile LONG HitCount;
} EQUEX_IP_ENTRY;

typedef struct _EQUEX_STATISTICS {
    volatile LONGLONG TotalPackets;
    volatile LONGLONG PermittedPackets;
    volatile LONGLONG BlockedPackets;
    volatile LONGLONG DroppedPackets;
    volatile LONGLONG MalformedPackets;
    volatile LONG     CurrentBlockedIPs;
    volatile LONG     RingBufferEntries;
    volatile LONGLONG LastPacketTime;
} EQUEX_STATISTICS;

typedef enum _EQUEX_DRIVER_STATE {
    EquexStateRunning = 0,
    EquexStateUnloading = 1,
    EquexStateUnloaded = 2
} EQUEX_DRIVER_STATE;

typedef struct _EQUEX_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;

    /* WFP Durumu */
    HANDLE         EngineHandle;
    UINT32         FwpsCalloutId;
    UINT32         FwpmCalloutId;
    UINT64         FilterId;
    BOOLEAN        SublayerAdded;
    volatile LONG  WfpInitialized;

    /* Ring Buffer */
    EQUEX_PACKET_ENTRY* RingBuffer;
    KSPIN_LOCK          RingLock;
    volatile ULONG      RingWriteIndex;
    volatile ULONG      RingReadIndex;

    /* IP Kara Liste */
    LIST_ENTRY          IpHashTable[EQUEX_HASH_TABLE_SIZE];
    KSPIN_LOCK          IpHashLocks[EQUEX_HASH_TABLE_SIZE];
    volatile LONG       BlockedIpCount;

    /* İstatistikler */
    EQUEX_STATISTICS    Stats;

    /* Senkronizasyon */
    KEVENT              CleanupCompleteEvent;
    volatile LONG       DriverState;
    volatile LONG       PendingClassifyCount;
    volatile BOOLEAN     CalloutUnregistered;
    EX_RUNDOWN_REF       ClassifyRundown;
    FAST_MUTEX           WfpLifecycleLock;
} EQUEX_DEVICE_EXTENSION;

typedef struct _EQUEX_IP_REQUEST {
    ULONG IpAddress;
} EQUEX_IP_REQUEST;

typedef struct _EQUEX_PACKET_RESPONSE {
    ULONG          Length;
    LARGE_INTEGER  Timestamp;
    UCHAR          Data[EQUEX_MAX_PACKET_SIZE];
} EQUEX_PACKET_RESPONSE;

typedef struct _EQUEX_TEMP_BUFFER {
    UCHAR Data[EQUEX_TEMP_BUFFER_SIZE];
} EQUEX_TEMP_BUFFER;

/* KERNEL HELPERS */

__forceinline BOOLEAN EquexValidateRingIndex(ULONG index)
{
    return index < EQUEX_RING_BUFFER_SIZE;
}

__forceinline ULONG EquexHashIp(ULONG ipAddress)
{
    ULONG hash = 2166136261UL;

    hash ^= (ipAddress & 0xFF);
    hash *= 16777619UL;
    hash ^= ((ipAddress >> 8) & 0xFF);
    hash *= 16777619UL;
    hash ^= ((ipAddress >> 16) & 0xFF);
    hash *= 16777619UL;
    hash ^= ((ipAddress >> 24) & 0xFF);
    hash *= 16777619UL;

    return hash & (EQUEX_HASH_TABLE_SIZE - 1);
}

__forceinline BOOLEAN EquexIsSpecialIp(ULONG ipAddress)
{
    ULONG firstOctet = ipAddress & 0xFF;
    ULONG lastOctet = (ipAddress >> 24) & 0xFF;

    if (ipAddress == 0 || ipAddress == 0xFFFFFFFFUL) {
        return TRUE;
    }

    /* 127.0.0.0/8 */
    if (firstOctet == 127) {
        return TRUE;
    }

    /* 224.0.0.0/4 */
    if (firstOctet >= 224 && firstOctet <= 239) {
        return TRUE;
    }

    UNREFERENCED_PARAMETER(lastOctet);
    return FALSE;
}

BOOLEAN EquexIsIpBlocked(
    EQUEX_DEVICE_EXTENSION* extension,
    ULONG ipAddress)
{
    ULONG hashIndex;
    KIRQL oldIrql;
    PLIST_ENTRY listHead;
    BOOLEAN found = FALSE;

    if (!extension) {
        return FALSE;
    }

    if (InterlockedCompareExchange(
        &extension->DriverState,
        EquexStateRunning,
        EquexStateRunning) != EquexStateRunning)
    {
        return FALSE;
    }

    hashIndex = EquexHashIp(ipAddress);

    KeAcquireSpinLock(&extension->IpHashLocks[hashIndex], &oldIrql);

    listHead = &extension->IpHashTable[hashIndex];

    for (PLIST_ENTRY entry = listHead->Flink;
        entry != listHead;
        entry = entry->Flink)
    {
        EQUEX_IP_ENTRY* ipEntry =
            CONTAINING_RECORD(entry, EQUEX_IP_ENTRY, ListEntry);

        if (ipEntry->IpAddress == ipAddress) {
            InterlockedIncrement(&ipEntry->HitCount);
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&extension->IpHashLocks[hashIndex], oldIrql);
    return found;
}

#if EQUEX_ENABLE_PACKET_CAPTURE

__forceinline BOOLEAN EquexIsMdlChainValid(PMDL mdl, ULONG maxDepth)
{
    ULONG depth = 0;
    PMDL current = mdl;

    while (current && depth < maxDepth) {
        if (MmGetMdlByteCount(current) == 0 ||
            MmGetMdlByteCount(current) > 65536)
        {
            return FALSE;
        }

        current = current->Next;
        depth++;
    }

    return current == NULL;
}

ULONG EquexCopyMdlToTempBuffer(
    NET_BUFFER* nb,
    PUCHAR tempBuffer,
    ULONG maxLen)
{
    ULONG totalCopied = 0;

    while (nb && totalCopied < maxLen) {
        PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);
        ULONG offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
        ULONG dataLength = NET_BUFFER_DATA_LENGTH(nb);
        ULONG copiedFromNb = 0;
        ULONG depth = 0;

        if (!mdl || dataLength == 0) {
            nb = NET_BUFFER_NEXT_NB(nb);
            continue;
        }

        while (mdl && copiedFromNb < dataLength &&
            totalCopied < maxLen && depth < 32)
        {
            ULONG mdlBytes = MmGetMdlByteCount(mdl);

            if (mdlBytes > offset) {
                ULONG available = mdlBytes - offset;
                ULONG wanted = dataLength - copiedFromNb;
                ULONG destinationRemaining = maxLen - totalCopied;
                ULONG toCopy = min(available, wanted);
                toCopy = min(toCopy, destinationRemaining);

                PVOID mapped = MmGetSystemAddressForMdlSafe(
                    mdl,
                    NormalPagePriority | MdlMappingNoExecute);

                if (!mapped) {
                    return totalCopied;
                }

                RtlCopyMemory(
                    tempBuffer + totalCopied,
                    (PUCHAR)mapped + offset,
                    toCopy);

                totalCopied += toCopy;
                copiedFromNb += toCopy;
            }

            mdl = mdl->Next;
            offset = 0;
            depth++;
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return totalCopied;
}

VOID EquexRingBufferWriteLocked(
    EQUEX_DEVICE_EXTENSION* extension,
    const UCHAR* data,
    ULONG length)
{
    KIRQL oldIrql;
    ULONG writeIdx;
    ULONG readIdx;
    ULONG nextWrite;

    if (!extension || !data ||
        length == 0 || length > EQUEX_MAX_PACKET_SIZE ||
        !extension->RingBuffer)
    {
        return;
    }

    KeAcquireSpinLock(&extension->RingLock, &oldIrql);

    writeIdx = extension->RingWriteIndex;
    readIdx = extension->RingReadIndex;

    if (!EquexValidateRingIndex(writeIdx) ||
        !EquexValidateRingIndex(readIdx))
    {
        extension->RingWriteIndex = 0;
        extension->RingReadIndex = 0;
        KeReleaseSpinLock(&extension->RingLock, oldIrql);
        return;
    }

    nextWrite = (writeIdx + 1) & EQUEX_RING_MASK;

    if (nextWrite == readIdx) {
        InterlockedIncrement64(&extension->Stats.DroppedPackets);
        KeReleaseSpinLock(&extension->RingLock, oldIrql);
        return;
    }

    EQUEX_PACKET_ENTRY* entry = &extension->RingBuffer[writeIdx];

    RtlCopyMemory(entry->Data, data, length);
    KeMemoryBarrier();
    entry->Length = (LONG)length;
    KeMemoryBarrier();

    extension->RingWriteIndex = nextWrite;

    ULONG entries =
        (extension->RingWriteIndex - extension->RingReadIndex) &
        EQUEX_RING_MASK;

    InterlockedExchange(&extension->Stats.RingBufferEntries, (LONG)entries);

    KeReleaseSpinLock(&extension->RingLock, oldIrql);
}

VOID EquexCapturePacketData(
    EQUEX_DEVICE_EXTENSION* extension,
    NET_BUFFER* nb)
{
    EQUEX_TEMP_BUFFER tempBuffer;
    ULONG copied;

    if (!extension || !nb) {
        return;
    }

    RtlZeroMemory(&tempBuffer, sizeof(tempBuffer));

    copied = EquexCopyMdlToTempBuffer(
        nb,
        tempBuffer.Data,
        sizeof(tempBuffer.Data));

    if (copied != 0) {
        EquexRingBufferWriteLocked(
            extension,
            tempBuffer.Data,
            copied);
    }
}

#endif /* EQUEX_ENABLE_PACKET_CAPTURE */

/* FORWARD DECLARATIONS */

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD EquexDriverUnload;
DRIVER_DISPATCH EquexDispatchCreateClose;
DRIVER_DISPATCH EquexDispatchDeviceControl;

/* [FIX #57] Doğru WFP callback imzası */
VOID NTAPI EquexClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);

    if (!classifyOut || !filter || !inFixedValues) {
        return;
    }

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        return;
    }

    /* rawContext is copied by BFE into FWPS_FILTER0.context. */
    EQUEX_DEVICE_EXTENSION* extension =
        (EQUEX_DEVICE_EXTENSION*)(ULONG_PTR)filter->context;

    if (!extension) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /* Protect extension-owned state against driver unload. */
    if (!ExAcquireRundownProtection(&extension->ClassifyRundown)) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    InterlockedIncrement(&extension->PendingClassifyCount);

    __try {
        if (InterlockedCompareExchange(
            &extension->DriverState,
            EquexStateRunning,
            EquexStateRunning) != EquexStateRunning)
        {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            __leave;
        }

        if (inFixedValues->layerId != FWPS_LAYER_INBOUND_IPPACKET_V4) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            __leave;
        }

        if (inFixedValues->valueCount <=
            FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS)
        {
            InterlockedIncrement64(&extension->Stats.MalformedPackets);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            __leave;
        }

        const FWP_VALUE0* remoteVal =
            &inFixedValues->incomingValue[
                FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS];

        if (remoteVal->type != FWP_UINT32) {
            InterlockedIncrement64(&extension->Stats.MalformedPackets);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            __leave;
        }

        ULONG srcIP = remoteVal->uint32;

        InterlockedIncrement64(&extension->Stats.TotalPackets);

        if (EquexIsSpecialIp(srcIP)) {
            InterlockedIncrement64(&extension->Stats.PermittedPackets);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            __leave;
        }

        if (EquexIsIpBlocked(extension, srcIP)) {
            InterlockedIncrement64(&extension->Stats.BlockedPackets);
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            __leave;
        }

        InterlockedIncrement64(&extension->Stats.PermittedPackets);
        classifyOut->actionType = FWP_ACTION_PERMIT;

#if EQUEX_ENABLE_PACKET_CAPTURE
        if (layerData && extension->RingBuffer) {
            NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerData;
            NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);

            if (nb) {
                EquexCapturePacketData(extension, nb);

                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                InterlockedExchange64(
                    &extension->Stats.LastPacketTime,
                    now.QuadPart);
            }
        }
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Fail open. Do not leave an undefined WFP action. */
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }

    InterlockedDecrement(&extension->PendingClassifyCount);
    ExReleaseRundownProtection(&extension->ClassifyRundown);
}

/* WFP Notify - doğru imza */

NTSTATUS NTAPI EquexNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* IP Ekleme */

NTSTATUS EquexAddBlockedIp(EQUEX_DEVICE_EXTENSION* extension, ULONG ipAddress)
{
    if (EquexIsSpecialIp(ipAddress)) {
        return STATUS_INVALID_PARAMETER;
    }

    EQUEX_IP_ENTRY* newEntry = (EQUEX_IP_ENTRY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EQUEX_IP_ENTRY),
        EQUEX_POOL_TAG);

    if (!newEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    newEntry->IpAddress = ipAddress;
    KeQuerySystemTime(&newEntry->TimeAdded);
    newEntry->HitCount = 0;

    ULONG hashIndex = EquexHashIp(ipAddress);
    KIRQL oldIrql;

    KeAcquireSpinLock(&extension->IpHashLocks[hashIndex], &oldIrql);

    if (extension->BlockedIpCount >= EQUEX_MAX_BLOCKED_IPS) {
        KeReleaseSpinLock(&extension->IpHashLocks[hashIndex], oldIrql);
        ExFreePoolWithTag(newEntry, EQUEX_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PLIST_ENTRY listHead = &extension->IpHashTable[hashIndex];
    BOOLEAN duplicate = FALSE;

    for (PLIST_ENTRY entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
        EQUEX_IP_ENTRY* ipEntry = CONTAINING_RECORD(entry, EQUEX_IP_ENTRY, ListEntry);
        if (ipEntry->IpAddress == ipAddress) {
            duplicate = TRUE;
            break;
        }
    }

    if (duplicate) {
        KeReleaseSpinLock(&extension->IpHashLocks[hashIndex], oldIrql);
        ExFreePoolWithTag(newEntry, EQUEX_POOL_TAG);
        return STATUS_DUPLICATE_OBJECTID;
    }

    InsertHeadList(listHead, &newEntry->ListEntry);
    InterlockedIncrement(&extension->BlockedIpCount);
    InterlockedExchange(
        &extension->Stats.CurrentBlockedIPs,
        InterlockedCompareExchange(&extension->BlockedIpCount, 0, 0));

    KeReleaseSpinLock(&extension->IpHashLocks[hashIndex], oldIrql);
    return STATUS_SUCCESS;
}

/* IP Silme */

NTSTATUS EquexRemoveBlockedIp(EQUEX_DEVICE_EXTENSION* extension, ULONG ipAddress)
{
    ULONG hashIndex = EquexHashIp(ipAddress);
    EQUEX_IP_ENTRY* removedEntry = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&extension->IpHashLocks[hashIndex], &oldIrql);

    PLIST_ENTRY listHead = &extension->IpHashTable[hashIndex];

    for (PLIST_ENTRY entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
        EQUEX_IP_ENTRY* ipEntry = CONTAINING_RECORD(entry, EQUEX_IP_ENTRY, ListEntry);
        if (ipEntry->IpAddress == ipAddress) {
            RemoveEntryList(entry);
            removedEntry = ipEntry;
            InterlockedDecrement(&extension->BlockedIpCount);
            InterlockedExchange(
                &extension->Stats.CurrentBlockedIPs,
                InterlockedCompareExchange(&extension->BlockedIpCount, 0, 0));
            break;
        }
    }

    KeReleaseSpinLock(&extension->IpHashLocks[hashIndex], oldIrql);

    if (removedEntry) {
        ExFreePoolWithTag(removedEntry, EQUEX_POOL_TAG);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

/* Tüm IP leri Temizle */

VOID EquexClearAllBlockedIps(EQUEX_DEVICE_EXTENSION* extension)
{
    LIST_ENTRY freeList;
    InitializeListHead(&freeList);

    for (ULONG i = 0; i < EQUEX_HASH_TABLE_SIZE; i++) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&extension->IpHashLocks[i], &oldIrql);

        PLIST_ENTRY listHead = &extension->IpHashTable[i];
        while (!IsListEmpty(listHead)) {
            PLIST_ENTRY entry = RemoveHeadList(listHead);
            InsertTailList(&freeList, entry);
        }

        KeReleaseSpinLock(&extension->IpHashLocks[i], oldIrql);
    }

    while (!IsListEmpty(&freeList)) {
        PLIST_ENTRY entry = RemoveHeadList(&freeList);
        EQUEX_IP_ENTRY* ipEntry = CONTAINING_RECORD(entry, EQUEX_IP_ENTRY, ListEntry);
        ExFreePoolWithTag(ipEntry, EQUEX_POOL_TAG);
    }

    InterlockedExchange(&extension->BlockedIpCount, 0);
    InterlockedExchange(&extension->Stats.CurrentBlockedIPs, 0);
}

/* WFP Temizleme */
VOID EquexCleanupWfp(EQUEX_DEVICE_EXTENSION* extension)
{
    if (!extension) {
        return;
    }

    ExAcquireFastMutex(&extension->WfpLifecycleLock);

    /* Stop accepting new classify calls before touching WFP state. */
    InterlockedExchange(&extension->DriverState, EquexStateUnloading);

    if (InterlockedCompareExchange(&extension->WfpInitialized, 0, 1) == 0) {
        ExWaitForRundownProtectionRelease(&extension->ClassifyRundown);
        InterlockedExchange(&extension->PendingClassifyCount, 0);
        ExReInitializeRundownProtection(&extension->ClassifyRundown);
        ExReleaseFastMutex(&extension->WfpLifecycleLock);
        return;
    }

    /* Delete filter first, then the management-plane callout and sublayer. */
    if (extension->FilterId != 0 && extension->EngineHandle) {
        (void)FwpmFilterDeleteById0(
            extension->EngineHandle,
            extension->FilterId);
        extension->FilterId = 0;
    }

    if (extension->FwpmCalloutId != 0 && extension->EngineHandle) {
        (void)FwpmCalloutDeleteById0(
            extension->EngineHandle,
            extension->FwpmCalloutId);
        extension->FwpmCalloutId = 0;
    }

    if (extension->SublayerAdded && extension->EngineHandle) {
        NTSTATUS status = FwpmSubLayerDeleteByKey0(
            extension->EngineHandle,
            &EQUEX_SUBLAYER_GUID);

        if (NT_SUCCESS(status) || status == FWP_E_SUBLAYER_NOT_FOUND) {
            extension->SublayerAdded = FALSE;
        }
    }

    if (extension->EngineHandle) {
        (void)FwpmEngineClose0(extension->EngineHandle);
        extension->EngineHandle = NULL;
    }

    /* Unregister the kernel callout after BFE no longer references it. */
    if (extension->FwpsCalloutId != 0) {
        (void)FwpsCalloutUnregisterById0(extension->FwpsCalloutId);
        extension->FwpsCalloutId = 0;
        extension->CalloutUnregistered = TRUE;
    }

    /* Drain callbacks that had already acquired the rundown reference. */
    ExWaitForRundownProtectionRelease(&extension->ClassifyRundown);
    ExReInitializeRundownProtection(&extension->ClassifyRundown);
    InterlockedExchange(&extension->PendingClassifyCount, 0);

    ExReleaseFastMutex(&extension->WfpLifecycleLock);
}

#pragma data_seg(pop)
#pragma code_seg(pop)

/* PAGED SECTION */

#pragma code_seg(push, "PAGE")

/* [DEBUG] WFP init sirasinda hangi cagrinin basarisiz oldugunu gormek icin. */
static VOID EquexLogStatus(
    const char* name,
    NTSTATUS status)
{
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[EQUEX] %s failed: NTSTATUS=0x%08X\n",
        name,
        status);
}

/* WFP Başlatma flags kaldırıldı */

NTSTATUS EquexInitializeWfp(EQUEX_DEVICE_EXTENSION* extension)
{
    PAGED_CODE();

    if (!extension) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&extension->WfpLifecycleLock);

    if (extension->DriverState == EquexStateUnloaded) {
        ExReleaseFastMutex(&extension->WfpLifecycleLock);
        return STATUS_DEVICE_NOT_READY;
    }

    if (InterlockedCompareExchange(&extension->WfpInitialized, 1, 0) != 0) {
        ExReleaseFastMutex(&extension->WfpLifecycleLock);
        return STATUS_ALREADY_INITIALIZED;
    }

    /* Resettable START_WFP is allowed while the device is not unloading. */
    InterlockedExchange(&extension->DriverState, EquexStateRunning);
    extension->CalloutUnregistered = FALSE;

    NTSTATUS status;

    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &extension->EngineHandle);

    if (!NT_SUCCESS(status)) {
        EquexLogStatus("FwpmEngineOpen0", status);
        goto Failure;
    }

    FWPM_SUBLAYER0 sublayer = { 0 };
    sublayer.subLayerKey = EQUEX_SUBLAYER_GUID;
    sublayer.displayData.name = L"EquexNet Sublayer";
    sublayer.weight = 0xFFFF;

    status = FwpmSubLayerAdd0(
        extension->EngineHandle,
        &sublayer,
        NULL);

    if (!NT_SUCCESS(status)) {
        EquexLogStatus("FwpmSubLayerAdd0", status);
        goto Failure;
    }

    extension->SublayerAdded = TRUE;

    FWPS_CALLOUT0 callout = { 0 };
    callout.calloutKey = EQUEX_CALLOUT_GUID;
    callout.classifyFn = EquexClassify;
    callout.notifyFn = EquexNotify;

    status = FwpsCalloutRegister0(
        extension->DeviceObject,
        &callout,
        &extension->FwpsCalloutId);

    if (!NT_SUCCESS(status)) {
        EquexLogStatus("FwpsCalloutRegister0", status);
        goto Failure;
    }

    FWPM_CALLOUT0 mCallout = { 0 };
    mCallout.calloutKey = EQUEX_CALLOUT_GUID;
    mCallout.displayData.name = L"EquexNet Callout";
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4;

    status = FwpmCalloutAdd0(
        extension->EngineHandle,
        &mCallout,
        NULL,
        &extension->FwpmCalloutId);

    if (!NT_SUCCESS(status)) {
        EquexLogStatus("FwpmCalloutAdd0", status);
        goto Failure;
    }

    FWPM_FILTER0 filter = { 0 };
    filter.filterKey = EQUEX_FILTER_GUID;
    filter.displayData.name = L"EquexNet Filter";
    filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
    filter.subLayerKey = EQUEX_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 255;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = EQUEX_CALLOUT_GUID;
    filter.rawContext = (UINT64)(ULONG_PTR)extension;
    filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;

    status = FwpmFilterAdd0(
        extension->EngineHandle,
        &filter,
        NULL,
        &extension->FilterId);

    if (!NT_SUCCESS(status)) {
        EquexLogStatus("FwpmFilterAdd0", status);
        goto Failure;
    }

    ExReleaseFastMutex(&extension->WfpLifecycleLock);
    return STATUS_SUCCESS;

Failure:
    if (extension->FilterId != 0 && extension->EngineHandle) {
        (void)FwpmFilterDeleteById0(
            extension->EngineHandle,
            extension->FilterId);
        extension->FilterId = 0;
    }

    if (extension->FwpmCalloutId != 0 && extension->EngineHandle) {
        (void)FwpmCalloutDeleteById0(
            extension->EngineHandle,
            extension->FwpmCalloutId);
        extension->FwpmCalloutId = 0;
    }

    if (extension->SublayerAdded && extension->EngineHandle) {
        (void)FwpmSubLayerDeleteByKey0(
            extension->EngineHandle,
            &EQUEX_SUBLAYER_GUID);
        extension->SublayerAdded = FALSE;
    }

    if (extension->EngineHandle) {
        (void)FwpmEngineClose0(extension->EngineHandle);
        extension->EngineHandle = NULL;
    }

    if (extension->FwpsCalloutId != 0) {
        (void)FwpsCalloutUnregisterById0(extension->FwpsCalloutId);
        extension->FwpsCalloutId = 0;
    }

    InterlockedExchange(&extension->WfpInitialized, 0);
    InterlockedExchange(&extension->DriverState, EquexStateRunning);
    extension->CalloutUnregistered = TRUE;

    ExReleaseFastMutex(&extension->WfpLifecycleLock);
    return status;
}

/* IRP dispatch */

NTSTATUS EquexDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS EquexDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PAGED_CODE();

    EQUEX_DEVICE_EXTENSION* extension = (EQUEX_DEVICE_EXTENSION*)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    ULONG ioctlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    if (extension->DriverState == EquexStateUnloading ||
        extension->DriverState == EquexStateUnloaded) {
        status = STATUS_DEVICE_NOT_READY;
        goto CompleteRequest;
    }

    switch (ioctlCode) {

    case IOCTL_EQUEX_START_WFP:
        status = EquexInitializeWfp(extension);
        break;

    case IOCTL_EQUEX_STOP_WFP:
        EquexCleanupWfp(extension);
        if (extension->DriverState == EquexStateUnloading) {
            InterlockedExchange(&extension->DriverState, EquexStateRunning);
        }
        break;

    case IOCTL_EQUEX_GET_PACKET:
    {
        if (!extension->RingBuffer) {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        if (outputLen < sizeof(EQUEX_PACKET_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            bytesReturned = sizeof(EQUEX_PACKET_RESPONSE);
            break;
        }

        PUCHAR tempData = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            EQUEX_MAX_PACKET_SIZE,
            EQUEX_POOL_TAG);

        if (!tempData) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ULONG packetLen = 0;
        LONGLONG timestamp = 0;

        KIRQL oldIrql;
        KeAcquireSpinLock(&extension->RingLock, &oldIrql);

        ULONG readIdx = extension->RingReadIndex;

        if (!EquexValidateRingIndex(readIdx)) {
            extension->RingReadIndex = 0;
            extension->RingWriteIndex = 0;
            status = STATUS_DATA_ERROR;
            KeReleaseSpinLock(&extension->RingLock, oldIrql);
            ExFreePoolWithTag(tempData, EQUEX_POOL_TAG);
            break;
        }

        if (readIdx == extension->RingWriteIndex) {
            status = STATUS_NO_MORE_ENTRIES;
            KeReleaseSpinLock(&extension->RingLock, oldIrql);
            ExFreePoolWithTag(tempData, EQUEX_POOL_TAG);
            break;
        }

        EQUEX_PACKET_ENTRY* entry = &extension->RingBuffer[readIdx];
        packetLen = entry->Length;

        if (packetLen > 0 && packetLen <= EQUEX_MAX_PACKET_SIZE) {
            RtlCopyMemory(tempData, entry->Data, packetLen);
            timestamp = extension->Stats.LastPacketTime;

            entry->Length = 0;
            extension->RingReadIndex = (readIdx + 1) & EQUEX_RING_MASK;

            ULONG entries = (extension->RingWriteIndex - extension->RingReadIndex) & EQUEX_RING_MASK;
            InterlockedExchange(&extension->Stats.RingBufferEntries, entries);

            status = STATUS_SUCCESS;
        }
        else {
            extension->RingReadIndex = (readIdx + 1) & EQUEX_RING_MASK;
            status = STATUS_DATA_ERROR;
        }

        KeReleaseSpinLock(&extension->RingLock, oldIrql);

        if (status == STATUS_SUCCESS) {
            __try {
                EQUEX_PACKET_RESPONSE* response =
                    (EQUEX_PACKET_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;

                response->Length = packetLen;
                response->Timestamp.QuadPart = timestamp;
                RtlCopyMemory(response->Data, tempData, packetLen);
                bytesReturned = sizeof(EQUEX_PACKET_RESPONSE);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                bytesReturned = 0;
            }
        }

        ExFreePoolWithTag(tempData, EQUEX_POOL_TAG);
    }
    break;

    case IOCTL_EQUEX_BLOCK_IP:
    {
        if (inputLen < sizeof(EQUEX_IP_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        EQUEX_IP_REQUEST* request = (EQUEX_IP_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
        status = EquexAddBlockedIp(extension, request->IpAddress);
        if (NT_SUCCESS(status)) {
            bytesReturned = sizeof(EQUEX_IP_REQUEST);
        }
    }
    break;

    case IOCTL_EQUEX_UNBLOCK_IP:
    {
        if (inputLen < sizeof(EQUEX_IP_REQUEST)) {
            EquexClearAllBlockedIps(extension);
            status = STATUS_SUCCESS;
        }
        else {
            EQUEX_IP_REQUEST* request = (EQUEX_IP_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
            status = EquexRemoveBlockedIp(extension, request->IpAddress);
        }
    }
    break;

    case IOCTL_EQUEX_GET_STATS:
    {
        if (outputLen < sizeof(EQUEX_STATISTICS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            bytesReturned = sizeof(EQUEX_STATISTICS);
            break;
        }

        EQUEX_STATISTICS* stats = (EQUEX_STATISTICS*)Irp->AssociatedIrp.SystemBuffer;

        __try {

            stats->TotalPackets = InterlockedCompareExchange64(&extension->Stats.TotalPackets, 0, 0);
            stats->PermittedPackets = InterlockedCompareExchange64(&extension->Stats.PermittedPackets, 0, 0);
            stats->BlockedPackets = InterlockedCompareExchange64(&extension->Stats.BlockedPackets, 0, 0);
            stats->DroppedPackets = InterlockedCompareExchange64(&extension->Stats.DroppedPackets, 0, 0);
            stats->MalformedPackets = InterlockedCompareExchange64(&extension->Stats.MalformedPackets, 0, 0);
            stats->CurrentBlockedIPs = InterlockedCompareExchange(&extension->BlockedIpCount, 0, 0);
            stats->RingBufferEntries = InterlockedCompareExchange(&extension->Stats.RingBufferEntries, 0, 0);
            stats->LastPacketTime = InterlockedCompareExchange64(&extension->Stats.LastPacketTime, 0, 0);

            bytesReturned = sizeof(EQUEX_STATISTICS);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            bytesReturned = 0;
        }
    }
    break;

    case IOCTL_EQUEX_CLEAR_STATS:
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&extension->RingLock, &oldIrql);

        InterlockedExchange64(&extension->Stats.TotalPackets, 0);
        InterlockedExchange64(&extension->Stats.PermittedPackets, 0);
        InterlockedExchange64(&extension->Stats.BlockedPackets, 0);
        InterlockedExchange64(&extension->Stats.DroppedPackets, 0);
        InterlockedExchange64(&extension->Stats.MalformedPackets, 0);
        InterlockedExchange(&extension->Stats.CurrentBlockedIPs, 0);
        InterlockedExchange(&extension->Stats.RingBufferEntries, 0);
        InterlockedExchange64(&extension->Stats.LastPacketTime, 0);

        KeReleaseSpinLock(&extension->RingLock, oldIrql);
    }
    break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

CompleteRequest:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* Driver Unload */

VOID EquexDriverUnload(PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    if (!deviceObject) {
        return;
    }

    EQUEX_DEVICE_EXTENSION* extension =
        (EQUEX_DEVICE_EXTENSION*)deviceObject->DeviceExtension;

    /* Stop new work first; cleanup then drains active WFP callbacks. */
    InterlockedExchange(&extension->DriverState, EquexStateUnloading);
    EquexCleanupWfp(extension);

    EquexClearAllBlockedIps(extension);

    if (extension->RingBuffer) {
        ExFreePoolWithTag(extension->RingBuffer, EQUEX_POOL_TAG);
        extension->RingBuffer = NULL;
    }

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, EQUEX_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    InterlockedExchange(&extension->DriverState, EquexStateUnloaded);
    IoDeleteDevice(deviceObject);
}

/* DRİVER ENTRY */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    EQUEX_DEVICE_EXTENSION* extension = NULL;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = EquexDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = EquexDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EquexDispatchDeviceControl;
    DriverObject->DriverUnload = EquexDriverUnload;

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, EQUEX_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(EQUEX_DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status)) return status;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    extension = (EQUEX_DEVICE_EXTENSION*)deviceObject->DeviceExtension;
    RtlZeroMemory(extension, sizeof(EQUEX_DEVICE_EXTENSION));

    extension->DeviceObject = deviceObject;
    extension->DriverState = EquexStateRunning;
    extension->CalloutUnregistered = FALSE;

    KeInitializeSpinLock(&extension->RingLock);
    KeInitializeEvent(&extension->CleanupCompleteEvent, NotificationEvent, FALSE);
    ExInitializeRundownProtection(&extension->ClassifyRundown);
    ExInitializeFastMutex(&extension->WfpLifecycleLock);

    for (ULONG i = 0; i < EQUEX_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&extension->IpHashTable[i]);
        KeInitializeSpinLock(&extension->IpHashLocks[i]);
    }

    extension->RingBuffer = (EQUEX_PACKET_ENTRY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EQUEX_PACKET_ENTRY) * EQUEX_RING_BUFFER_SIZE,
        EQUEX_POOL_TAG);

    if (!extension->RingBuffer) {
        IoDeleteDevice(deviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        extension->RingBuffer,
        sizeof(EQUEX_PACKET_ENTRY) * EQUEX_RING_BUFFER_SIZE);

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, EQUEX_SYMLINK_NAME);

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(extension->RingBuffer, EQUEX_POOL_TAG);
        IoDeleteDevice(deviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}

#pragma code_seg(pop)