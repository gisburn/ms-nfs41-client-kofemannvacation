/* Copyright (c) 2010, 2011
 * The Regents of the University of Michigan
 * All Rights Reserved
 * 
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * Permission is granted to use, copy and redistribute this software
 * for noncommercial education and research purposes, so long as no
 * fee is charged, and so long as the name of the University of Michigan
 * is not used in any advertising or publicity pertaining to the use
 * or distribution of this software without specific, written prior
 * authorization.  Permission to modify or otherwise create derivative
 * works of this software is not granted.
 *
 * This software is provided as is, without representation or warranty
 * of any kind either express or implied, including without limitation
 * the implied warranties of merchantability, fitness for a particular
 * purpose, or noninfringement.  The Regents of the University of
 * Michigan shall not be liable for any damages, including special,
 * indirect, incidental, or consequential damages, with respect to any
 * claim arising out of or in connection with the use of the software,
 * even if it has been or is hereafter advised of the possibility of
 * such damages.
 */

#define MINIRDR__NAME "Value is ignored, only fact of definition"
#include <rx.h>
#include <windef.h>
#include <winerror.h>

#include <Ntstrsafe.h>

#include "nfs41_driver.h"
#include "nfs41_np.h"
#include "nfs41_debug.h"

#define USE_MOUNT_SEC_CONTEXT

/* debugging printout defines */
//#define DEBUG_OPEN
//#define DEBUG_CLOSE
//#define DEBUG_CACHE
//#define DEBUG_READ
//#define DEBUG_WRITE
//#define DEBUG_DIR_QUERY
//#define DEBUG_FILE_QUERY
//#define DEBUG_FILE_SET
//#define DEBUG_ACL_QUERY
//#define DEBUG_ACL_SET
//#define DEBUG_EA_QUERY
//#define DEBUG_EA_SET
//#define DEBUG_LOCK

//#define ENABLE_TIMINGS
//#define ENABLE_INDV_TIMINGS
#ifdef ENABLE_TIMINGS
typedef struct __nfs41_timings {
    LONG tops, sops;
    LONGLONG ticks, size;
} nfs41_timings;

nfs41_timings lookup, readdir, open, close, getattr, setattr, getacl, setacl, volume,
    read, write, lock, unlock, setexattr, getexattr;
#endif
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD nfs41_driver_unload;
DRIVER_DISPATCH ( nfs41_FsdDispatch );

struct _MINIRDR_DISPATCH nfs41_ops;
PRDBSS_DEVICE_OBJECT nfs41_dev;

#define FCB_BASIC_INFO_CACHED 0x0001
#define FCB_STANDARD_INFO_CACHED 0x0010

#define DISABLE_CACHING 0
#define ENABLE_READ_CACHING 1
#define ENABLE_WRITE_CACHING 2
#define ENABLE_READWRITE_CACHING 3

#define NFS41_MM_POOLTAG        ('nfs4')

KEVENT upcallEvent;
FAST_MUTEX upcallLock, downcallLock, srvopenLock;
FAST_MUTEX xidLock;
FAST_MUTEX openOwnerLock;

LONGLONG xid = 0;
LONG open_owner_id = 1;

#define DECLARE_CONST_ANSI_STRING(_var, _string) \
    const CHAR _var ## _buffer[] = _string; \
    const ANSI_STRING _var = { sizeof(_string) - sizeof(CHAR), \
        sizeof(_string), (PCH) _var ## _buffer }

DECLARE_CONST_ANSI_STRING(NfsV3Attributes, "NfsV3Attributes");
DECLARE_CONST_ANSI_STRING(NfsSymlinkTargetName, "NfsSymlinkTargetName");
DECLARE_CONST_ANSI_STRING(NfsActOnLink, "NfsActOnLink");

INLINE BOOL AnsiStrEq(
    IN const ANSI_STRING *lhs,
    IN const CHAR *rhs,
    IN const UCHAR rhs_len)
{
    return lhs->Length == rhs_len &&
        RtlCompareMemory(lhs->Buffer, rhs, rhs_len) == rhs_len;
}

typedef struct _nfs3_attrs {
    DWORD type, mode, nlink, uid, gid, filler1;
    LARGE_INTEGER size, used;
    struct {
        DWORD specdata1;
        DWORD specdata2;
    } rdev;
    LONGLONG fsid, fileid;
    LONGLONG atime, mtime, ctime;
} nfs3_attrs;
LARGE_INTEGER unix_time_diff; //needed to convert windows time to unix

enum ftype3 {
    NF3REG = 1,
    NF3DIR,
    NF3BLK,
    NF3CHR,
    NF3LNK,
    NF3SOCK,
    NF3FIFO
};

typedef enum _nfs41_updowncall_state {
    NFS41_WAITING_FOR_UPCALL,
    NFS41_WAITING_FOR_DOWNCALL,
    NFS41_DONE_PROCESSING,
    NFS41_NOT_WAITING
} nfs41_updowncall_state;

typedef struct _updowncall_entry {
    DWORD version;
    LONGLONG xid;
    DWORD opcode;
    NTSTATUS status;
    nfs41_updowncall_state state;
    FAST_MUTEX lock;
    LIST_ENTRY next;
    KEVENT cond;
    DWORD errno;
    BOOLEAN async_op;
    SECURITY_CLIENT_CONTEXT sec_ctx;
    PSECURITY_CLIENT_CONTEXT psec_ctx;
    HANDLE open_state;
    HANDLE session;
    PUNICODE_STRING filename;
    union {
        struct {
            PUNICODE_STRING srv_name;
            PUNICODE_STRING root;
            DWORD sec_flavor;
            DWORD rsize;
            DWORD wsize;
        } Mount;
        struct {                       
            PMDL MdlAddress;
            PVOID buf;
            LONGLONG offset;
            ULONG len;
            PRX_CONTEXT rxcontext;
            ULONGLONG ChangeTime;
        } ReadWrite;
        struct {
            LONGLONG offset;
            LONGLONG length;
            BOOLEAN exclusive;
            BOOLEAN blocking;
        } Lock;
        struct {
            ULONG count;
            LOWIO_LOCK_LIST locks;
        } Unlock;
        struct {
            FILE_BASIC_INFORMATION binfo;
            FILE_STANDARD_INFORMATION sinfo;
            PUNICODE_STRING filename;
            UNICODE_STRING symlink;
            ULONG access_mask;
            ULONG access_mode;
            ULONG attrs;
            ULONG copts;
            ULONG disp;
            ULONG cattrs;
            LONG open_owner_id;
            DWORD mode;
            ULONGLONG changeattr;
            HANDLE srv_open;
            DWORD deleg_type;
            BOOLEAN symlink_embedded;
        } Open;
        struct {
            PUNICODE_STRING filename;
            HANDLE srv_open;
            BOOLEAN remove;
            BOOLEAN renamed;
        } Close;
        struct {
            PUNICODE_STRING filter;
            PVOID buf;
            ULONG buf_len;
            FILE_INFORMATION_CLASS InfoClass;
            BOOLEAN restart_scan;
            BOOLEAN return_single;
            BOOLEAN initial_query;
            PMDL mdl;
            PVOID mdl_buf;
            ULONGLONG ChangeTime;
        } QueryFile;
        struct {
            PUNICODE_STRING filename;
            PVOID buf;
            ULONG buf_len;
            FILE_INFORMATION_CLASS InfoClass;
            ULONGLONG ChangeTime;
        } SetFile;
        struct {
            PUNICODE_STRING filename;
            PVOID buf;
            ULONG buf_len;
            DWORD mode;
            ULONGLONG ChangeTime;
        } SetEa;
        struct {
            PUNICODE_STRING filename;
            PVOID buf;
            ULONG buf_len;
            PVOID EaList;
            ULONG EaListLength;
            ULONG EaIndex;
            BOOLEAN ReturnSingleEntry;
            BOOLEAN RestartScan;
        } QueryEa;
        struct {
            PUNICODE_STRING filename;
            PUNICODE_STRING target;
            BOOLEAN set;
        } Symlink;
        struct {
            FS_INFORMATION_CLASS query;
            PVOID buf;
            ULONG buf_len;
        } Volume;
        struct {
            SECURITY_INFORMATION query;
            PVOID buf;
            DWORD buf_len;
            ULONGLONG ChangeTime;
        } Acl;
    } u;

} nfs41_updowncall_entry;

typedef struct _updowncall_list {
    LIST_ENTRY head;
} nfs41_updowncall_list;
nfs41_updowncall_list *upcall = NULL, *downcall = NULL;

typedef struct _nfs41_mount_entry {
    LIST_ENTRY next;
    LUID login_id;
    HANDLE authsys_session;
    HANDLE gss_session;
    HANDLE gssi_session;
    HANDLE gssp_session;
} nfs41_mount_entry;

typedef struct _nfs41_mount_list {
    LIST_ENTRY head;
} nfs41_mount_list;

#define nfs41_AddEntry(lock,pList,pEntry)                   \
            ExAcquireFastMutex(&lock);                      \
            InsertTailList(&pList->head, &(pEntry)->next);  \
            ExReleaseFastMutex(&lock);
#define nfs41_RemoveFirst(lock,pList,pEntry)                \
            ExAcquireFastMutex(&lock);                      \
            pEntry = (IsListEmpty(&pList->head)             \
            ? NULL                                          \
            : RemoveHeadList(&pList->head));                \
            ExReleaseFastMutex(&lock);
#define nfs41_RemoveEntry(lock,pList,pEntry)                \
            ExAcquireFastMutex(&lock);                      \
            RemoveEntryList(&pEntry->next);                 \
            ExReleaseFastMutex(&lock);                      
#define nfs41_IsListEmpty(lock,pList,flag)                  \
            ExAcquireFastMutex(&lock);                      \
            *flag = IsListEmpty(&pList->head);              \
            ExReleaseFastMutex(&lock);
#define nfs41_GetFirstEntry(lock,pList,pEntry)              \
            ExAcquireFastMutex(&lock);                      \
            pEntry = (IsListEmpty(&pList->head)             \
             ? NULL                                         \
             : (nfs41_updowncall_entry *)                   \
               (CONTAINING_RECORD(pList->head.Flink,        \
                                  nfs41_updowncall_entry,   \
                                  next)));                  \
            ExReleaseFastMutex(&lock);
#define nfs41_GetFirstMountEntry(lock,pList,pEntry)         \
            ExAcquireFastMutex(&lock);                      \
            pEntry = (IsListEmpty(&pList->head)             \
             ? NULL                                         \
             : (nfs41_mount_entry *)                        \
               (CONTAINING_RECORD(pList->head.Flink,        \
                                  nfs41_mount_entry,        \
                                  next)));                  \
            ExReleaseFastMutex(&lock);

/* In order to cooperate with other network providers,
 * we only claim paths of the format '\\server\nfs4\path' */
DECLARE_CONST_UNICODE_STRING(NfsPrefix, L"\\nfs4");
DECLARE_CONST_UNICODE_STRING(AUTH_SYS_NAME, L"sys");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5_NAME, L"krb5");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5I_NAME, L"krb5i");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5P_NAME, L"krb5p");
DECLARE_CONST_UNICODE_STRING(SLASH, L"\\");
DECLARE_CONST_UNICODE_STRING(EMPTY_STRING, L"");

#define SERVER_NAME_BUFFER_SIZE     1024

#define MOUNT_CONFIG_RW_SIZE_MIN        1024
#define MOUNT_CONFIG_RW_SIZE_DEFAULT    1048576
#define MOUNT_CONFIG_RW_SIZE_MAX        1048576
#define MAX_SEC_FLAVOR_LEN 12

typedef struct _NFS41_MOUNT_CONFIG {
    DWORD ReadSize;
    DWORD WriteSize;
    BOOLEAN ReadOnly;
    BOOLEAN write_thru;
    BOOLEAN nocache;
    WCHAR srv_buffer[SERVER_NAME_BUFFER_SIZE];
    UNICODE_STRING SrvName;
    WCHAR mntpt_buffer[MAX_PATH];
    UNICODE_STRING MntPt;
    WCHAR sec_flavor[MAX_SEC_FLAVOR_LEN];
    UNICODE_STRING SecFlavor;
} NFS41_MOUNT_CONFIG, *PNFS41_MOUNT_CONFIG;

typedef struct _NFS41_NETROOT_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    DWORD                   nfs41d_version;
    BOOLEAN                 mounts_init;
    FAST_MUTEX              mountLock;
    nfs41_mount_list        *mounts;
} NFS41_NETROOT_EXTENSION, *PNFS41_NETROOT_EXTENSION;
#define NFS41GetNetRootExtension(pNetRoot)      \
        (((pNetRoot) == NULL) ? NULL :          \
        (PNFS41_NETROOT_EXTENSION)((pNetRoot)->Context))

/* FileSystemName as reported by FileFsAttributeInfo query */
#define FS_NAME     L"NFS"
#define FS_NAME_LEN (sizeof(FS_NAME) - sizeof(WCHAR))
#define FS_ATTR_LEN (sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + FS_NAME_LEN)

/* FileSystemName as reported by FileFsAttributeInfo query */
#define VOL_NAME     L"PnfsVolume"
#define VOL_NAME_LEN (sizeof(VOL_NAME) - sizeof(WCHAR))
#define VOL_ATTR_LEN (sizeof(FILE_FS_VOLUME_INFORMATION) + VOL_NAME_LEN)

typedef struct _NFS41_V_NET_ROOT_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    HANDLE                  session;
    BYTE                    FsAttrs[FS_ATTR_LEN];
    LONG                    FsAttrsLen;
    DWORD                   sec_flavor;
    BOOLEAN                 read_only;
    BOOLEAN                 write_thru;
    BOOLEAN                 nocache;
#define STORE_MOUNT_SEC_CONTEXT
#ifdef STORE_MOUNT_SEC_CONTEXT
    SECURITY_CLIENT_CONTEXT mount_sec_ctx;
#endif
} NFS41_V_NET_ROOT_EXTENSION, *PNFS41_V_NET_ROOT_EXTENSION;
#define NFS41GetVNetRootExtension(pVNetRoot)      \
        (((pVNetRoot) == NULL) ? NULL :           \
        (PNFS41_V_NET_ROOT_EXTENSION)((pVNetRoot)->Context))

typedef struct _NFS41_FCB {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    ULONG                   Flags;
    FILE_BASIC_INFORMATION  BasicInfo;
    FILE_STANDARD_INFORMATION StandardInfo;
    BOOLEAN                 Renamed;
    DWORD                   mode;
    ULONGLONG                changeattr;
} NFS41_FCB, *PNFS41_FCB;
#define NFS41GetFcbExtension(pFcb)      \
        (((pFcb) == NULL) ? NULL : (PNFS41_FCB)((pFcb)->Context))

typedef struct _NFS41_FOBX {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;

    HANDLE nfs41_open_state;
    SECURITY_CLIENT_CONTEXT sec_ctx;
    PVOID acl;
    DWORD acl_len;
    LARGE_INTEGER time; 
    DWORD deleg_type;
} NFS41_FOBX, *PNFS41_FOBX;
#define NFS41GetFobxExtension(pFobx)  \
        (((pFobx) == NULL) ? NULL : (PNFS41_FOBX)((pFobx)->Context))

typedef struct _NFS41_SERVER_ENTRY {
    PMRX_SRV_CALL                 pRdbssSrvCall;
    WCHAR                         NameBuffer[SERVER_NAME_BUFFER_SIZE];
    UNICODE_STRING                Name;             // the server name.
} NFS41_SERVER_ENTRY, *PNFS41_SERVER_ENTRY;

typedef struct _NFS41_DEVICE_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    PRDBSS_DEVICE_OBJECT    DeviceObject;
    ULONG                   ActiveNodes;
    HANDLE                  SharedMemorySection;
    DWORD                   nfs41d_version;
    BYTE                    VolAttrs[VOL_ATTR_LEN];
    DWORD                   VolAttrsLen;
    HANDLE                  openlistHandle;
} NFS41_DEVICE_EXTENSION, *PNFS41_DEVICE_EXTENSION;

#define NFS41GetDeviceExtension(RxContext,pExt)        \
        PNFS41_DEVICE_EXTENSION pExt = (PNFS41_DEVICE_EXTENSION) \
        ((PBYTE)(RxContext->RxDeviceObject) + sizeof(RDBSS_DEVICE_OBJECT))

typedef struct _nfs41_srvopen_list_entry {
    LIST_ENTRY next;
    PMRX_SRV_OPEN srv_open;
    PNFS41_FOBX nfs41_fobx;
    ULONGLONG ChangeTime;
    BOOLEAN skip;
} nfs41_srvopen_list_entry;

typedef struct _nfs41_srvopen_list {
    LIST_ENTRY head;
} nfs41_srvopen_list;
nfs41_srvopen_list *openlist = NULL;

typedef enum _NULMRX_STORAGE_TYPE_CODES {
    NTC_NFS41_DEVICE_EXTENSION      =   (NODE_TYPE_CODE)0xFC00,    
} NFS41_STORAGE_TYPE_CODES;
#define RxDefineNode( node, type )          \
        node->NodeTypeCode = NTC_##type;    \
        node->NodeByteSize = sizeof(type);

#define RDR_NULL_STATE  0
#define RDR_UNLOADED    1
#define RDR_UNLOADING   2
#define RDR_LOADING     3
#define RDR_LOADED      4
#define RDR_STOPPED     5
#define RDR_STOPPING    6
#define RDR_STARTING    7
#define RDR_STARTED     8

nfs41_init_driver_state nfs41_init_state = NFS41_INIT_DRIVER_STARTABLE;
nfs41_start_driver_state nfs41_start_state = NFS41_START_DRIVER_STARTABLE;

NTSTATUS map_readwrite_errors(DWORD status);

void print_debug_header(
    PRX_CONTEXT RxContext)
{

    PIO_STACK_LOCATION IrpSp = RxContext->CurrentIrpSp;

    if (IrpSp) {
        DbgP("FileOject %p name %wZ\n", IrpSp->FileObject, 
            &IrpSp->FileObject->FileName);
        print_file_object(0, IrpSp->FileObject);
        print_irps_flags(0, RxContext->CurrentIrpSp);
    } else
        DbgP("Couldn't print FileObject IrpSp is NULL\n");

    print_fo_all(1, RxContext);
    if (RxContext->CurrentIrp)
        print_irp_flags(0, RxContext->CurrentIrp);
}

/* convert strings from unicode -> ansi during marshalling to
 * save space in the upcall buffers and avoid extra copies */
INLINE ULONG length_as_ansi(
    PCUNICODE_STRING str)
{
    return sizeof(str->MaximumLength) + RtlUnicodeStringToAnsiSize(str);
}

NTSTATUS marshall_unicode_as_ansi(
    IN OUT unsigned char **pos,
    IN PCUNICODE_STRING str)
{
    ANSI_STRING ansi;
    NTSTATUS status;

    /* convert the string directly into the upcall buffer */
    ansi.Buffer = (PCHAR)*pos + sizeof(ansi.MaximumLength);
    ansi.MaximumLength = (USHORT)RtlUnicodeStringToAnsiSize(str);
    status = RtlUnicodeStringToAnsiString(&ansi, str, FALSE);
    if (status)
        goto out;

    RtlCopyMemory(*pos, &ansi.MaximumLength, sizeof(ansi.MaximumLength));
    *pos += sizeof(ansi.MaximumLength);
    (*pos)[ansi.Length] = '\0';
    *pos += ansi.MaximumLength;
out:
    return status;
}

NTSTATUS marshal_nfs41_header(
    nfs41_updowncall_entry *entry,
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    header_len = sizeof(entry->version) + sizeof(entry->xid) + 
        sizeof(entry->opcode) + 2 * sizeof(HANDLE);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    else
        *len = header_len;
    RtlCopyMemory(tmp, &entry->version, sizeof(entry->version));
    tmp += sizeof(entry->version);
    RtlCopyMemory(tmp, &entry->xid, sizeof(entry->xid));
    tmp += sizeof(entry->xid);
    RtlCopyMemory(tmp, &entry->opcode, sizeof(entry->opcode));
    tmp += sizeof(entry->opcode);
    RtlCopyMemory(tmp, &entry->session, sizeof(HANDLE));
    tmp += sizeof(HANDLE);
    RtlCopyMemory(tmp, &entry->open_state, sizeof(HANDLE));
    tmp += sizeof(HANDLE);

    DbgP("[upcall header] xid=%lld opcode=%s filename=%wZ version=%d "
        "session=0x%x open_state=0x%x\n", entry->xid, 
        opcode2string(entry->opcode), entry->filename,
        entry->version, entry->session, entry->open_state);
out:
    return status;
}

const char* secflavorop2name(
    DWORD sec_flavor)
{
    switch(sec_flavor) {
    case RPCSEC_AUTH_SYS:      return "AUTH_SYS";
    case RPCSEC_AUTHGSS_KRB5:  return "AUTHGSS_KRB5";
    case RPCSEC_AUTHGSS_KRB5I: return "AUTHGSS_KRB5I";
    case RPCSEC_AUTHGSS_KRB5P: return "AUTHGSS_KRB5P";
    }

    return "UNKNOWN FLAVOR";
}
NTSTATUS marshal_nfs41_mount(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    /* 03/25/2011: Kernel crash to nfsd not running but mount upcall cued up */
    if (!MmIsAddressValid(entry->u.Mount.srv_name) || 
            !MmIsAddressValid(entry->u.Mount.root)) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    header_len = *len + length_as_ansi(entry->u.Mount.srv_name) +
        length_as_ansi(entry->u.Mount.root) + 3 * sizeof(DWORD);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_ansi(&tmp, entry->u.Mount.srv_name);
    if (status) goto out;
    status = marshall_unicode_as_ansi(&tmp, entry->u.Mount.root);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Mount.sec_flavor, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Mount.rsize, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Mount.wsize, sizeof(DWORD));

    *len = header_len;

    DbgP("marshal_nfs41_mount: server name=%wZ mount point=%wZ sec_flavor=%s "
         "rsize=%d wsize=%d\n", entry->u.Mount.srv_name, entry->u.Mount.root, 
         secflavorop2name(entry->u.Mount.sec_flavor), entry->u.Mount.rsize,
         entry->u.Mount.wsize);
out:
    return status;
}

NTSTATUS marshal_nfs41_unmount(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len) 
{
    return marshal_nfs41_header(entry, buf, buf_len, len);
}

NTSTATUS marshal_nfs41_open(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + length_as_ansi(entry->u.Open.filename) +
        5 * sizeof(ULONG) + sizeof(LONG) + sizeof(DWORD) + sizeof(HANDLE);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_ansi(&tmp, entry->u.Open.filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Open.access_mask, 
        sizeof(entry->u.Open.access_mask));
    tmp += sizeof(entry->u.Open.access_mask);
    RtlCopyMemory(tmp, &entry->u.Open.access_mode, 
        sizeof(entry->u.Open.access_mode));
    tmp += sizeof(entry->u.Open.access_mode);
    RtlCopyMemory(tmp, &entry->u.Open.attrs, sizeof(entry->u.Open.attrs));
    tmp += sizeof(entry->u.Open.attrs);
    RtlCopyMemory(tmp, &entry->u.Open.copts, sizeof(entry->u.Open.copts));
    tmp += sizeof(entry->u.Open.copts);
    RtlCopyMemory(tmp, &entry->u.Open.disp, sizeof(entry->u.Open.disp));
    tmp += sizeof(entry->u.Open.disp);
    RtlCopyMemory(tmp, &entry->u.Open.open_owner_id,
        sizeof(entry->u.Open.open_owner_id));
    tmp += sizeof(entry->u.Open.open_owner_id);
    RtlCopyMemory(tmp, &entry->u.Open.mode, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Open.srv_open, sizeof(HANDLE));

    *len = header_len;

    DbgP("marshal_nfs41_open: name=%wZ mask=0x%x access=0x%x attrs=0x%x "
         "opts=0x%x dispo=0x%x open_owner_id=0x%x mode=%o srv_open=%p\n", 
         entry->u.Open.filename, entry->u.Open.access_mask, 
         entry->u.Open.access_mode, entry->u.Open.attrs, entry->u.Open.copts, 
         entry->u.Open.disp, entry->u.Open.open_owner_id, entry->u.Open.mode,
         entry->u.Open.srv_open); 
out:
    return status;
}

NTSTATUS marshal_nfs41_rw(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len,
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(entry->u.ReadWrite.len) +
        sizeof(entry->u.ReadWrite.offset) + sizeof(HANDLE);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.ReadWrite.len, sizeof(entry->u.ReadWrite.len));
    tmp += sizeof(entry->u.ReadWrite.len);
    RtlCopyMemory(tmp, &entry->u.ReadWrite.offset, 
        sizeof(entry->u.ReadWrite.offset));
    tmp += sizeof(entry->u.ReadWrite.offset);
    __try {
        entry->u.ReadWrite.MdlAddress->MdlFlags |= MDL_MAPPING_CAN_FAIL;
        entry->u.ReadWrite.buf = 
            MmMapLockedPagesSpecifyCache(entry->u.ReadWrite.MdlAddress, 
                UserMode, MmNonCached, NULL, TRUE, NormalPagePriority);
        if (entry->u.ReadWrite.buf == NULL) {
            print_error("MmMapLockedPagesSpecifyCache failed to map pages\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        NTSTATUS code; 
        code = GetExceptionCode(); 
        print_error("Call to MmMapLocked failed due to exception 0x%x\n", code);
        status = STATUS_ACCESS_DENIED;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.ReadWrite.buf, sizeof(HANDLE));

    *len = header_len;

    DbgP("marshal_nfs41_rw: len=%u offset=%lu MdlAddress=%p Userspace=%p\n", 
         entry->u.ReadWrite.len, entry->u.ReadWrite.offset, 
         entry->u.ReadWrite.MdlAddress, entry->u.ReadWrite.buf);
out:
    return status;
}

NTSTATUS marshal_nfs41_lock(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;

    header_len = *len + 2 * sizeof(LONGLONG) + 2 * sizeof(BOOLEAN);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Lock.offset, sizeof(LONGLONG));
    tmp += sizeof(LONGLONG);
    RtlCopyMemory(tmp, &entry->u.Lock.length, sizeof(LONGLONG));
    tmp += sizeof(LONGLONG);
    RtlCopyMemory(tmp, &entry->u.Lock.exclusive, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.Lock.blocking, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);

    *len = header_len;

    DbgP("marshal_nfs41_lock: offset=%llx length=%llx exclusive=%u "
         "blocking=%u\n", entry->u.Lock.offset, entry->u.Lock.length,
         entry->u.Lock.exclusive, entry->u.Lock.blocking);
out:
    return status;
}

NTSTATUS marshal_nfs41_unlock(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;
    PLOWIO_LOCK_LIST lock;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;

    header_len = *len + sizeof(ULONG) + 
        entry->u.Unlock.count * 2 * sizeof(LONGLONG);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Unlock.count, sizeof(ULONG));
    tmp += sizeof(ULONG);

    lock = &entry->u.Unlock.locks;
    while (lock) {
        RtlCopyMemory(tmp, &lock->ByteOffset, sizeof(LONGLONG));
        tmp += sizeof(LONGLONG);
        RtlCopyMemory(tmp, &lock->Length, sizeof(LONGLONG));
        tmp += sizeof(LONGLONG);
        lock = lock->Next;
    }

    *len = header_len;

    DbgP("marshal_nfs41_unlock: count=%u\n", entry->u.Unlock.count);
out:
    return status;
}

NTSTATUS marshal_nfs41_close(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;


    header_len = *len + sizeof(BOOLEAN) + sizeof(HANDLE);
    if (entry->u.Close.remove)
        header_len += length_as_ansi(entry->u.Close.filename) +
            sizeof(BOOLEAN);

    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Close.remove, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.Close.srv_open, sizeof(HANDLE));
    if (entry->u.Close.remove) {
        tmp += sizeof(HANDLE);
        status = marshall_unicode_as_ansi(&tmp, entry->u.Close.filename);
        if (status) goto out;
        RtlCopyMemory(tmp, &entry->u.Close.renamed, sizeof(BOOLEAN));
    }

    *len = header_len;

    DbgP("marshal_nfs41_close: name=%wZ remove=%d srv_open=%p renamed=%d\n", 
        entry->u.Close.filename->Length?entry->u.Close.filename:&SLASH, 
        entry->u.Close.remove, entry->u.Close.srv_open, entry->u.Close.renamed);
out:
    return status;
}

NTSTATUS marshal_nfs41_dirquery(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;

    header_len = *len + 2 * sizeof(ULONG) + sizeof(HANDLE) +
        length_as_ansi(entry->u.QueryFile.filter) + 3 * sizeof(BOOLEAN);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    status = marshall_unicode_as_ansi(&tmp, entry->u.QueryFile.filter);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.QueryFile.initial_query, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryFile.restart_scan, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryFile.return_single, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    __try {
        entry->u.QueryFile.mdl_buf = 
            MmMapLockedPagesSpecifyCache(entry->u.QueryFile.mdl, 
                UserMode, MmNonCached, NULL, TRUE, NormalPagePriority);
        if (entry->u.QueryFile.mdl_buf == NULL) {
            print_error("MmMapLockedPagesSpecifyCache failed to map pages\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        NTSTATUS code; 
        code = GetExceptionCode(); 
        print_error("Call to MmMapLocked failed due to exception 0x%x\n", code);
        status = STATUS_ACCESS_DENIED;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryFile.mdl_buf, sizeof(HANDLE));
    *len = header_len;

    DbgP("marshal_nfs41_dirquery: filter='%wZ'class=%d len=%d "
         "1st\\restart\\single=%d\\%d\\%d\n", entry->u.QueryFile.filter, 
         entry->u.QueryFile.InfoClass, entry->u.QueryFile.buf_len, 
         entry->u.QueryFile.initial_query, entry->u.QueryFile.restart_scan, 
         entry->u.QueryFile.return_single);
out:
    return status;
}

NTSTATUS marshal_nfs41_filequery(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + 2 * sizeof(ULONG);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->session, sizeof(HANDLE));
    tmp += sizeof(HANDLE);
    RtlCopyMemory(tmp, &entry->open_state, sizeof(HANDLE));

    *len = header_len;

    DbgP("marshal_nfs41_filequery: class=%d\n", entry->u.QueryFile.InfoClass);
out:
    return status;
}

NTSTATUS marshal_nfs41_fileset(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + length_as_ansi(entry->u.SetFile.filename) +
        2 * sizeof(ULONG) + entry->u.SetFile.buf_len;
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_ansi(&tmp, entry->u.SetFile.filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.SetFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.SetFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->u.SetFile.buf, entry->u.SetFile.buf_len);
    tmp += entry->u.SetFile.buf_len;

    *len = header_len;

    DbgP("marshal_nfs41_fileset: filename='%wZ' class=%d\n",
        entry->u.SetFile.filename, entry->u.SetFile.InfoClass);
    print_hexbuf(0, (unsigned char *)"setfile buffer", entry->u.SetFile.buf,
        entry->u.SetFile.buf_len);
out:
    return status;
}

NTSTATUS marshal_nfs41_easet(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + length_as_ansi(entry->u.SetEa.filename) + 
        sizeof(ULONG) + entry->u.SetEa.buf_len  + sizeof(DWORD);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = marshall_unicode_as_ansi(&tmp, entry->u.SetEa.filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.SetEa.mode, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.SetEa.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->u.SetEa.buf, entry->u.SetEa.buf_len);
    
    *len = header_len;

    DbgP("marshal_nfs41_easet: filename=%wZ, buflen=%d mode=0x%x\n", 
        entry->u.SetEa.filename, entry->u.SetEa.buf_len, entry->u.SetEa.mode);
out:
    return status;
}

NTSTATUS marshal_nfs41_eaget(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else
        tmp += *len;
    header_len = *len + length_as_ansi(entry->u.QueryEa.filename) + 
        2 * sizeof(ULONG) + entry->u.QueryEa.EaListLength + 2 * sizeof(BOOLEAN);

    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = marshall_unicode_as_ansi(&tmp, entry->u.QueryEa.filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.QueryEa.EaIndex, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryEa.RestartScan, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryEa.ReturnSingleEntry, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryEa.EaListLength, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->u.QueryEa.EaList, entry->u.QueryEa.EaListLength);

    *len = header_len; 

    DbgP("marshal_nfs41_eaget: filename=%wZ, index=%d list_len=%d "
        "rescan=%d single=%d\n", entry->u.QueryEa.filename, 
        entry->u.QueryEa.EaIndex, entry->u.QueryEa.EaListLength, 
        entry->u.QueryEa.RestartScan, entry->u.QueryEa.ReturnSingleEntry);
out:
    return status;
}

NTSTATUS marshal_nfs41_symlink(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(BOOLEAN) +
        length_as_ansi(entry->u.Symlink.filename);
    if (entry->u.Symlink.set)
        header_len += length_as_ansi(entry->u.Symlink.target);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    marshall_unicode_as_ansi(&tmp, entry->u.Symlink.filename);
    RtlCopyMemory(tmp, &entry->u.Symlink.set, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    if (entry->u.Symlink.set)
        marshall_unicode_as_ansi(&tmp, entry->u.Symlink.target);

    *len = header_len;

    DbgP("marshal_nfs41_symlink: name %wZ symlink target %wZ\n", 
         entry->u.Symlink.filename, 
         entry->u.Symlink.set?entry->u.Symlink.target : NULL);
out:
    return status;
}

NTSTATUS marshal_nfs41_volume(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(FS_INFORMATION_CLASS);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Volume.query, sizeof(FS_INFORMATION_CLASS));
    *len = header_len;

    DbgP("marshal_nfs41_volume: class=%d\n", entry->u.Volume.query);
out:
    return status;
}

NTSTATUS marshal_nfs41_getacl(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(SECURITY_INFORMATION);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Acl.query, sizeof(SECURITY_INFORMATION));
    *len = header_len;

    DbgP("marshal_nfs41_getacl: class=0x%x\n", entry->u.Acl.query);
out:
    return status;
}

NTSTATUS marshal_nfs41_setacl(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(SECURITY_INFORMATION) +
        sizeof(ULONG) + entry->u.Acl.buf_len;
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Acl.query, sizeof(SECURITY_INFORMATION));
    tmp += sizeof(SECURITY_INFORMATION);
    RtlCopyMemory(tmp, &entry->u.Acl.buf_len, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, entry->u.Acl.buf, entry->u.Acl.buf_len);
    *len = header_len;

    DbgP("marshal_nfs41_setacl: class=0x%x sec_desc_len=%d\n", 
         entry->u.Acl.query, entry->u.Acl.buf_len);
out:
    return status;
}

NTSTATUS marshal_nfs41_shutdown(
    nfs41_updowncall_entry *entry, 
    unsigned char *buf, 
    ULONG buf_len, 
    ULONG *len) 
{
    return marshal_nfs41_header(entry, buf, buf_len, len);
}

NTSTATUS nfs41_invalidate_cache (
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    unsigned char *buf = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    ULONG flag = DISABLE_CACHING;
    PMRX_SRV_OPEN srv_open;

    DbgEn();
    RtlCopyMemory(&srv_open, buf, sizeof(HANDLE));

    DbgP("nfs41_invalidate_cache: received srv_open=%p\n", srv_open);
    if (MmIsAddressValid(srv_open))
        RxChangeBufferingState((PSRV_OPEN)srv_open, ULongToPtr(flag), 1);
    DbgEx();
    return status;
}

NTSTATUS handle_upcall(
    IN PRX_CONTEXT RxContext,
    IN nfs41_updowncall_entry *entry,
    OUT ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    ULONG cbOut = LowIoContext->ParamsFor.IoCtl.OutputBufferLength;
    unsigned char *pbOut = LowIoContext->ParamsFor.IoCtl.pOutputBuffer;

    status = SeImpersonateClientEx(entry->psec_ctx, NULL);
    if (status != STATUS_SUCCESS) {
        print_error("SeImpersonateClientEx failed %x\n", status);
        goto out;
    }

    switch(entry->opcode) {
    case NFS41_SHUTDOWN:
        status = marshal_nfs41_shutdown(entry, pbOut, cbOut, len);
        KeSetEvent(&entry->cond, 0, FALSE);
        break;
    case NFS41_MOUNT:
        status = marshal_nfs41_mount(entry, pbOut, cbOut, len);
        break;
    case NFS41_UNMOUNT:
        status = marshal_nfs41_unmount(entry, pbOut, cbOut, len);
        break;
    case NFS41_OPEN:
        status = marshal_nfs41_open(entry, pbOut, cbOut, len);
        break;
    case NFS41_READ:
        status = marshal_nfs41_rw(entry, pbOut, cbOut, len);
        break;
    case NFS41_WRITE:
        status = marshal_nfs41_rw(entry, pbOut, cbOut, len);
        break;
    case NFS41_LOCK:
        status = marshal_nfs41_lock(entry, pbOut, cbOut, len);
        break;
    case NFS41_UNLOCK:
        status = marshal_nfs41_unlock(entry, pbOut, cbOut, len);
        break;
    case NFS41_CLOSE:
        status = marshal_nfs41_close(entry, pbOut, cbOut, len);
        break;
    case NFS41_DIR_QUERY:
        status = marshal_nfs41_dirquery(entry, pbOut, cbOut, len);
        break;
    case NFS41_FILE_QUERY:
        status = marshal_nfs41_filequery(entry, pbOut, cbOut, len);
        break;
    case NFS41_FILE_SET:
        status = marshal_nfs41_fileset(entry, pbOut, cbOut, len);
        break;
    case NFS41_EA_SET:
        status = marshal_nfs41_easet(entry, pbOut, cbOut, len);
        break;
    case NFS41_EA_GET:
        status = marshal_nfs41_eaget(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYMLINK:
        status = marshal_nfs41_symlink(entry, pbOut, cbOut, len);
        break;
    case NFS41_VOLUME_QUERY:
        status = marshal_nfs41_volume(entry, pbOut, cbOut, len);
        break;
    case NFS41_ACL_QUERY:
        status = marshal_nfs41_getacl(entry, pbOut, cbOut, len);
        break;
    case NFS41_ACL_SET:
        status = marshal_nfs41_setacl(entry, pbOut, cbOut, len);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        print_error("Unknown nfs41 ops %d\n", entry->opcode);
    }

    if (status == STATUS_SUCCESS)
        print_hexbuf(0, (unsigned char *)"upcall buffer", pbOut, *len);

out:
    return status;
}

NTSTATUS nfs41_UpcallCreate(
    IN DWORD opcode,
    IN PSECURITY_CLIENT_CONTEXT clnt_sec_ctx,
    IN HANDLE session,
    IN HANDLE open_state,
    IN DWORD version,
    IN PUNICODE_STRING filename,
    OUT nfs41_updowncall_entry **entry_out)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    SECURITY_SUBJECT_CONTEXT sec_ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;

    entry = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_entry), 
                NFS41_MM_POOLTAG);
    if (entry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlZeroMemory(entry, sizeof(nfs41_updowncall_entry));
    entry->xid = InterlockedIncrement64(&xid);
    entry->opcode = opcode;
    entry->state = NFS41_WAITING_FOR_UPCALL;
    entry->session = session;
    entry->open_state = open_state;
    entry->version = version;
    if (filename && filename->Length) entry->filename = filename;
    else if (filename && !filename->Length) entry->filename = (PUNICODE_STRING)&SLASH;
    else entry->filename = (PUNICODE_STRING)&EMPTY_STRING;
    /*XXX KeInitializeEvent will bugcheck under verifier if allocated 
     * from PagedPool? */
    KeInitializeEvent(&entry->cond, SynchronizationEvent, FALSE);
    ExInitializeFastMutex(&entry->lock);

    if (clnt_sec_ctx == NULL) {
        SeCaptureSubjectContext(&sec_ctx);
        sec_qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        sec_qos.ImpersonationLevel = SecurityImpersonation;
        sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sec_qos.EffectiveOnly = 0;
        status = SeCreateClientSecurityFromSubjectContext(&sec_ctx, &sec_qos, 
                    1, &entry->sec_ctx);
        if (status != STATUS_SUCCESS) {
            print_error("nfs41_UpcallCreate: "
                "SeCreateClientSecurityFromSubjectContext failed with %x\n", 
                status);
            RxFreePool(entry);
        } else
            entry->psec_ctx = &entry->sec_ctx;
        SeReleaseSubjectContext(&sec_ctx);
    } else
        entry->psec_ctx = clnt_sec_ctx;

    *entry_out = entry;
out:
    return status;
}

NTSTATUS nfs41_UpcallWaitForReply(
    IN nfs41_updowncall_entry *entry)
{
    NTSTATUS status = STATUS_SUCCESS;

    nfs41_AddEntry(upcallLock, upcall, entry);
    KeSetEvent(&upcallEvent, 0, FALSE);
    if (!entry->async_op) {
        /* 02/03/2011 AGLO: it is not clear what the "right" waiting design 
         * should be. Having non-interruptable waiting seems to be the right 
         * approach. However, when things go wrong, the only wait to proceed 
         * is a reboot (since "waits" are not interruptable we can't stop a 
         * hung task. Having interruptable wait causes issues with security 
         * context. For now, I'm making CLOSE non-interruptable but keeping 
         * the rest interruptable so that we don't have to reboot all the time
         */
        /* 02/15/2011 cbodley: added NFS41_UNLOCK for the same reason. locking
         * tests were triggering an interrupted unlock, which led to a bugcheck
         * in CloseSrvOpen() */
#define MAKE_WAITONCLOSE_NONITERRUPTABLE
#ifdef MAKE_WAITONCLOSE_NONITERRUPTABLE
        if (entry->opcode == NFS41_CLOSE || entry->opcode == NFS41_UNLOCK)
            status = KeWaitForSingleObject(&entry->cond, Executive, 
                        KernelMode, FALSE, NULL);
        else
            status = KeWaitForSingleObject(&entry->cond, Executive, 
                        UserMode, TRUE, NULL);
#else

        status = KeWaitForSingleObject(&entry->cond, Executive, KernelMode, FALSE, NULL);
#endif
        print_wait_status(0, "[downcall]", status, opcode2string(entry->opcode), 
            entry, entry->xid);
    } else 
        goto out;

    switch(status) {
    case STATUS_SUCCESS: break;
    case STATUS_USER_APC:
    case STATUS_ALERTED:
    default:
        ExAcquireFastMutex(&entry->lock);
        if (entry->state == NFS41_DONE_PROCESSING) {
            ExReleaseFastMutex(&entry->lock);
            break;
        }
        DbgP("[upcall] abandoning %s entry=%p xid=%lld\n", 
            opcode2string(entry->opcode), entry, entry->xid);
        entry->state = NFS41_NOT_WAITING;
        ExReleaseFastMutex(&entry->lock);
        goto out;
    }
    nfs41_RemoveEntry(downcallLock, downcall, entry);
out:
    return status;
}

NTSTATUS nfs41_upcall(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry = NULL;
    ULONG len = 0;
    PLIST_ENTRY pEntry;

process_upcall:
    nfs41_RemoveFirst(upcallLock, upcall, pEntry);
    if (pEntry) {
        entry = (nfs41_updowncall_entry *)CONTAINING_RECORD(pEntry, 
                    nfs41_updowncall_entry, next);
        ExAcquireFastMutex(&entry->lock);
        nfs41_AddEntry(downcallLock, downcall, entry);
        status = handle_upcall(RxContext, entry, &len);
        if (status == STATUS_SUCCESS && 
                entry->state == NFS41_WAITING_FOR_UPCALL)
            entry->state = NFS41_WAITING_FOR_DOWNCALL;
        ExReleaseFastMutex(&entry->lock);
        if (status) {
            entry->status = status;
            KeSetEvent(&entry->cond, 0, FALSE);
            RxContext->InformationToReturn = 0;
        } else 
            RxContext->InformationToReturn = len;
    }
    else {
        status = KeWaitForSingleObject(&upcallEvent, Executive, UserMode, TRUE,
            (PLARGE_INTEGER) NULL);
        print_wait_status(0, "[upcall]", status, NULL, NULL, 0);
        switch (status) {
        case STATUS_SUCCESS: goto process_upcall;
        case STATUS_USER_APC:
        case STATUS_ALERTED:
        default: goto out;
        }
    }
out:
    return status;
}

void unmarshal_nfs41_header(
    nfs41_updowncall_entry *tmp,
    unsigned char **buf)
{
    RtlZeroMemory(tmp, sizeof(nfs41_updowncall_entry));

    RtlCopyMemory(&tmp->xid, *buf, sizeof(tmp->xid));
    *buf += sizeof(tmp->xid);
    RtlCopyMemory(&tmp->opcode, *buf, sizeof(tmp->opcode));
    *buf += sizeof(tmp->opcode);
    RtlCopyMemory(&tmp->status, *buf, sizeof(tmp->status));
    *buf += sizeof(tmp->status);
    RtlCopyMemory(&tmp->errno, *buf, sizeof(tmp->errno));
    *buf += sizeof(tmp->errno);
    DbgP("[downcall header] xid=%lld opcode=%s status=%d errno=%d\n", tmp->xid, 
        opcode2string(tmp->opcode), tmp->status, tmp->errno);
}

void unmarshal_nfs41_mount(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    RtlCopyMemory(&cur->session, *buf, sizeof(HANDLE));
    *buf += sizeof(HANDLE);
    RtlCopyMemory(&cur->version, *buf, sizeof(DWORD));
    DbgP("unmarshal_nfs41_mount: session pointer 0x%x version %d\n", cur->session, 
        cur->version);
}

VOID unmarshal_nfs41_setattr(
    nfs41_updowncall_entry *cur,
    PULONGLONG dest_buf,
    unsigned char **buf)
{
    RtlCopyMemory(dest_buf, *buf, sizeof(ULONGLONG));
    DbgP("unmarshal_nfs41_setattr: returned ChangeTime %llu\n", *dest_buf);
}

NTSTATUS unmarshal_nfs41_rw(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlCopyMemory(&cur->u.ReadWrite.len, *buf, sizeof(cur->u.ReadWrite.len));
    *buf += sizeof(cur->u.ReadWrite.len);
    RtlCopyMemory(&cur->u.ReadWrite.ChangeTime, *buf, sizeof(ULONGLONG));
    DbgP("unmarshal_nfs41_rw: returned len %lu ChangeTime %llu\n", 
        cur->u.ReadWrite.len, cur->u.ReadWrite.ChangeTime);
#if 1
    /* 08/27/2010: it looks like we really don't need to call 
        * MmUnmapLockedPages() eventhough we called 
        * MmMapLockedPagesSpecifyCache() as the MDL passed to us
        * is already locked. 
        */
    __try {
        MmUnmapLockedPages(cur->u.ReadWrite.buf, cur->u.ReadWrite.MdlAddress);
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        NTSTATUS code; 
        code = GetExceptionCode(); 
        print_error("Call to MmUnmapLockedPages failed due to"
            " exception 0x%0x\n", code);
        status = STATUS_ACCESS_DENIED;
    }
#endif
    return status;
}

NTSTATUS unmarshal_nfs41_open(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlCopyMemory(&cur->u.Open.binfo, *buf, sizeof(FILE_BASIC_INFORMATION));
    *buf += sizeof(FILE_BASIC_INFORMATION);
    RtlCopyMemory(&cur->u.Open.sinfo, *buf, sizeof(FILE_STANDARD_INFORMATION));
    *buf += sizeof(FILE_STANDARD_INFORMATION);
    RtlCopyMemory(&cur->open_state, *buf, sizeof(HANDLE));
    *buf += sizeof(HANDLE);
    RtlCopyMemory(&cur->u.Open.mode, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    RtlCopyMemory(&cur->u.Open.changeattr, *buf, sizeof(ULONGLONG));
    *buf += sizeof(ULONGLONG);
    RtlCopyMemory(&cur->u.Open.deleg_type, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    if (cur->errno == ERROR_REPARSE) {
        RtlCopyMemory(&cur->u.Open.symlink_embedded, *buf, sizeof(BOOLEAN));
        *buf += sizeof(BOOLEAN);
        RtlCopyMemory(&cur->u.Open.symlink.MaximumLength, *buf, 
            sizeof(USHORT));
        *buf += sizeof(USHORT);
        cur->u.Open.symlink.Length = cur->u.Open.symlink.MaximumLength -
            sizeof(WCHAR);
        cur->u.Open.symlink.Buffer = RxAllocatePoolWithTag(NonPagedPool, 
            cur->u.Open.symlink.MaximumLength, NFS41_MM_POOLTAG);
        if (cur->u.Open.symlink.Buffer == NULL) {
            cur->status = STATUS_INSUFFICIENT_RESOURCES;
            status = STATUS_UNSUCCESSFUL;
            goto out;
        }
        RtlCopyMemory(cur->u.Open.symlink.Buffer, *buf, 
            cur->u.Open.symlink.MaximumLength);
        DbgP("unmarshal_nfs41_open: ERROR_REPARSE -> '%wZ'\n", &cur->u.Open.symlink);
    }
    DbgP("unmarshal_nfs41_open: open_state 0x%x mode %o changeattr %llu "
        "deleg_type %d\n", cur->open_state, cur->u.Open.mode, 
        cur->u.Open.changeattr, cur->u.Open.deleg_type);
out:
    return status;
}

NTSTATUS unmarshal_nfs41_dirquery(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG buf_len;
    
    RtlCopyMemory(&buf_len, *buf, sizeof(ULONG));
    DbgP("unmarshal_nfs41_dirquery: reply size %d\n", buf_len);
    *buf += sizeof(ULONG);
    __try {
        MmUnmapLockedPages(cur->u.QueryFile.mdl_buf, cur->u.QueryFile.mdl);
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        NTSTATUS code; 
        code = GetExceptionCode(); 
        print_error("MmUnmapLockedPages thrown exception=0x%0x\n", code);
        status = STATUS_ACCESS_DENIED;
    }
    if (buf_len > cur->u.QueryFile.buf_len)
        cur->status = STATUS_BUFFER_TOO_SMALL;
    cur->u.QueryFile.buf_len = buf_len;

    return status;
}

void unmarshal_nfs41_attrget(
    nfs41_updowncall_entry *cur,
    PVOID attr_value,
    ULONG *attr_len,
    unsigned char **buf)
{
    ULONG buf_len;
    RtlCopyMemory(&buf_len, *buf, sizeof(ULONG));
    if (buf_len > *attr_len) {
        cur->status = STATUS_BUFFER_TOO_SMALL;        
        return;
    }
    *buf += sizeof(ULONG);
    *attr_len = buf_len;
    RtlCopyMemory(attr_value, *buf, buf_len);
    *buf += buf_len;
}

void unmarshal_nfs41_getattr(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    unmarshal_nfs41_attrget(cur, cur->u.QueryFile.buf, 
        &cur->u.QueryFile.buf_len, buf);
    RtlCopyMemory(&cur->u.QueryFile.ChangeTime, *buf, sizeof(LONGLONG));
    if (cur->u.QueryFile.InfoClass == FileBasicInformation)
        DbgP("[unmarshal_nfs41_getattr] ChangeTime %llu\n", cur->u.QueryFile.ChangeTime);
}

NTSTATUS unmarshal_nfs41_getacl(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD buf_len;

    RtlCopyMemory(&buf_len, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    cur->u.Acl.buf = RxAllocatePoolWithTag(NonPagedPool, 
        buf_len, NFS41_MM_POOLTAG);
    if (cur->u.Acl.buf == NULL) {
        cur->status = status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(cur->u.Acl.buf, *buf, buf_len);
    if (buf_len > cur->u.Acl.buf_len)
        cur->status = STATUS_BUFFER_TOO_SMALL;
    cur->u.Acl.buf_len = buf_len;

out:
    return status;
}

void unmarshal_nfs41_symlink(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    if (cur->u.Symlink.set)
        return;
    RtlCopyMemory(&cur->u.Symlink.target->Length, *buf, sizeof(USHORT));
    *buf += sizeof(USHORT);
    if (cur->u.Symlink.target->Length > 
            cur->u.Symlink.target->MaximumLength) {
        cur->status = STATUS_BUFFER_TOO_SMALL;
        return;
    }
    RtlCopyMemory(cur->u.Symlink.target->Buffer, *buf,
        cur->u.Symlink.target->Length);
    cur->u.Symlink.target->Length -= sizeof(UNICODE_NULL);
}

NTSTATUS nfs41_downcall(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    ULONG in_len = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
    unsigned char *buf = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    PLIST_ENTRY pEntry;
    nfs41_updowncall_entry *tmp, *cur= NULL;
    BOOLEAN found = 0;

    print_hexbuf(0, (unsigned char *)"downcall buffer", buf, in_len);

    tmp = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_entry), 
            NFS41_MM_POOLTAG);
    if (tmp == NULL)
        goto out;

    unmarshal_nfs41_header(tmp, &buf);

    ExAcquireFastMutex(&downcallLock); 
    pEntry = &downcall->head;
    pEntry = pEntry->Flink;
    while (pEntry != NULL) {
        cur = (nfs41_updowncall_entry *)CONTAINING_RECORD(pEntry, 
                nfs41_updowncall_entry, next);
        if (cur->xid == tmp->xid) {
            found = 1;
            break;
        }
        if (pEntry->Flink == &downcall->head)
            break;
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&downcallLock);
    SeStopImpersonatingClient();
    if (!found) {
        print_error("Didn't find xid=%lld entry\n", tmp->xid);
        goto out_free;
    }

    ExAcquireFastMutex(&cur->lock);    
    if (cur->state == NFS41_NOT_WAITING) {
        DbgP("[downcall] Nobody is waiting for this request!!!\n");
        switch(cur->opcode) {
        case NFS41_WRITE:
        case NFS41_READ:
            MmUnmapLockedPages(cur->u.ReadWrite.buf, 
                cur->u.ReadWrite.MdlAddress);
            break;
        case NFS41_DIR_QUERY:
            MmUnmapLockedPages(cur->u.QueryFile.mdl_buf, 
                    cur->u.QueryFile.mdl);
            IoFreeMdl(cur->u.QueryFile.mdl);
        }
        ExReleaseFastMutex(&cur->lock);
        nfs41_RemoveEntry(downcallLock, downcall, cur);
        RxFreePool(cur);
        status = STATUS_UNSUCCESSFUL;
        goto out_free;
    }
    cur->state = NFS41_DONE_PROCESSING;
    cur->status = tmp->status;
    cur->errno = tmp->errno;
    status = STATUS_SUCCESS;

    if (!tmp->status) {
        switch (tmp->opcode) {
        case NFS41_MOUNT:
            unmarshal_nfs41_mount(cur, &buf);
            break;
        case NFS41_WRITE:
        case NFS41_READ:
            status = unmarshal_nfs41_rw(cur, &buf);
            break;
        case NFS41_OPEN:
            status = unmarshal_nfs41_open(cur, &buf);
            break;
        case NFS41_DIR_QUERY:
            status = unmarshal_nfs41_dirquery(cur, &buf);
            break;
        case NFS41_FILE_QUERY:
            unmarshal_nfs41_getattr(cur, &buf);
            break;
        case NFS41_EA_GET:
            unmarshal_nfs41_attrget(cur, cur->u.QueryEa.buf, 
                &cur->u.QueryEa.buf_len, &buf);
            break;
        case NFS41_SYMLINK:
            unmarshal_nfs41_symlink(cur, &buf);
            break;
        case NFS41_VOLUME_QUERY:
            unmarshal_nfs41_attrget(cur, cur->u.Volume.buf, 
                &cur->u.Volume.buf_len, &buf);
            break;
        case NFS41_ACL_QUERY:
            status = unmarshal_nfs41_getacl(cur, &buf);
            break;
        case NFS41_FILE_SET:
            unmarshal_nfs41_setattr(cur, &cur->u.SetFile.ChangeTime, &buf);
            break;
        case NFS41_EA_SET:
            unmarshal_nfs41_setattr(cur, &cur->u.SetEa.ChangeTime, &buf);
            break;
        case NFS41_ACL_SET:
            unmarshal_nfs41_setattr(cur, &cur->u.Acl.ChangeTime, &buf);
            break;
        }
    }
    ExReleaseFastMutex(&cur->lock);
    if (cur->async_op) {
        if (cur->status == STATUS_SUCCESS) {
            cur->u.ReadWrite.rxcontext->StoredStatus = STATUS_SUCCESS;
            cur->u.ReadWrite.rxcontext->InformationToReturn = 
                cur->u.ReadWrite.len;
        } else {
            cur->u.ReadWrite.rxcontext->StoredStatus = 
                map_readwrite_errors(cur->status);
            cur->u.ReadWrite.rxcontext->InformationToReturn = 0;
        }
        nfs41_RemoveEntry(downcallLock, downcall, cur);
        RxLowIoCompletion(cur->u.ReadWrite.rxcontext);
    } else
        KeSetEvent(&cur->cond, 0, FALSE);    

out_free:
    RxFreePool(tmp);
out:
    return status;
}

NTSTATUS nfs41_shutdown_daemon(
    DWORD version)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry = NULL;

    DbgEn();
    status = nfs41_UpcallCreate(NFS41_SHUTDOWN, NULL, INVALID_HANDLE_VALUE,
        INVALID_HANDLE_VALUE, version, NULL, &entry);
    if (status)
        goto out;

    status = nfs41_UpcallWaitForReply(entry);
    SeDeleteClientSecurity(&entry->sec_ctx);
    if (status != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS SharedMemoryInit(
    OUT PHANDLE phSection)
{
    NTSTATUS status;
    HANDLE hSection;
    UNICODE_STRING SectionName;
    SECURITY_DESCRIPTOR SecurityDesc;
    OBJECT_ATTRIBUTES SectionAttrs;
    LARGE_INTEGER nSectionSize;

    DbgEn();

    RtlInitUnicodeString(&SectionName, NFS41_SHARED_MEMORY_NAME);

    /* XXX: setting dacl=NULL grants access to everyone */
    status = RtlCreateSecurityDescriptor(&SecurityDesc,
        SECURITY_DESCRIPTOR_REVISION);
    if (status) {
        print_error("RtlCreateSecurityDescriptor() failed with %08X\n", status);
        goto out;
    }
    status = RtlSetDaclSecurityDescriptor(&SecurityDesc, TRUE, NULL, FALSE);
    if (status) {
        print_error("RtlSetDaclSecurityDescriptor() failed with %08X\n", status);
        goto out;
    }

    InitializeObjectAttributes(&SectionAttrs, &SectionName,
        0, NULL, &SecurityDesc);

    nSectionSize.QuadPart = sizeof(NFS41NP_SHARED_MEMORY);

    status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE,
        &SectionAttrs, &nSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    switch (status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_OBJECT_NAME_COLLISION:
        DbgP("section already created; returning success\n");
        status = STATUS_SUCCESS;
        goto out;
    default:
        DbgP("ZwCreateSection failed with %08X\n", status);
        goto out;
    }
out:
    DbgEx();
    return status;
}

NTSTATUS SharedMemoryFree(
    IN HANDLE hSection)
{
    NTSTATUS status;
    DbgEn();
    status = ZwClose(hSection);
    DbgEx();
    return status;
}

NTSTATUS nfs41_Start(
    IN OUT PRX_CONTEXT RxContext, 
    IN OUT PRDBSS_DEVICE_OBJECT dev)
{
    NTSTATUS status;
    NFS41GetDeviceExtension(RxContext, DevExt);

    DbgEn();

    status = SharedMemoryInit(&DevExt->SharedMemorySection);
    if (status) {
        print_error("InitSharedMemory failed with %08X\n", status);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    InterlockedCompareExchange((PLONG)&nfs41_start_state,
        NFS41_START_DRIVER_STARTED,
        NFS41_START_DRIVER_START_IN_PROGRESS);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_Stop(
    IN OUT PRX_CONTEXT RxContext,
    IN OUT PRDBSS_DEVICE_OBJECT dev)
{
    NTSTATUS status;
    NFS41GetDeviceExtension(RxContext, DevExt);
    DbgEn();
    status = SharedMemoryFree(DevExt->SharedMemorySection);
    DbgEx();
    return status;
}

NTSTATUS GetConnectionHandle(
    IN PUNICODE_STRING ConnectionName,
    IN PVOID EaBuffer,
    IN ULONG EaLength,
    OUT PHANDLE Handle)
{
    NTSTATUS status;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;

#ifdef DEBUG_MOUNT
    DbgEn();
#endif
    InitializeObjectAttributes(&ObjectAttributes, ConnectionName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(Handle, SYNCHRONIZE, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_CREATE_TREE_CONNECTION | FILE_SYNCHRONOUS_IO_NONALERT,
        EaBuffer, EaLength);

#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_GetConnectionInfoFromBuffer(
    IN PVOID Buffer,
    IN ULONG BufferLen,
    OUT PUNICODE_STRING pConnectionName,
    OUT PVOID *ppEaBuffer,
    OUT PULONG pEaLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    USHORT NameLength, EaPadding;
    ULONG EaLength, BufferLenExpected;
    PBYTE ptr;

    /* make sure buffer is at least big enough for header */
    if (BufferLen < sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG)) {
        status = STATUS_BAD_NETWORK_NAME;
        print_error("Invalid input buffer.\n");
        pConnectionName->Length = pConnectionName->MaximumLength = 0;
        *ppEaBuffer = NULL;
        *pEaLength = 0;
        goto out;
    }

    ptr = Buffer;
    NameLength = *(PUSHORT)ptr;
    ptr += sizeof(USHORT);
    EaPadding = *(PUSHORT)ptr;
    ptr += sizeof(USHORT);
    EaLength = *(PULONG)ptr;
    ptr += sizeof(ULONG);

    /* validate buffer length */
    BufferLenExpected = sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG) +
        NameLength + EaPadding + EaLength;
    if (BufferLen != BufferLenExpected) {
        status = STATUS_BAD_NETWORK_NAME;
        print_error("Received buffer of length %lu, but expected %lu bytes.\n",
            BufferLen, BufferLenExpected);
        pConnectionName->Length = pConnectionName->MaximumLength = 0;
        *ppEaBuffer = NULL;
        *pEaLength = 0;
        goto out;
    }

    pConnectionName->Buffer = (PWCH)ptr;
    pConnectionName->Length = NameLength - sizeof(WCHAR);
    pConnectionName->MaximumLength = NameLength;

    if (EaLength)
        *ppEaBuffer = ptr + NameLength + EaPadding;
    else
        *ppEaBuffer = NULL;
    *pEaLength = EaLength;

out:
    return status;
}

NTSTATUS nfs41_CreateConnection(
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    PVOID Buffer = LowIoContext->ParamsFor.IoCtl.pInputBuffer, EaBuffer;
    ULONG BufferLen = LowIoContext->ParamsFor.IoCtl.InputBufferLength, EaLength;
    UNICODE_STRING FileName;
    BOOLEAN Wait = BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_WAIT);

#ifdef DEBUG_MOUNT
    DbgEn();
#endif

    if (!Wait) {
        //just post right now!
        DbgP("returning STATUS_PENDING\n");
        *PostToFsp = TRUE;
        status = STATUS_PENDING;
        goto out;
    }

    status = nfs41_GetConnectionInfoFromBuffer(Buffer, BufferLen,
        &FileName, &EaBuffer, &EaLength);
    if (status != STATUS_SUCCESS)
        goto out;

    status = GetConnectionHandle(&FileName, EaBuffer, EaLength, &Handle);
    if (!status && Handle != INVALID_HANDLE_VALUE)
        ZwClose(Handle);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

#ifdef ENABLE_TIMINGS
void print_op_stat(
    const char *op_str, 
    nfs41_timings *time, BOOLEAN clear) 
{
    DbgP("%-9s: num_ops=%-10d delta_ticks=%-10d size=%-10d\n", op_str, 
        time->tops, time->tops ? time->ticks/time->tops : 0,
        time->sops ? time->size/time->sops : 0);
    if (clear) {
        time->tops = 0;
        time->ticks = 0;
        time->size = 0;
        time->sops = 0;
    }
}
#endif
NTSTATUS nfs41_unmount(
    HANDLE session, 
    DWORD version)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;

#ifdef DEBUG_MOUNT
    DbgEn();
#endif
    status = nfs41_UpcallCreate(NFS41_UNMOUNT, NULL, session, 
        INVALID_HANDLE_VALUE, version, NULL, &entry);
    SeDeleteClientSecurity(&entry->sec_ctx);
    if (status)
        goto out;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    print_op_stat("lookup", &lookup, 1);
    print_op_stat("open", &open, 1);
    print_op_stat("close", &close, 1);
    print_op_stat("volume", &volume, 1);
    print_op_stat("getattr", &getattr, 1);
    print_op_stat("setattr", &setattr, 1);
    print_op_stat("getexattr", &getexattr, 1);
    print_op_stat("setexattr", &setexattr, 1);
    print_op_stat("readdir", &readdir, 1);
    print_op_stat("getacl", &getacl, 1);
    print_op_stat("setacl", &setacl, 1);
    print_op_stat("read", &read, 1);
    print_op_stat("write", &write, 1);
    print_op_stat("lock", &lock, 1);
    print_op_stat("unlock", &unlock, 1);
#endif
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_DeleteConnection (
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    PWCHAR ConnectName = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    ULONG ConnectNameLen = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
    HANDLE Handle;
    UNICODE_STRING FileName;
    PFILE_OBJECT pFileObject;
    BOOLEAN Wait = BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_WAIT);

#ifdef DEBUG_MOUNT
    DbgEn();
#endif

    if (!Wait) {
        //just post right now!
        *PostToFsp = TRUE;
        DbgP("returning STATUS_PENDING\n");
        status = STATUS_PENDING;
        goto out;
    }

    FileName.Buffer = ConnectName;
    FileName.Length = (USHORT) ConnectNameLen - sizeof(WCHAR);
    FileName.MaximumLength = (USHORT) ConnectNameLen;

    status = GetConnectionHandle(&FileName, NULL, 0, &Handle);
    if (status != STATUS_SUCCESS)
        goto out;

    status = ObReferenceObjectByHandle(Handle, 0L, NULL, KernelMode,
                (PVOID *)&pFileObject, NULL);
    if (NT_SUCCESS(status)) {
        PV_NET_ROOT VNetRoot;

        // VNetRoot exists as FOBx in the FsContext2
        VNetRoot = (PV_NET_ROOT) pFileObject->FsContext2;
        // make sure the node looks right
        if (NodeType(VNetRoot) == RDBSS_NTC_V_NETROOT)
        {
#ifdef DEBUG_MOUNT
            DbgP("Calling RxFinalizeConnection for NetRoot %p from VNetRoot %p\n",
                VNetRoot->NetRoot, VNetRoot);
#endif
            status = RxFinalizeConnection(VNetRoot->NetRoot, VNetRoot, TRUE);
        }
        else
            status = STATUS_BAD_NETWORK_NAME;

        ObDereferenceObject(pFileObject);
    }
    ZwClose(Handle);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_DevFcbXXXControlFile(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    UCHAR op = RxContext->MajorFunction;
    PLOWIO_CONTEXT io_ctx = &RxContext->LowIoContext;
    ULONG fsop = io_ctx->ParamsFor.FsCtl.FsControlCode, state;
    ULONG in_len = io_ctx->ParamsFor.IoCtl.InputBufferLength;
    DWORD *buf = io_ctx->ParamsFor.IoCtl.pInputBuffer;
    NFS41GetDeviceExtension(RxContext, DevExt);
    DWORD nfs41d_version = 0;

    //DbgEn();

    print_ioctl(0, op);
    switch(op) {
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        print_fs_ioctl(0, fsop);
        switch (fsop) {
        case IOCTL_NFS41_INVALCACHE:
            status = nfs41_invalidate_cache(RxContext);
            break;
        case IOCTL_NFS41_READ:
            status = nfs41_upcall(RxContext);
            break;
        case IOCTL_NFS41_WRITE:
            status = nfs41_downcall(RxContext);
            break;
        case IOCTL_NFS41_ADDCONN:
            status = nfs41_CreateConnection(RxContext, &RxContext->PostRequest);
            break;
        case IOCTL_NFS41_DELCONN:
            if (RxContext->RxDeviceObject->NumberOfActiveFcbs > 0) {
                DbgP("device has open handles %d\n", 
                    RxContext->RxDeviceObject->NumberOfActiveFcbs);
                status = STATUS_REDIRECTOR_HAS_OPEN_HANDLES;
                break;
            }
            status = nfs41_DeleteConnection(RxContext, &RxContext->PostRequest);
            break;
        case IOCTL_NFS41_GETSTATE:
            state = RDR_NULL_STATE;

            if (io_ctx->ParamsFor.IoCtl.OutputBufferLength >= sizeof(ULONG)) {
                // map the states to control app's equivalents
                print_driver_state(nfs41_start_state);
                switch (nfs41_start_state) {
                case NFS41_START_DRIVER_STARTABLE:
                case NFS41_START_DRIVER_STOPPED:
                    state = RDR_STOPPED;
                    break;
                case NFS41_START_DRIVER_START_IN_PROGRESS:
                    state = RDR_STARTING;
                    break;
                case NFS41_START_DRIVER_STARTED:
                    state = RDR_STARTED;
                    break;
                }
                *(ULONG *)io_ctx->ParamsFor.IoCtl.pOutputBuffer = state;
                RxContext->InformationToReturn = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else
                status = STATUS_INVALID_PARAMETER;
            break;
        case IOCTL_NFS41_START:
            print_driver_state(nfs41_start_state);
            if (in_len >= sizeof(DWORD)) {
                RtlCopyMemory(&nfs41d_version, buf, sizeof(DWORD));
                DbgP("NFS41 Daemon sent start request with version %d\n", 
                    nfs41d_version);
                DbgP("Currently used NFS41 Daemon version is %d\n", 
                    DevExt->nfs41d_version);
                DevExt->nfs41d_version = nfs41d_version;
            }
            switch(nfs41_start_state) {
            case NFS41_START_DRIVER_STARTABLE:
                (nfs41_start_driver_state)InterlockedCompareExchange(
                              (PLONG)&nfs41_start_state,
                              NFS41_START_DRIVER_START_IN_PROGRESS,
                              NFS41_START_DRIVER_STARTABLE);
                    //lack of break is intentional
            case NFS41_START_DRIVER_START_IN_PROGRESS:
                status = RxStartMinirdr(RxContext, &RxContext->PostRequest);
                if (status == STATUS_REDIRECTOR_STARTED) {
                    DbgP("redirector started\n");
                    status = STATUS_SUCCESS;
                } else if (status == STATUS_PENDING && 
                            RxContext->PostRequest == TRUE) {
                    DbgP("RxStartMinirdr pending %08lx\n", status);
                    status = STATUS_MORE_PROCESSING_REQUIRED;
                } 
                break;
            case NFS41_START_DRIVER_STARTED:
                status = STATUS_SUCCESS;
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case IOCTL_NFS41_STOP:
            if (nfs41_start_state == NFS41_START_DRIVER_STARTED)
                nfs41_shutdown_daemon(DevExt->nfs41d_version);
            if (RxContext->RxDeviceObject->NumberOfActiveFcbs > 0) {
                DbgP("device has open handles %d\n", 
                    RxContext->RxDeviceObject->NumberOfActiveFcbs);
                status = STATUS_REDIRECTOR_HAS_OPEN_HANDLES;
                break;
            }

            state = (nfs41_start_driver_state)InterlockedCompareExchange(
                        (PLONG)&nfs41_start_state, 
                        NFS41_START_DRIVER_STARTABLE, 
                        NFS41_START_DRIVER_STARTED);

            status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
            DbgP("RxStopMinirdr status %08lx\n", status);
            if (status == STATUS_PENDING && RxContext->PostRequest == TRUE )
                status = STATUS_MORE_PROCESSING_REQUIRED;
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
        };
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    };

    //DbgEx();
    return status;
}

NTSTATUS _nfs41_CreateSrvCall(
    PMRX_SRVCALL_CALLBACK_CONTEXT pCallbackContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMRX_SRVCALL_CALLBACK_CONTEXT SCCBC = pCallbackContext;
    PMRX_SRV_CALL pSrvCall;
    PMRX_SRVCALLDOWN_STRUCTURE SrvCalldownStructure =
        (PMRX_SRVCALLDOWN_STRUCTURE)(SCCBC->SrvCalldownStructure);
    PNFS41_SERVER_ENTRY pServerEntry = NULL;

#ifdef DEBUG_MOUNT
    DbgEn();
#endif

    pSrvCall = SrvCalldownStructure->SrvCall;

    ASSERT( pSrvCall );
    ASSERT( NodeType(pSrvCall) == RDBSS_NTC_SRVCALL );
    print_srv_call(0, pSrvCall);

    // validate the server name with the test name of 'pnfs'
#ifdef DEBUG_MOUNT
    DbgP("SrvCall: Connection Name Length: %d %wZ\n",
        pSrvCall->pSrvCallName->Length, pSrvCall->pSrvCallName);
#endif

    if (pSrvCall->pSrvCallName->Length > SERVER_NAME_BUFFER_SIZE) {
        print_error("Server name '%wZ' too long for server entry (max %u)\n",
            pSrvCall->pSrvCallName, SERVER_NAME_BUFFER_SIZE);
        status = STATUS_NAME_TOO_LONG;
        goto out;
    }

    /* Let's create our own representation of the server */
    pServerEntry = (PNFS41_SERVER_ENTRY)RxAllocatePoolWithTag(PagedPool, 
        sizeof(NFS41_SERVER_ENTRY), NFS41_MM_POOLTAG);
    if (pServerEntry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlZeroMemory(pServerEntry, sizeof(NFS41_SERVER_ENTRY));

    pServerEntry->Name.Buffer = pServerEntry->NameBuffer;
    pServerEntry->Name.Length = pSrvCall->pSrvCallName->Length;
    pServerEntry->Name.MaximumLength = SERVER_NAME_BUFFER_SIZE;
    RtlCopyMemory(pServerEntry->Name.Buffer, pSrvCall->pSrvCallName->Buffer,
        pServerEntry->Name.Length);

    pCallbackContext->RecommunicateContext = pServerEntry;
    InterlockedExchangePointer(&pServerEntry->pRdbssSrvCall, pSrvCall);

out:
    SCCBC->Status = status;
    SrvCalldownStructure->CallBack(SCCBC);

#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_CreateSrvCall(
    PMRX_SRV_CALL pSrvCall,
    PMRX_SRVCALL_CALLBACK_CONTEXT pCallbackContext)
{
    NTSTATUS status;

    ASSERT( pSrvCall );
    ASSERT( NodeType(pSrvCall) == RDBSS_NTC_SRVCALL );

    if (IoGetCurrentProcess() == RxGetRDBSSProcess()) {
        DbgP("executing with RDBSS context\n");
        status = _nfs41_CreateSrvCall(pCallbackContext);
    } else {
        status = RxDispatchToWorkerThread(nfs41_dev, DelayedWorkQueue, 
            _nfs41_CreateSrvCall, pCallbackContext);
        if (status != STATUS_SUCCESS) {
            print_error("RxDispatchToWorkerThread returned status %08lx\n", 
                status);
            pCallbackContext->Status = status;
            pCallbackContext->SrvCalldownStructure->CallBack(pCallbackContext);
            status = STATUS_PENDING;
        }
    }
    /* RDBSS expects MRxCreateSrvCall to return STATUS_PENDING */
    if (status == STATUS_SUCCESS)
        status = STATUS_PENDING;

    return status;
}

NTSTATUS nfs41_SrvCallWinnerNotify(
    IN OUT PMRX_SRV_CALL pSrvCall, 
    IN BOOLEAN ThisMinirdrIsTheWinner,
    IN OUT PVOID pSrvCallContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_SERVER_ENTRY pServerEntry;

    pServerEntry = (PNFS41_SERVER_ENTRY)pSrvCallContext;

    if (!ThisMinirdrIsTheWinner) {
        ASSERT(1);
        goto out;
    }

    pSrvCall->Context = pServerEntry;
out:
    return status;
}

NTSTATUS map_mount_errors(
    DWORD status)
{
    switch (status) {
    case NO_ERROR:              return STATUS_SUCCESS;
    case ERROR_NETWORK_UNREACHABLE: return STATUS_NETWORK_UNREACHABLE;
    case ERROR_BAD_NET_RESP:    return STATUS_UNEXPECTED_NETWORK_ERROR;
    case ERROR_BAD_NET_NAME:    return STATUS_BAD_NETWORK_NAME;
    case ERROR_BAD_NETPATH:     return STATUS_BAD_NETWORK_PATH;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INSUFFICIENT_RESOURCES\n", status);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

NTSTATUS nfs41_mount(
    PNFS41_MOUNT_CONFIG config, 
    DWORD sec_flavor, 
    PHANDLE session, 
    DWORD *version)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;

#ifdef DEBUG_MOUNT
    DbgEn();
    DbgP("Server Name %wZ Mount Point %wZ SecFlavor %wZ\n",
        config->SrvName, config->MntPt, sec_flavor);
#endif
    status = nfs41_UpcallCreate(NFS41_MOUNT, NULL, INVALID_HANDLE_VALUE,
        INVALID_HANDLE_VALUE, *version, &config->MntPt, &entry);
    if (status)
        goto out;
    entry->u.Mount.srv_name = &config->SrvName;
    entry->u.Mount.root = &config->MntPt;
    entry->u.Mount.rsize = config->ReadSize;
    entry->u.Mount.wsize = config->WriteSize;
    entry->u.Mount.sec_flavor = sec_flavor;

    status = nfs41_UpcallWaitForReply(entry);
    SeDeleteClientSecurity(&entry->sec_ctx);
    if (status != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    *session = entry->session;

    /* map windows ERRORs to NTSTATUS */
    status = map_mount_errors(entry->status);
    if (status == STATUS_SUCCESS)
        *version = entry->version;
    RxFreePool(entry);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

/* TODO: move mount config stuff to another file -cbodley */

void nfs41_MountConfig_InitDefaults(
    OUT PNFS41_MOUNT_CONFIG Config)
{
    RtlZeroMemory(Config, sizeof(NFS41_MOUNT_CONFIG));

    Config->ReadSize = MOUNT_CONFIG_RW_SIZE_DEFAULT;
    Config->WriteSize = MOUNT_CONFIG_RW_SIZE_DEFAULT;
    Config->ReadOnly = FALSE;
    Config->write_thru = FALSE;
    Config->nocache = FALSE;
    Config->SrvName.Length = 0;
    Config->SrvName.MaximumLength = SERVER_NAME_BUFFER_SIZE;
    Config->SrvName.Buffer = Config->srv_buffer;
    Config->MntPt.Length = 0;
    Config->MntPt.MaximumLength = MAX_PATH;
    Config->MntPt.Buffer = Config->mntpt_buffer;
    Config->SecFlavor.Length = 0;
    Config->SecFlavor.MaximumLength = MAX_SEC_FLAVOR_LEN;
    Config->SecFlavor.Buffer = Config->sec_flavor;
    RtlCopyUnicodeString(&Config->SecFlavor, &AUTH_SYS_NAME);
}

NTSTATUS nfs41_MountConfig_ParseBoolean(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    OUT PBOOLEAN Value)
{
    NTSTATUS status = STATUS_SUCCESS;

    /* if no value is specified, assume TRUE
     * if a value is specified, it must be a '1' */
    if (Option->EaValueLength == 0 || *usValue->Buffer == L'1')
        *Value = TRUE;
    else
        *Value = FALSE;

    DbgP("    '%ls' -> '%wZ' -> %u\n",
        (LPWSTR)Option->EaName, *usValue, *Value);
    return status;
}

NTSTATUS nfs41_MountConfig_ParseDword(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    OUT PDWORD Value,
    IN DWORD Minimum,
    IN DWORD Maximum)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    LPWSTR Name = (LPWSTR)Option->EaName;

    if (Option->EaValueLength) {
        status = RtlUnicodeStringToInteger(usValue, 0, Value);
        if (status == STATUS_SUCCESS) {
#ifdef IMPOSE_MINMAX_RWSIZES
            if (*Value < Minimum)
                *Value = Minimum;
            if (*Value > Maximum)
                *Value = Maximum;
            DbgP("    '%ls' -> '%wZ' -> %lu\n", Name, *usValue, *Value);
#endif
        }
        else
            print_error("Failed to convert %s='%wZ' to unsigned long.\n",
                Name, *usValue);
    }

    return status;
}

NTSTATUS nfs41_MountConfig_ParseOptions(
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaLength,
    IN OUT PNFS41_MOUNT_CONFIG Config)
{
    NTSTATUS  status = STATUS_SUCCESS;
    PFILE_FULL_EA_INFORMATION Option;
    LPWSTR Name;
    size_t NameLen;
    UNICODE_STRING  usValue;
    Option = EaBuffer;
    while (status == STATUS_SUCCESS) {
        Name = (LPWSTR)Option->EaName;
        NameLen = Option->EaNameLength/sizeof(WCHAR);

        usValue.Length = usValue.MaximumLength = Option->EaValueLength;
        usValue.Buffer = (PWCH)(Option->EaName +
            Option->EaNameLength + sizeof(WCHAR));

        if (wcsncmp(L"ro", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                &Config->ReadOnly);
        }
        else if (wcsncmp(L"writethru", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                &Config->write_thru);
        }
        else if (wcsncmp(L"nocache", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                &Config->nocache);
        }
        else if (wcsncmp(L"rsize", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->ReadSize, MOUNT_CONFIG_RW_SIZE_MIN,
                MOUNT_CONFIG_RW_SIZE_MAX);
        }
        else if (wcsncmp(L"wsize", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->WriteSize, MOUNT_CONFIG_RW_SIZE_MIN,
                MOUNT_CONFIG_RW_SIZE_MAX);
        }
        else if (wcsncmp(L"srvname", Name, NameLen) == 0) {
            if (usValue.Length > Config->SrvName.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->SrvName, &usValue);
        }
        else if (wcsncmp(L"mntpt", Name, NameLen) == 0) {
            if (usValue.Length > Config->MntPt.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->MntPt, &usValue);
        }
        else if (wcsncmp(L"sec", Name, NameLen) == 0) {
            if (usValue.Length > Config->SecFlavor.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->SecFlavor, &usValue);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            print_error("Unrecognized option '%ls' -> '%wZ'\n",
                Name, usValue);
        }

        if (Option->NextEntryOffset == 0)
            break;

        Option = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Option + Option->NextEntryOffset);
    }

    return status;
}

NTSTATUS has_nfs_prefix(
    IN PUNICODE_STRING SrvCallName,
    IN PUNICODE_STRING NetRootName)
{
    NTSTATUS status = STATUS_BAD_NETWORK_NAME;

    if (NetRootName->Length == SrvCallName->Length + NfsPrefix.Length) {
        const UNICODE_STRING NetRootPrefix = {
            NfsPrefix.Length,
            NetRootName->MaximumLength - SrvCallName->Length,
            &NetRootName->Buffer[SrvCallName->Length/2]
        };
        if (RtlCompareUnicodeString(&NetRootPrefix, &NfsPrefix, FALSE) == 0)
            status = STATUS_SUCCESS;
    }
    return status;
}

NTSTATUS map_sec_flavor(
    IN PUNICODE_STRING sec_flavor_name,
    OUT PDWORD sec_flavor)
{
    if (RtlCompareUnicodeString(sec_flavor_name, &AUTH_SYS_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTH_SYS;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5I_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5I;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5P_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5P;
    else return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_GetLUID(
    PLUID id)
{
    NTSTATUS status = STATUS_SUCCESS;
    SECURITY_SUBJECT_CONTEXT sec_ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;
    SECURITY_CLIENT_CONTEXT clnt_sec_ctx;

    SeCaptureSubjectContext(&sec_ctx);
    sec_qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    sec_qos.ImpersonationLevel = SecurityIdentification;
    sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    sec_qos.EffectiveOnly = 0;
    status = SeCreateClientSecurityFromSubjectContext(&sec_ctx, &sec_qos, 1, 
                &clnt_sec_ctx);
    if (status) {
        print_error("nfs41_GetLUID: SeCreateClientSecurityFromSubjectContext "
             "failed %x\n", status);
        goto release_sec_ctx;
    }
    status = SeQueryAuthenticationIdToken(clnt_sec_ctx.ClientToken, id);
    if (status) {
        print_error("SeQueryAuthenticationIdToken failed %x\n", status);
        goto release_clnt_sec_ctx;
    }
release_clnt_sec_ctx:
    SeDeleteClientSecurity(&clnt_sec_ctx);
release_sec_ctx:
    SeReleaseSubjectContext(&sec_ctx);

    return status;
}

NTSTATUS nfs41_get_sec_ctx(
    IN enum _SECURITY_IMPERSONATION_LEVEL level,
    OUT PSECURITY_CLIENT_CONTEXT out_ctx)
{
    NTSTATUS status;
    SECURITY_SUBJECT_CONTEXT ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;

    SeCaptureSubjectContext(&ctx);
    sec_qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    sec_qos.ImpersonationLevel = level;
    sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    sec_qos.EffectiveOnly = 0;
    status = SeCreateClientSecurityFromSubjectContext(&ctx, &sec_qos, 1, out_ctx);
    if (status != STATUS_SUCCESS) {
        print_error("SeCreateClientSecurityFromSubjectContext "
            "failed with %x\n", status);
    }
#ifdef DEBUG_MOUNT
    DbgP("Created client security token %p\n", out_ctx->ClientToken);
#endif
    SeReleaseSubjectContext(&ctx);

    return status;
}

NTSTATUS nfs41_CreateVNetRoot(
    IN OUT PMRX_CREATENETROOT_CONTEXT pCreateNetRootContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    NFS41_MOUNT_CONFIG Config;
    __notnull PMRX_V_NET_ROOT pVNetRoot = (PMRX_V_NET_ROOT)
        pCreateNetRootContext->pVNetRoot;
    __notnull PMRX_NET_ROOT pNetRoot = pVNetRoot->pNetRoot;
    __notnull PMRX_SRV_CALL pSrvCall = pNetRoot->pSrvCall;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(pNetRoot);
    NFS41GetDeviceExtension(pCreateNetRootContext->RxContext,DevExt);
    DWORD nfs41d_version = DevExt->nfs41d_version;
    nfs41_mount_entry *existing_mount = NULL;
    LUID luid;
    BOOLEAN found_existing_mount = FALSE, found_matching_flavor = FALSE;

    ASSERT((NodeType(pNetRoot) == RDBSS_NTC_NETROOT) &&
        (NodeType(pNetRoot->pSrvCall) == RDBSS_NTC_SRVCALL));

#ifdef DEBUG_MOUNT
    DbgEn();
    print_srv_call(0, pSrvCall);
    print_net_root(0, pNetRoot);
    print_v_net_root(0, pVNetRoot);

    DbgP("pVNetRoot=%p pNetRoot=%p pSrvCall=%p\n", pVNetRoot, pNetRoot, pSrvCall);
    DbgP("pNetRoot=%wZ Type=%d pSrvCallName=%wZ VirtualNetRootStatus=0x%x "
        "NetRootStatus=0x%x\n", pNetRoot->pNetRootName, 
        pNetRoot->Type, pSrvCall->pSrvCallName, 
        pCreateNetRootContext->VirtualNetRootStatus, 
        pCreateNetRootContext->NetRootStatus);
#endif

    if (pNetRoot->Type != NET_ROOT_DISK && pNetRoot->Type != NET_ROOT_WILD) {
        print_error("nfs41_CreateVNetRoot: Unsupported NetRoot Type %u\n", 
            pNetRoot->Type);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    pVNetRootContext->session = INVALID_HANDLE_VALUE;

    /* In order to cooperate with other network providers, we must
     * only claim paths of the form '\\server\nfs4\path' */
    status = has_nfs_prefix(pSrvCall->pSrvCallName, pNetRoot->pNetRootName);
    if (status) {
        print_error("nfs41_CreateVNetRoot: NetRootName %wZ doesn't match "
            "'\\nfs4'!\n", pNetRoot->pNetRootName);
        goto out;
    }
    pNetRoot->MRxNetRootState = MRX_NET_ROOT_STATE_GOOD;
    pNetRoot->DeviceType = FILE_DEVICE_DISK;

    nfs41_MountConfig_InitDefaults(&Config);

    if (pCreateNetRootContext->RxContext->Create.EaLength) {
        /* parse the extended attributes for mount options */
        status = nfs41_MountConfig_ParseOptions(
            pCreateNetRootContext->RxContext->Create.EaBuffer,
            pCreateNetRootContext->RxContext->Create.EaLength,
            &Config);
        if (status != STATUS_SUCCESS)
            goto out;
        pVNetRootContext->read_only = Config.ReadOnly;
        pVNetRootContext->write_thru = Config.write_thru;
        pVNetRootContext->nocache = Config.nocache;
    } else {
        /* use the SRV_CALL name (without leading \) as the hostname */
        Config.SrvName.Buffer = pSrvCall->pSrvCallName->Buffer + 1;
        Config.SrvName.Length =
            pSrvCall->pSrvCallName->Length - sizeof(WCHAR);
        Config.SrvName.MaximumLength =
            pSrvCall->pSrvCallName->MaximumLength - sizeof(WCHAR);
    }

    status = map_sec_flavor(&Config.SecFlavor, &pVNetRootContext->sec_flavor);
    if (status != STATUS_SUCCESS) {
        DbgP("Invalid rpcsec security flavor %wZ\n", &Config.SecFlavor);
        goto out;
    }

    status = nfs41_GetLUID(&luid);
    if (status)
        goto out;

    if (!pNetRootContext->mounts_init) {
#ifdef DEBUG_MOUNT
        DbgP("Initializing mount array\n");
#endif
        ExInitializeFastMutex(&pNetRootContext->mountLock);
        pNetRootContext->mounts = RxAllocatePoolWithTag(NonPagedPool, 
            sizeof(nfs41_mount_list), NFS41_MM_POOLTAG);
        if (pNetRootContext->mounts == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
        InitializeListHead(&pNetRootContext->mounts->head);
        pNetRootContext->mounts_init = TRUE;
    } else {
        PLIST_ENTRY pEntry;

        ExAcquireFastMutex(&pNetRootContext->mountLock); 
        pEntry = &pNetRootContext->mounts->head;
        pEntry = pEntry->Flink;
        while (pEntry != NULL) {
            existing_mount = (nfs41_mount_entry *)CONTAINING_RECORD(pEntry, 
                    nfs41_mount_entry, next);
#ifdef DEBUG_MOUNT
            DbgP("comparing %x.%x with %x.%x\n", luid.HighPart, luid.LowPart,
                existing_mount->login_id.HighPart, existing_mount->login_id.LowPart);
#endif
            if (RtlEqualLuid(&luid, &existing_mount->login_id)) {
#ifdef DEBUG_MOUNT
                DbgP("Found a matching LUID entry\n");
#endif
                found_existing_mount = TRUE;
                switch(pVNetRootContext->sec_flavor) {
                case RPCSEC_AUTH_SYS:
                    if (existing_mount->authsys_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = 
                            existing_mount->authsys_session;
                    break;
                case RPCSEC_AUTHGSS_KRB5:
                    if (existing_mount->gssi_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = existing_mount->gss_session;
                    break;
                case RPCSEC_AUTHGSS_KRB5I:
                    if (existing_mount->gss_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = existing_mount->gssi_session;
                    break;
                case RPCSEC_AUTHGSS_KRB5P:
                    if (existing_mount->gssp_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = existing_mount->gssp_session;
                    break;
                }
                if (pVNetRootContext->session)
                    found_matching_flavor = 1;
                break;                
            }
            if (pEntry->Flink == &pNetRootContext->mounts->head)
                break;
            pEntry = pEntry->Flink;
        }
        ExReleaseFastMutex(&pNetRootContext->mountLock);
#ifdef DEBUG_MOUNT
        if (!found_matching_flavor)
            DbgP("Didn't find matching security flavor\n");
#endif
    }

    if (!found_existing_mount || !found_matching_flavor) {
        /* send the mount upcall */
        status = nfs41_mount(&Config, pVNetRootContext->sec_flavor,
            &pVNetRootContext->session, &nfs41d_version);
        if (status != STATUS_SUCCESS) {
            if (!found_existing_mount) {
                RxFreePool(pNetRootContext->mounts);
                pNetRootContext->mounts_init = FALSE;
                pVNetRootContext->session = INVALID_HANDLE_VALUE;
            }
            goto out;
        }
    } 

    if (!found_existing_mount) {
        /* create a new mount entry and add it to the list */
        nfs41_mount_entry *entry;
        entry = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_mount_entry), 
            NFS41_MM_POOLTAG);
        if (entry == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            RxFreePool(pNetRootContext->mounts);
            goto out;
        }
        entry->authsys_session = entry->gss_session = 
            entry->gssi_session = entry->gssp_session = INVALID_HANDLE_VALUE;
        switch (pVNetRootContext->sec_flavor) {
        case RPCSEC_AUTH_SYS:
            entry->authsys_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5:
            entry->gss_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5I:
            entry->gssi_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5P:
            entry->gssp_session = pVNetRootContext->session; break;
        }
        RtlCopyLuid(&entry->login_id, &luid);
        nfs41_AddEntry(pNetRootContext->mountLock, pNetRootContext->mounts, entry);
    } else if (!found_matching_flavor) {
        ASSERT(existing_mount != NULL);
        /* modify existing mount entry */
#ifdef DEBUG_MOUNT
        DbgP("Using existing %d flavor session 0x%x\n", 
            pVNetRootContext->sec_flavor);
#endif
        switch (pVNetRootContext->sec_flavor) {
        case RPCSEC_AUTH_SYS:
            existing_mount->authsys_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5:
            existing_mount->gss_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5I:
            existing_mount->gssi_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5P:
            existing_mount->gssp_session = pVNetRootContext->session; break;
        }
    }
    pNetRootContext->nfs41d_version = nfs41d_version;
#ifdef DEBUG_MOUNT
    DbgP("Saving new session 0x%x\n", pVNetRootContext->session);
#endif
#ifdef STORE_MOUNT_SEC_CONTEXT
    status = nfs41_get_sec_ctx(SecurityImpersonation, 
        &pVNetRootContext->mount_sec_ctx);
#endif

out:
    pCreateNetRootContext->VirtualNetRootStatus = status;
    if (pNetRoot->Context == NULL)
        pCreateNetRootContext->NetRootStatus = status;
    pCreateNetRootContext->Callback(pCreateNetRootContext);

    /* RDBSS expects that MRxCreateVNetRoot returns STATUS_PENDING 
     * on success or failure */
    status = STATUS_PENDING;
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

VOID nfs41_ExtractNetRootName(
    IN PUNICODE_STRING FilePathName,
    IN PMRX_SRV_CALL SrvCall,
    OUT PUNICODE_STRING NetRootName,
    OUT PUNICODE_STRING RestOfName OPTIONAL)
{
    ULONG length = FilePathName->Length;
    PWCH w = FilePathName->Buffer;
    PWCH wlimit = (PWCH)(((PCHAR)w)+length);
    PWCH wlow;

    w += (SrvCall->pSrvCallName->Length/sizeof(WCHAR));
    NetRootName->Buffer = wlow = w;
    /* parse the entire path into NetRootName */
#if USE_ENTIRE_PATH
    w = wlimit;
#else
    for (;;) {
        if (w >= wlimit)
            break;
        if ((*w == OBJ_NAME_PATH_SEPARATOR) && (w != wlow))
            break;
        w++;
    }
#endif
    NetRootName->Length = NetRootName->MaximumLength
                = (USHORT)((PCHAR)w - (PCHAR)wlow);
#ifdef DEBUG_MOUNT
    DbgP("In: pSrvCall %p PathName=%wZ SrvCallName=%wZ Out: NetRootName=%wZ\n", 
        SrvCall, FilePathName, SrvCall->pSrvCallName, NetRootName);
#endif
    return;

}

NTSTATUS nfs41_FinalizeSrvCall(
    PMRX_SRV_CALL pSrvCall,
    BOOLEAN Force)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_SERVER_ENTRY pServerEntry = (PNFS41_SERVER_ENTRY)(pSrvCall->Context);

#ifdef DEBUG_MOUNT
    DbgEn();
#endif
    print_srv_call(0, pSrvCall);

    if (pSrvCall->Context == NULL)
        goto out;

    InterlockedCompareExchangePointer(&pServerEntry->pRdbssSrvCall, 
        NULL, pSrvCall);
    RxFreePool(pServerEntry);

    pSrvCall->Context = NULL;
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_FinalizeNetRoot(
    IN OUT PMRX_NET_ROOT pNetRoot,
    IN PBOOLEAN ForceDisconnect)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension((PMRX_NET_ROOT)pNetRoot);
    nfs41_updowncall_entry *tmp;
    nfs41_mount_entry *mount_tmp;
    
#ifdef DEBUG_MOUNT
    DbgEn();
    print_net_root(1, pNetRoot);
#endif

    if (pNetRoot->Type != NET_ROOT_DISK && pNetRoot->Type != NET_ROOT_WILD) {
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (pNetRootContext == NULL || !pNetRootContext->mounts_init) {
        print_error("nfs41_FinalizeNetRoot: No valid session established\n");
        goto out;
    }

    if (pNetRoot->NumberOfFcbs > 0 || pNetRoot->NumberOfSrvOpens > 0) {
        print_error("%d open Fcbs %d open SrvOpens\n", pNetRoot->NumberOfFcbs, 
            pNetRoot->NumberOfSrvOpens);
        goto out;
    }

    do {
        nfs41_GetFirstMountEntry(pNetRootContext->mountLock, 
            pNetRootContext->mounts, mount_tmp);
        if (mount_tmp == NULL)
            break;
#ifdef DEBUG_MOUNT
        DbgP("Removing entry luid %x.%x from mount list\n", 
            mount_tmp->login_id.HighPart, mount_tmp->login_id.LowPart);
#endif
        if (mount_tmp->authsys_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->authsys_session, 
                        pNetRootContext->nfs41d_version);
            if (status)
                print_error("nfs41_unmount AUTH_SYS failed with %d\n", status);
        }
        if (mount_tmp->gss_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->gss_session, 
                        pNetRootContext->nfs41d_version);
            if (status)
                print_error("nfs41_unmount RPCSEC_GSS_KRB5 failed with %d\n", 
                            status);
        }
        if (mount_tmp->gssi_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->gssi_session, 
                        pNetRootContext->nfs41d_version);
            if (status)
                print_error("nfs41_unmount RPCSEC_GSS_KRB5I failed with %d\n", 
                            status);
        }
        if (mount_tmp->gssp_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->gssp_session, 
                        pNetRootContext->nfs41d_version);
            if (status)
                print_error("nfs41_unmount RPCSEC_GSS_KRB5P failed with %d\n", 
                            status);
        }
        nfs41_RemoveEntry(pNetRootContext->mountLock, pNetRootContext->mounts, 
            mount_tmp);
        RxFreePool(mount_tmp);
    } while (1);
    /* ignore any errors from unmount */
    status = STATUS_SUCCESS;
    RxFreePool(pNetRootContext->mounts);

    // check if there is anything waiting in the upcall or downcall queue
    do {
        nfs41_GetFirstEntry(upcallLock, upcall, tmp);
        if (tmp != NULL) {
            DbgP("Removing entry from upcall list\n");
            nfs41_RemoveEntry(upcallLock, upcall, tmp);
            tmp->status = STATUS_INSUFFICIENT_RESOURCES;
            KeSetEvent(&tmp->cond, 0, FALSE);
        } else
            break;
    } while (1);

    do {
        nfs41_GetFirstEntry(downcallLock, downcall, tmp);
        if (tmp != NULL) {
            DbgP("Removing entry from downcall list\n");
            nfs41_RemoveEntry(downcallLock, downcall, tmp);
            tmp->status = STATUS_INSUFFICIENT_RESOURCES;
            KeSetEvent(&tmp->cond, 0, FALSE);
        } else
            break;
    } while (1);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}


NTSTATUS nfs41_FinalizeVNetRoot(
    IN OUT PMRX_V_NET_ROOT pVNetRoot,
    IN PBOOLEAN ForceDisconnect)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(pVNetRoot);
#ifdef DEBUG_MOUNT
    DbgEn();
    print_v_net_root(1, pVNetRoot);
#endif
    if (pVNetRoot->pNetRoot->Type != NET_ROOT_DISK && 
            pVNetRoot->pNetRoot->Type != NET_ROOT_WILD)
        status = STATUS_NOT_SUPPORTED;
#ifdef STORE_MOUNT_SEC_CONTEXT
    else if (pVNetRootContext->session != INVALID_HANDLE_VALUE) {
#ifdef DEBUG_MOUNT
        DbgP("nfs41_FinalizeVNetRoot: deleting security context: %p\n",
            pVNetRootContext->mount_sec_ctx.ClientToken);
#endif
        SeDeleteClientSecurity(&pVNetRootContext->mount_sec_ctx);
    }
#endif
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

BOOLEAN isDataAccess(
    ACCESS_MASK mask) 
{
    if (mask & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA))
        return TRUE;
    return FALSE;
}

NTSTATUS map_open_errors(
    DWORD status, 
    USHORT len)
{
    switch (status) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_ACCESS_DENIED:
        if (len > 0)                    return STATUS_NETWORK_ACCESS_DENIED;
        else                            return STATUS_SUCCESS;
    case ERROR_INVALID_NAME:            return STATUS_OBJECT_NAME_INVALID;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_FILENAME_EXCED_RANGE:    return STATUS_NAME_TOO_LONG;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_BAD_NETPATH:             return STATUS_BAD_NETWORK_PATH;
    case ERROR_SHARING_VIOLATION:       return STATUS_SHARING_VIOLATION;
    case ERROR_REPARSE:                 return STATUS_REPARSE;
    case ERROR_TOO_MANY_LINKS:          return STATUS_TOO_MANY_LINKS;
    default:
        print_error("[ERROR] nfs41_Create: upcall returned %d returning "
            "STATUS_INSUFFICIENT_RESOURCES\n", status);
    case ERROR_OUTOFMEMORY:             return STATUS_INSUFFICIENT_RESOURCES;
    }
}

DWORD map_disposition_to_create_retval(
    DWORD disposition, 
    DWORD errno)
{
    switch(disposition) {
    case FILE_SUPERSEDE:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_SUPERSEDED;
    case FILE_CREATE:                       return FILE_CREATED;
    case FILE_OPEN:                         return FILE_OPENED;
    case FILE_OPEN_IF:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_OPENED;
    case FILE_OVERWRITE:                    return FILE_OVERWRITTEN;
    case FILE_OVERWRITE_IF:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_OVERWRITTEN;
    default:
        print_error("unknown disposition %d\n", disposition);
        return FILE_OPENED;
    }
}

NTSTATUS nfs41_Create(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry = NULL;
    FCB_INIT_PACKET InitPacket;
    RX_FILE_TYPE StorageType = 0;
    NT_CREATE_PARAMETERS params = RxContext->Create.NtCreateParameters;
    PFILE_FULL_EA_INFORMATION eainfo = NULL;
    nfs3_attrs *attrs = NULL;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PMRX_FCB Fcb = RxContext->pFcb;
    __notnull PNFS41_FCB nfs41_fcb = (PNFS41_FCB)Fcb->Context;
    PNFS41_FOBX nfs41_fobx = NULL;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

    ASSERT( NodeType(SrvOpen) == RDBSS_NTC_SRVOPEN );

#ifdef DEBUG_OPEN
    DbgEn();
    print_debug_header(RxContext);
    print_nt_create_params(1, RxContext->Create.NtCreateParameters);
    if (RxContext->CurrentIrp->AssociatedIrp.SystemBuffer)
        print_ea_info(0, RxContext->CurrentIrp->AssociatedIrp.SystemBuffer);
#endif

    if (Fcb->pNetRoot->Type != NET_ROOT_DISK && 
            Fcb->pNetRoot->Type != NET_ROOT_WILD) {
        print_error("nfs41_Create: Unsupported NetRoot Type %u\n", 
            Fcb->pNetRoot->Type);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (FlagOn(Fcb->FcbState, FCB_STATE_PAGING_FILE )) {
        print_error("FCB_STATE_PAGING_FILE not implemented\n");
        status = STATUS_NOT_IMPLEMENTED;
        goto out;
    }
    
    if (!pNetRootContext->mounts_init) {
        print_error("nfs41_Create: No valid session established\n");
        goto out;
    }

    if (pVNetRootContext->read_only && 
            ((params.DesiredAccess & FILE_WRITE_DATA) ||
            (params.DesiredAccess & FILE_APPEND_DATA))) {
        DbgP("Read-only mount\n");
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

#if defined(STORE_MOUNT_SEC_CONTEXT) && defined (USE_MOUNT_SEC_CONTEXT)
    status = nfs41_UpcallCreate(NFS41_OPEN, &pVNetRootContext->mount_sec_ctx,
#else
    status = nfs41_UpcallCreate(NFS41_OPEN, NULL,
#endif
        pVNetRootContext->session, INVALID_HANDLE_VALUE, 
        pNetRootContext->nfs41d_version, 
        SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.Open.filename = SrvOpen->pAlreadyPrefixedName;
    entry->u.Open.access_mask = params.DesiredAccess;
    entry->u.Open.access_mode = params.ShareAccess;
    entry->u.Open.attrs = params.FileAttributes;
    entry->u.Open.disp = params.Disposition;
    entry->u.Open.copts = params.CreateOptions;
    entry->u.Open.srv_open = SrvOpen;
    if (isDataAccess(params.DesiredAccess))
        entry->u.Open.open_owner_id = InterlockedIncrement(&open_owner_id);
    // if we are creating a file check if nfsv3attributes were passed in
    if (params.Disposition != FILE_OPEN && params.Disposition != FILE_OVERWRITE) {
        if (RxContext->CurrentIrp->AssociatedIrp.SystemBuffer) {
            eainfo = (PFILE_FULL_EA_INFORMATION)
                RxContext->CurrentIrp->AssociatedIrp.SystemBuffer;
            if (AnsiStrEq(&NfsV3Attributes, eainfo->EaName, eainfo->EaNameLength)) {
                attrs = (nfs3_attrs *)(eainfo->EaName + eainfo->EaNameLength + 1);
#ifdef DEBUG_OPEN
                DbgP("creating file with mode %o\n", attrs->mode);
#endif
                entry->u.Open.mode = attrs->mode;
            }
        }
        if (!entry->u.Open.mode)
            entry->u.Open.mode = 0777;
    }

    status = nfs41_UpcallWaitForReply(entry);
#ifndef USE_MOUNT_SEC_CONTEXT
    SeDeleteClientSecurity(&entry->sec_ctx);
#endif
    if (status != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == NO_ERROR && entry->errno == ERROR_REPARSE) {
        /* symbolic link handling. when attempting to open a symlink when the
         * FILE_OPEN_REPARSE_POINT flag is not set, replace the filename with
         * the symlink target's by calling RxPrepareToReparseSymbolicLink()
         * and returning STATUS_REPARSE. the object manager will attempt to
         * open the new path, and return its handle for the original open */
        PRDBSS_DEVICE_OBJECT DeviceObject = RxContext->RxDeviceObject;
        PV_NET_ROOT VNetRoot = (PV_NET_ROOT)
            RxContext->pRelevantSrvOpen->pVNetRoot;
        PUNICODE_STRING VNetRootPrefix = &VNetRoot->PrefixEntry.Prefix;
        UNICODE_STRING AbsPath;
        PCHAR buf;
        BOOLEAN ReparseRequired;

        /* allocate the string for RxPrepareToReparseSymbolicLink(), and
         * format an absolute path "DeviceName+VNetRootName+symlink" */
        AbsPath.Length = DeviceObject->DeviceName.Length +
            VNetRootPrefix->Length + entry->u.Open.symlink.Length;
        AbsPath.MaximumLength = AbsPath.Length + sizeof(UNICODE_NULL);
        AbsPath.Buffer = RxAllocatePoolWithTag(NonPagedPool,
            AbsPath.MaximumLength, NFS41_MM_POOLTAG);
        if (AbsPath.Buffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out_free;
        }

        buf = (PCHAR)AbsPath.Buffer;
        RtlCopyMemory(buf, DeviceObject->DeviceName.Buffer, 
            DeviceObject->DeviceName.Length);
        buf += DeviceObject->DeviceName.Length;
        RtlCopyMemory(buf, VNetRootPrefix->Buffer, VNetRootPrefix->Length);
        buf += VNetRootPrefix->Length;
        RtlCopyMemory(buf, entry->u.Open.symlink.Buffer, 
            entry->u.Open.symlink.Length);
        RxFreePool(entry->u.Open.symlink.Buffer);
        buf += entry->u.Open.symlink.Length;
        *(PWCHAR)buf = UNICODE_NULL;

        status = RxPrepareToReparseSymbolicLink(RxContext,
            entry->u.Open.symlink_embedded, &AbsPath, TRUE, &ReparseRequired);
#ifdef DEBUG_OPEN 
        DbgP("RxPrepareToReparseSymbolicLink(%u, '%wZ') returned %08lX, "
            "FileName is '%wZ'\n", entry->u.Open.symlink_embedded,
            &AbsPath, status, &RxContext->CurrentIrpSp->FileObject->FileName);
#endif
        if (status == STATUS_SUCCESS)
            status = ReparseRequired ? STATUS_REPARSE :
                STATUS_OBJECT_PATH_NOT_FOUND;
        goto out_free;
    }

    status = map_open_errors(entry->status, 
                SrvOpen->pAlreadyPrefixedName->Length);
    if (status) {
#ifdef DEBUG_OPEN 
        print_open_error(1, status);
#endif
        goto out_free;
    }

    if (!RxIsFcbAcquiredExclusive(Fcb)) {
        ASSERT(!RxIsFcbAcquiredShared(Fcb));
        RxAcquireExclusiveFcbResourceInMRx(Fcb);
    }

    RxContext->pFobx = RxCreateNetFobx(RxContext, SrvOpen);
    if (RxContext->pFobx == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out_free;
    }
#ifdef DEBUG_OPEN
    DbgP("nfs41_Create: created FOBX %p\n", RxContext->pFobx);
#endif
    nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    nfs41_fobx->nfs41_open_state = entry->open_state;
#ifndef USE_MOUNT_SEC_CONTEXT
    status = nfs41_get_sec_ctx(SecurityImpersonation, &nfs41_fobx->sec_ctx);
    if (status)
        goto out_free;
#else
    RtlCopyMemory(&nfs41_fobx->sec_ctx, &pVNetRootContext->mount_sec_ctx,
        sizeof(nfs41_fobx->sec_ctx));
#endif

    // we get attributes only for data access and file (not directories)
    if (Fcb->OpenCount == 0 || 
            (Fcb->OpenCount > 0 && 
                nfs41_fcb->changeattr != entry->u.Open.changeattr)) {
#ifdef DEBUG_OPEN
        print_basic_info(1, &entry->u.Open.binfo);
        print_std_info(1, &entry->u.Open.sinfo);
#endif
        RtlCopyMemory(&nfs41_fcb->BasicInfo, &entry->u.Open.binfo, 
            sizeof(entry->u.Open.binfo));
        RtlCopyMemory(&nfs41_fcb->StandardInfo, &entry->u.Open.sinfo, 
            sizeof(entry->u.Open.sinfo));
        nfs41_fcb->mode = entry->u.Open.mode;
        nfs41_fcb->changeattr = entry->u.Open.changeattr;
        nfs41_fcb->Flags = FCB_BASIC_INFO_CACHED | FCB_STANDARD_INFO_CACHED;

        RxFormInitPacket(InitPacket,
            &entry->u.Open.binfo.FileAttributes,
            &entry->u.Open.sinfo.NumberOfLinks,
            &entry->u.Open.binfo.CreationTime,
            &entry->u.Open.binfo.LastAccessTime,
            &entry->u.Open.binfo.LastWriteTime,
            &entry->u.Open.binfo.ChangeTime,
            &entry->u.Open.sinfo.AllocationSize,
            &entry->u.Open.sinfo.EndOfFile,
            &entry->u.Open.sinfo.EndOfFile);

        if (entry->u.Open.sinfo.Directory)
            StorageType = FileTypeDirectory;
        else
            StorageType = FileTypeFile;

        RxFinishFcbInitialization(Fcb, RDBSS_STORAGE_NTC(StorageType), 
                                    &InitPacket);
    }
#ifdef DEBUG_OPEN
    else {
        DbgP("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
        if (nfs41_fcb->Flags) {
            print_basic_info(1, &nfs41_fcb->BasicInfo);
            print_std_info(1, &nfs41_fcb->StandardInfo);
        }
    }
#endif

    if (Fcb->OpenCount > 0 && 
            nfs41_fcb->changeattr != entry->u.Open.changeattr && 
                !nfs41_fcb->StandardInfo.Directory) {
        ULONG flag = DISABLE_CACHING;
#ifdef DEBUG_OPEN
        DbgP("nfs41_Create: reopening (changed) file %wZ\n", SrvOpen->pAlreadyPrefixedName);
#endif
        RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);
    } else if (!nfs41_fcb->StandardInfo.Directory && 
                isDataAccess(params.DesiredAccess)) {
        nfs41_fobx->deleg_type = entry->u.Open.deleg_type;
#ifdef DEBUG_OPEN
        DbgP("nfs41_Create: received delegation %d\n", entry->u.Open.deleg_type);
#endif
        if (!(params.CreateOptions & FILE_WRITE_THROUGH) &&
                !pVNetRootContext->write_thru &&
                (entry->u.Open.deleg_type == 2 ||
                (params.DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)))) {
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: enabling write buffering\n");
#endif
            SrvOpen->BufferingFlags |= 
                (FCB_STATE_WRITECACHING_ENABLED | 
                FCB_STATE_WRITEBUFFERING_ENABLED);
        }
        if (entry->u.Open.deleg_type >= 1 ||
                params.DesiredAccess & FILE_READ_DATA) {
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: enabling read buffering\n");
#endif
            SrvOpen->BufferingFlags |= 
                (FCB_STATE_READBUFFERING_ENABLED | 
                FCB_STATE_READCACHING_ENABLED);
        }
        if (pVNetRootContext->nocache || 
                (params.CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING)) {
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: disabling buffering\n");
#endif
            SrvOpen->BufferingFlags = FCB_STATE_DISABLE_LOCAL_BUFFERING;
        } else if (!entry->u.Open.deleg_type) {
            nfs41_srvopen_list_entry *oentry;
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: received no delegations: srv_open=%p "
                "ctime=%llu\n", SrvOpen, entry->u.Open.changeattr);
#endif
            oentry = RxAllocatePoolWithTag(NonPagedPool, 
                sizeof(nfs41_srvopen_list_entry), NFS41_MM_POOLTAG);
            if (oentry == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto out;
            }
            oentry->srv_open = SrvOpen;
            oentry->nfs41_fobx = nfs41_fobx;
            oentry->ChangeTime = entry->u.Open.changeattr;
            oentry->skip = FALSE;
            nfs41_AddEntry(srvopenLock, openlist, oentry);
        }
    }

    if ((params.CreateOptions & FILE_DELETE_ON_CLOSE) && 
            !pVNetRootContext->read_only)
        nfs41_fcb->StandardInfo.DeletePending = TRUE;

    RxContext->Create.ReturnedCreateInformation = 
        map_disposition_to_create_retval(params.Disposition, entry->errno);

    RxContext->pFobx->OffsetOfNextEaToReturn = 1;
    RxContext->CurrentIrp->IoStatus.Information = 
        RxContext->Create.ReturnedCreateInformation;
    status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;

out_free:
    if (entry)
        RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    if ((params.DesiredAccess & FILE_READ_DATA) ||
            (params.DesiredAccess & FILE_WRITE_DATA) ||
            (params.DesiredAccess & FILE_APPEND_DATA) ||
            (params.DesiredAccess & FILE_EXECUTE)) {
        InterlockedIncrement(&open.tops); 
        InterlockedAdd64(&open.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Create open delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, open.tops, open.ticks);
#endif
    } else {
        InterlockedIncrement(&lookup.tops); 
        InterlockedAdd64(&lookup.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Create lookup delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, lookup.tops, lookup.ticks);
#endif
    }
#endif
#ifdef DEBUG_OPEN
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_CollapseOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_ShouldTryToCollapseThisOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    if (RxContext->pRelevantSrvOpen == NULL) 
        return STATUS_SUCCESS;
    else return STATUS_MORE_PROCESSING_REQUIRED;
}

ULONG nfs41_ExtendForCache(
    IN OUT PRX_CONTEXT RxContext,
    IN PLARGE_INTEGER pNewFileSize,
    OUT PLARGE_INTEGER pNewAllocationSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
#ifdef DEBUG_CACHE
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    DbgEn();
    print_debug_header(RxContext);
    DbgP("input: byte count 0x%x filesize 0x%x alloc size 0x%x\n", 
        LowIoContext->ParamsFor.ReadWrite.ByteCount, *pNewFileSize, 
        *pNewAllocationSize);
#endif
    pNewAllocationSize->QuadPart = pNewFileSize->QuadPart + 8192;
    nfs41_fcb->StandardInfo.AllocationSize.QuadPart = 
        pNewAllocationSize->QuadPart;
    nfs41_fcb->StandardInfo.EndOfFile.QuadPart = pNewFileSize->QuadPart;
#ifdef DEBUG_CACHE
    DbgP("new filesize 0x%x new allocation size 0x%x\n", *pNewFileSize, 
        *pNewAllocationSize);
#endif
#ifdef DEBUG_CACHE
    DbgEx();
#endif
    return status;
}

VOID nfs41_remove_srvopen_entry(
    PMRX_SRV_OPEN SrvOpen)
{
    PLIST_ENTRY pEntry;
    nfs41_srvopen_list_entry *cur;
    ExAcquireFastMutex(&srvopenLock);

    pEntry = openlist->head.Flink;
#ifdef DEBUG_CLOSE
    DbgP("nfs41_remove_srvopen_entry: Looking for srv_open=%p\n", SrvOpen);
#endif
    while (!IsListEmpty(&openlist->head)) {
        cur = (nfs41_srvopen_list_entry *)CONTAINING_RECORD(pEntry, 
                nfs41_srvopen_list_entry, next);
        if (cur->srv_open == SrvOpen) {
#ifdef DEBUG_CLOSE
            DbgP("nfs41_remove_srvopen_entry: Found match\n");
#endif
            RemoveEntryList(pEntry);
            RxFreePool(cur);
            break;
        }
        if (pEntry->Flink == &openlist->head) {
#ifdef DEBUG_CLOSE
            DbgP("nfs41_remove_srvopen_entry: reached end of the list\n");
#endif
            break;
        }
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&srvopenLock);
}

NTSTATUS map_close_errors(
    DWORD status)
{
    switch (status) {
    case NO_ERROR:              return STATUS_SUCCESS;
    case ERROR_NETNAME_DELETED: return STATUS_NETWORK_NAME_DELETED;
    case ERROR_NOT_EMPTY:       return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_INVALID:    return STATUS_FILE_INVALID;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INTERNAL_ERROR\n", status);
    case ERROR_INTERNAL_ERROR: return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS nfs41_CloseSrvOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_CLOSE
    DbgEn();
    print_debug_header(RxContext);
#endif

    if (!nfs41_fobx->deleg_type && !nfs41_fcb->StandardInfo.Directory &&
            (SrvOpen->DesiredAccess & 
            (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA))) {
        nfs41_remove_srvopen_entry(SrvOpen);
    }

    status = nfs41_UpcallCreate(NFS41_CLOSE, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state, 
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.Close.srv_open = SrvOpen;
    entry->u.Close.filename = SrvOpen->pAlreadyPrefixedName;
    if (!RxContext->pFcb->OpenCount || 
            (nfs41_fcb->StandardInfo.DeletePending &&
                nfs41_fcb->StandardInfo.Directory))
        entry->u.Close.remove = nfs41_fcb->StandardInfo.DeletePending;
    if (!RxContext->pFcb->OpenCount)
        entry->u.Close.renamed = nfs41_fcb->Renamed;

    status = nfs41_UpcallWaitForReply(entry);
#ifndef USE_MOUNT_SEC_CONTEXT
    SeDeleteClientSecurity(&nfs41_fobx->sec_ctx);
#endif
    if (status != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    /* map windows ERRORs to NTSTATUS */
    status = map_close_errors(entry->status);
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&close.tops); 
    InterlockedAdd64(&close.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_CloseSrvOpen delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, close.tops, close.ticks);
#endif
#endif
#ifdef DEBUG_CLOSE
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_Flush(
    IN OUT PRX_CONTEXT RxContext)
{
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_DeallocateForFcb(
    IN OUT PMRX_FCB pFcb)
{
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_DeallocateForFobx(
    IN OUT PMRX_FOBX pFobx)
{
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(pFobx);
    if (nfs41_fobx->acl)
        RxFreePool(nfs41_fobx->acl);
    return STATUS_SUCCESS;
}

void print_debug_filedirquery_header(
    PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = %s\n", 
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext), 
        print_file_information_class(RxContext->Info.FileInformationClass));
}

void print_querydir_args(
    PRX_CONTEXT RxContext)
{
    print_debug_filedirquery_header(RxContext);
    DbgP("Filter='%wZ', Index=%d, Restart/Single/Specified/Init=%d/%d/%d/%d\n",
        &RxContext->pFobx->UnicodeQueryTemplate, 
        RxContext->QueryDirectory.FileIndex,
        RxContext->QueryDirectory.RestartScan,
        RxContext->QueryDirectory.ReturnSingleEntry,
        RxContext->QueryDirectory.IndexSpecified,
        RxContext->QueryDirectory.InitialQuery);
}

NTSTATUS map_querydir_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_BUFFER_OVERFLOW:     return STATUS_BUFFER_OVERFLOW;
    case ERROR_FILE_NOT_FOUND:      return STATUS_NO_SUCH_FILE;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_NO_MORE_FILES:       return STATUS_NO_MORE_FILES;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QueryDirectory(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    PUNICODE_STRING Filter = &RxContext->pFobx->UnicodeQueryTemplate;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_DIR_QUERY
    DbgEn();
    print_querydir_args(RxContext);
#endif

    switch (InfoClass) {
    /* classes handled in readdir_copy_entry() and readdir_size_for_entry() */
    case FileNamesInformation:
    case FileDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileIdFullDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileIdBothDirectoryInformation:
        break;
    default:
        print_error("nfs41_QueryDirectory: unhandled dir query class %d\n", 
            InfoClass);
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    status = nfs41_UpcallCreate(NFS41_DIR_QUERY, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.QueryFile.InfoClass = InfoClass;
    entry->u.QueryFile.buf_len = RxContext->Info.LengthRemaining;
    entry->u.QueryFile.buf = RxContext->Info.Buffer;
    entry->u.QueryFile.mdl = IoAllocateMdl(RxContext->Info.Buffer, 
        RxContext->Info.LengthRemaining, FALSE, FALSE, NULL);
    if (entry->u.QueryFile.mdl == NULL) {
        status = STATUS_INTERNAL_ERROR;
        RxFreePool(entry);
        goto out;
    }
    entry->u.QueryFile.mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;
    MmProbeAndLockPages(entry->u.QueryFile.mdl, KernelMode, IoModifyAccess);

    entry->u.QueryFile.filter = Filter;
    entry->u.QueryFile.initial_query = RxContext->QueryDirectory.InitialQuery;
    entry->u.QueryFile.restart_scan = RxContext->QueryDirectory.RestartScan;
    entry->u.QueryFile.return_single = RxContext->QueryDirectory.ReturnSingleEntry;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    MmUnlockPages(entry->u.QueryFile.mdl);

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        DbgP("nfs41_QueryDirectory: buffer too small provided %d need %d\n", 
            RxContext->Info.LengthRemaining, entry->u.QueryFile.buf_len);
        RxContext->InformationToReturn = entry->u.QueryFile.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&readdir.sops); 
        InterlockedAdd64(&readdir.size, entry->u.QueryFile.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->u.QueryFile.buf_len;
        status = STATUS_SUCCESS;
    } else {
        /* map windows ERRORs to NTSTATUS */
        status = map_querydir_errors(entry->status);
    }
    IoFreeMdl(entry->u.QueryFile.mdl);
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&readdir.tops); 
    InterlockedAdd64(&readdir.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryDirectory delta = %d ops=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, readdir.tops, readdir.ticks);
#endif
#endif
#ifdef DEBUG_DIR_QUERY
    DbgEx();
#endif
    return status;
}

void print_queryvolume_args(
    PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = %s BufferLen = %d\n", 
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext), 
        print_fs_information_class(RxContext->Info.FileInformationClass), 
        RxContext->Info.LengthRemaining);
}

NTSTATUS map_volume_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_VC_DISCONNECTED:     return STATUS_CONNECTION_DISCONNECTED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

void nfs41_create_volume_info(PFILE_FS_VOLUME_INFORMATION pVolInfo, DWORD *len)
{
    DECLARE_CONST_UNICODE_STRING(VolName, VOL_NAME);

    RtlZeroMemory(pVolInfo, sizeof(FILE_FS_VOLUME_INFORMATION));
    pVolInfo->VolumeSerialNumber = 0xBABAFACE;
    pVolInfo->VolumeLabelLength = VolName.Length;
    RtlCopyMemory(&pVolInfo->VolumeLabel[0], (PVOID)VolName.Buffer, 
        VolName.MaximumLength);
    *len = sizeof(FILE_FS_VOLUME_INFORMATION) + VolName.Length;
}

NTSTATUS nfs41_QueryVolumeInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    ULONG RemainingLength = RxContext->Info.LengthRemaining, SizeUsed;
    FS_INFORMATION_CLASS InfoClass = RxContext->Info.FsInformationClass;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    NFS41GetDeviceExtension(RxContext, DevExt);

#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_VOLUME_QUERY
    DbgEn();
    print_queryvolume_args(RxContext);
#endif

    switch (InfoClass) {
    case FileFsVolumeInformation:
        if ((ULONG)RxContext->Info.LengthRemaining >= DevExt->VolAttrsLen) {
            RtlCopyMemory(RxContext->Info.Buffer, DevExt->VolAttrs, 
                DevExt->VolAttrsLen);
            RxContext->Info.LengthRemaining -= DevExt->VolAttrsLen;
            status = STATUS_SUCCESS;
        } else {
            RxContext->InformationToReturn = DevExt->VolAttrsLen;
            status = STATUS_BUFFER_TOO_SMALL;            
        }
        goto out;
    case FileFsDeviceInformation:
    {
        PFILE_FS_DEVICE_INFORMATION pDevInfo = RxContext->Info.Buffer;

        SizeUsed = sizeof(FILE_FS_DEVICE_INFORMATION);
        if (RemainingLength < SizeUsed) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = SizeUsed;
            goto out;
        }
        pDevInfo->DeviceType = RxContext->pFcb->pNetRoot->DeviceType;
        pDevInfo->Characteristics = FILE_REMOTE_DEVICE | FILE_DEVICE_IS_MOUNTED;
        RxContext->Info.LengthRemaining -= SizeUsed;
        status = STATUS_SUCCESS;
        goto out;
    }

    case FileFsAttributeInformation:
        /* used cached fs attributes if available */
        if (pVNetRootContext->FsAttrsLen) {
            const LONG len = pVNetRootContext->FsAttrsLen;
            if (RxContext->Info.LengthRemaining < len) {
                RxContext->InformationToReturn = len;
                status = STATUS_BUFFER_TOO_SMALL;
                goto out;
            }
            RtlCopyMemory(RxContext->Info.Buffer,
                pVNetRootContext->FsAttrs, len);
            RxContext->Info.LengthRemaining -= len;
            status = STATUS_SUCCESS;
            goto out;
        }
        /* else fall through and send the upcall */
    case FileFsSizeInformation:
    case FileFsFullSizeInformation:
        break;

    default:
        print_error("unhandled fs query class %d\n", InfoClass);
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    status = nfs41_UpcallCreate(NFS41_VOLUME_QUERY, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state, 
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.Volume.query = InfoClass;
    entry->u.Volume.buf = RxContext->Info.Buffer;
    entry->u.Volume.buf_len = RxContext->Info.LengthRemaining;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->u.Volume.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        if (InfoClass == FileFsAttributeInformation) {
            /* fill in the FileSystemName */
            PFILE_FS_ATTRIBUTE_INFORMATION attrs =
                (PFILE_FS_ATTRIBUTE_INFORMATION)RxContext->Info.Buffer;
            DECLARE_CONST_UNICODE_STRING(FsName, FS_NAME);
            entry->u.Volume.buf_len += FsName.Length;
            if (entry->u.Volume.buf_len > (ULONG)RxContext->Info.LengthRemaining) {
                RxContext->InformationToReturn = entry->u.Volume.buf_len;
                status = STATUS_BUFFER_TOO_SMALL;
                goto out;
            }
            RtlCopyMemory(attrs->FileSystemName, FsName.Buffer,
                FsName.MaximumLength); /* 'MaximumLength' to include null */
            attrs->FileSystemNameLength = FsName.Length;

            /* save fs attributes with the vnetroot */
            if (entry->u.Volume.buf_len <= FS_ATTR_LEN) {
                RtlCopyMemory(&pVNetRootContext->FsAttrs,
                    RxContext->Info.Buffer, entry->u.Volume.buf_len);
                pVNetRootContext->FsAttrsLen = entry->u.Volume.buf_len;
            }
        }
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&volume.sops); 
        InterlockedAdd64(&volume.size, entry->u.Volume.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->u.Volume.buf_len;
        status = STATUS_SUCCESS;
    } else {
        status = map_volume_errors(entry->status);
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&volume.tops); 
    InterlockedAdd64(&volume.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryVolumeInformation delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, volume.tops, volume.ticks);
#endif
#endif
#ifdef DEBUG_VOLUME_QUERY
    DbgEx();
#endif
    return status;
}

VOID nfs41_update_srvopen_list(
    PMRX_SRV_OPEN SrvOpen,
    ULONGLONG ChangeTime)
{
    PLIST_ENTRY pEntry;
    nfs41_srvopen_list_entry *cur;
    ExAcquireFastMutex(&srvopenLock); 
    pEntry = openlist->head.Flink;
#if defined(DEBUG_FILE_SET) || defined(DEBUG_ACL_SET) || \
    defined(DEBUG_WRITE) || defined(DEBUG_EA_SET)
    DbgP("nfs41_update_srvopen_list: Looking for srv_open=%p\n", SrvOpen);
#endif
    while (!IsListEmpty(&openlist->head)) {
        cur = (nfs41_srvopen_list_entry *)CONTAINING_RECORD(pEntry, 
                nfs41_srvopen_list_entry, next);
        if (cur->srv_open == SrvOpen && 
                cur->ChangeTime != ChangeTime) {
#if defined(DEBUG_FILE_SET) || defined(DEBUG_ACL_SET) || \
    defined(DEBUG_WRITE) || defined(DEBUG_EA_SET)
            DbgP("nfs41_update_srvopen_list: Found match: updating %llu to "
                "%llu\n", cur->ChangeTime, ChangeTime);
#endif
            cur->ChangeTime = ChangeTime;
            break;
        }
        /* place an upcall for this srv_open */
        if (pEntry->Flink == &openlist->head) {
#if defined(DEBUG_FILE_SET) || defined(DEBUG_ACL_SET) || \
    defined(DEBUG_WRITE) || defined(DEBUG_EA_SET)
            DbgP("nfs41_update_srvopen_list: reached end of the list\n");
#endif
            break;
        }
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&srvopenLock);
}

void print_nfs3_attrs(
    nfs3_attrs *attrs)
{
    DbgP("type=%d mode=%o nlink=%d size=%d atime=%x mtime=%x ctime=%x\n",
        attrs->type, attrs->mode, attrs->nlink, attrs->size, attrs->atime,
        attrs->mtime, attrs->ctime);
}

void file_time_to_nfs_time(
    IN const PLARGE_INTEGER file_time,
    OUT LONGLONG *nfs_time)
{
    LARGE_INTEGER diff = unix_time_diff;
    diff.QuadPart = file_time->QuadPart - diff.QuadPart;
    *nfs_time = diff.QuadPart / 10000000;
}

void create_nfs3_attrs(
    nfs3_attrs *attrs, 
    PNFS41_FCB nfs41_fcb)
{
    RtlZeroMemory(attrs, sizeof(nfs3_attrs));
    if (nfs41_fcb->BasicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        attrs->type = NF3LNK;
    else if (nfs41_fcb->StandardInfo.Directory)
        attrs->type = NF3DIR;
    else
        attrs->type = NF3REG;
    attrs->mode = nfs41_fcb->mode;
    attrs->nlink = nfs41_fcb->StandardInfo.NumberOfLinks;
    attrs->size.QuadPart = attrs->used.QuadPart = 
        nfs41_fcb->StandardInfo.EndOfFile.QuadPart;
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.LastAccessTime, &attrs->atime);
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.ChangeTime, &attrs->mtime);
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.CreationTime, &attrs->ctime);
}


NTSTATUS map_setea_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_NOT_EMPTY:               return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_NOT_SUPPORTED:           return STATUS_NOT_IMPLEMENTED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_PARAMETER\n", error);
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS nfs41_SetEaInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_EAS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    PUNICODE_STRING FileName = GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext);
    __notnull PFILE_FULL_EA_INFORMATION eainfo = 
        (PFILE_FULL_EA_INFORMATION)RxContext->Info.Buffer;        
    nfs3_attrs *attrs = NULL;
    ULONG buflen = RxContext->CurrentIrpSp->Parameters.SetEa.Length, error_offset;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_EA_SET
    DbgEn();
    print_debug_header(RxContext);
    print_ea_info(1, eainfo);
#endif

    if (pVNetRootContext->read_only) {
        DbgP("Read-only mount\n");
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_EA_SET, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;

    if (AnsiStrEq(&NfsV3Attributes, eainfo->EaName, eainfo->EaNameLength)) {
        attrs = (nfs3_attrs *)(eainfo->EaName + eainfo->EaNameLength + 1);
#ifdef DEBUG_EA_SET
        print_nfs3_attrs(attrs);
        DbgP("old mode is %o new mode is %o\n", nfs41_fcb->mode, attrs->mode);
#endif
        entry->u.SetEa.mode = nfs41_fcb->mode = attrs->mode;
    } else {
        entry->u.SetEa.mode = 0;
        status = IoCheckEaBufferValidity(eainfo, buflen, &error_offset);
        if (status) {
            RxFreePool(entry);
            goto out;
        }
    }
    entry->u.SetEa.buf = eainfo;
    entry->u.SetEa.buf_len = buflen;
    entry->u.SetEa.filename = FileName;
     
    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
#ifdef ENABLE_TIMINGS
    if (entry->status == STATUS_SUCCESS) {
        InterlockedIncrement(&setexattr.sops); 
        InterlockedAdd64(&setexattr.size, entry->u.SetEa.buf_len);
    }
#endif
    status = map_setea_error(entry->status);
    if (!status) {
        if (!nfs41_fobx->deleg_type && entry->u.SetEa.ChangeTime &&
                (SrvOpen->DesiredAccess & 
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_srvopen_list(SrvOpen, entry->u.SetEa.ChangeTime);
        nfs41_fcb->changeattr = entry->u.SetEa.ChangeTime;
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setexattr.tops); 
    InterlockedAdd64(&setexattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetEaInformation delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, setexattr.tops, setexattr.ticks);
#endif
#endif
#ifdef DEBUG_EA_SET
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_QueryEaInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_EAS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    PFILE_GET_EA_INFORMATION query = (PFILE_GET_EA_INFORMATION)
            RxContext->CurrentIrpSp->Parameters.QueryEa.EaList;
    __notnull PFILE_FULL_EA_INFORMATION info = 
        (PFILE_FULL_EA_INFORMATION)RxContext->Info.Buffer;        
    PUNICODE_STRING FileName = GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext);
    ULONG buflen = RxContext->CurrentIrpSp->Parameters.QueryEa.Length;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
            NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
            NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_EA_QUERY
    DbgEn();
    print_debug_header(RxContext);
#endif
    if (RxContext->CurrentIrpSp->Parameters.QueryEa.EaList == NULL)
        goto out;

#ifdef DEBUG_EA_QUERY
    print_get_ea(1, query);
#endif

    if (AnsiStrEq(&NfsV3Attributes, query->EaName, query->EaNameLength)) {
        nfs3_attrs attrs;

        const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
            NfsV3Attributes.Length + sizeof(nfs3_attrs) - sizeof(CHAR);
        if (LengthRequired > RxContext->Info.LengthRemaining) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = LengthRequired;
            goto out;
        }

        create_nfs3_attrs(&attrs, nfs41_fcb);
#ifdef DEBUG_EA_QUERY
        print_nfs3_attrs(&attrs);
#endif

        info->NextEntryOffset = 0;
        info->Flags = 0;
        info->EaNameLength = (UCHAR)NfsV3Attributes.Length;
        info->EaValueLength = sizeof(nfs3_attrs);
        RtlCopyMemory(info->EaName, NfsV3Attributes.Buffer, 
            NfsV3Attributes.Length);
        RtlCopyMemory(info->EaName + info->EaNameLength + 1, &attrs, 
            sizeof(nfs3_attrs));
        RxContext->Info.LengthRemaining = LengthRequired;
        status = STATUS_SUCCESS;
        goto out;
    } 
        
    if (AnsiStrEq(&NfsActOnLink, query->EaName, query->EaNameLength) || 
            AnsiStrEq(&NfsSymlinkTargetName, query->EaName, 
                query->EaNameLength)) {

        const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
            NfsActOnLink.Length - sizeof(CHAR);
        if (LengthRequired > RxContext->Info.LengthRemaining) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = LengthRequired;
            goto out;
        }

        info->NextEntryOffset = 0;
        info->Flags = 0;
        info->EaNameLength = (UCHAR)NfsActOnLink.Length;
        info->EaValueLength = 0;
        RtlCopyMemory(info->EaName, NfsActOnLink.Buffer, NfsActOnLink.Length);
        RxContext->Info.LengthRemaining = LengthRequired;
        status = STATUS_SUCCESS;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_EA_GET, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out; 
    entry->u.QueryEa.filename = FileName;  
    entry->u.QueryEa.buf_len = buflen; 
    entry->u.QueryEa.buf = RxContext->Info.Buffer; 
    entry->u.QueryEa.EaList = query;
    entry->u.QueryEa.EaListLength = RxContext->QueryEa.UserEaListLength;
    entry->u.QueryEa.EaIndex = RxContext->QueryEa.UserEaIndex;
    entry->u.QueryEa.RestartScan = RxContext->QueryEa.RestartScan;
    entry->u.QueryEa.ReturnSingleEntry = RxContext->QueryEa.ReturnSingleEntry;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->u.QueryEa.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        RxContext->Info.LengthRemaining = entry->u.QueryEa.buf_len;
        RxContext->IoStatusBlock.Status = STATUS_SUCCESS; 
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getexattr.sops); 
        InterlockedAdd64(&getexattr.size, entry->u.QueryEa.buf_len);
#endif
    } else {
        status = map_setea_error(entry->status);
    }
    RxFreePool(entry);        
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&getexattr.tops); 
    InterlockedAdd64(&getexattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryEaInformation delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, getexattr.tops, getexattr.ticks);
#endif
#endif
#ifdef DEBUG_EA_QUERY
    DbgEx();
#endif
    return status;
}

NTSTATUS map_query_acl_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_NOT_SUPPORTED:       return STATUS_NOT_SUPPORTED;
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_FILE_NOT_FOUND:      return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", error);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QuerySecurityInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    SECURITY_INFORMATION info_class =
        RxContext->CurrentIrpSp->Parameters.QuerySecurity.SecurityInformation;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_ACL_QUERY
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(info_class);
#endif

    /* we don't support sacls */
    if (info_class == SACL_SECURITY_INFORMATION || 
            info_class == LABEL_SECURITY_INFORMATION)
        goto out;

    if (nfs41_fobx->acl && nfs41_fobx->acl_len) {
        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);
#ifdef DEBUG_ACL_QUERY
        DbgP("CurrentTime %lx Saved Acl time %lx\n", 
            current_time.QuadPart, nfs41_fobx->time.QuadPart);
#endif
        if (current_time.QuadPart - nfs41_fobx->time.QuadPart <= 20*1000) {         
            PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
                RxContext->CurrentIrp->UserBuffer;
            RtlCopyMemory(sec_desc, nfs41_fobx->acl, nfs41_fobx->acl_len); 
            RxContext->IoStatusBlock.Information = 
                RxContext->InformationToReturn = nfs41_fobx->acl_len;
            RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;
#ifdef ENABLE_TIMINGS
            InterlockedIncrement(&getacl.sops);
            InterlockedAdd64(&getacl.size, nfs41_fobx->acl_len);
#endif
        }
        RxFreePool(nfs41_fobx->acl);
        nfs41_fobx->acl = NULL;
        nfs41_fobx->acl_len = 0;
        if (!status)
            goto out;
    }

    status = nfs41_UpcallCreate(NFS41_ACL_QUERY, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.Acl.query = info_class;
    /* we can't provide RxContext->CurrentIrp->UserBuffer to the upcall thread 
     * because it becomes an invalid pointer with that execution context
     */
    entry->u.Acl.buf_len = RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
#ifdef DEBUG_ACL_QUERY
        DbgP("nfs41_QuerySecurityInformation: provided buffer size=%d but we "
             "need %d\n", 
             RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length, 
             entry->u.Acl.buf_len);
#endif
        status = STATUS_BUFFER_OVERFLOW;
        RxContext->InformationToReturn = entry->u.Acl.buf_len;

        /* Save ACL buffer */
        nfs41_fobx->acl = entry->u.Acl.buf;
        nfs41_fobx->acl_len = entry->u.Acl.buf_len;
        KeQuerySystemTime(&nfs41_fobx->time);
    } else if (entry->status == STATUS_SUCCESS) {
        PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
            RxContext->CurrentIrp->UserBuffer;
        RtlCopyMemory(sec_desc, entry->u.Acl.buf, entry->u.Acl.buf_len); 
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getacl.sops);
        InterlockedAdd64(&getacl.size, entry->u.Acl.buf_len);
#endif
        RxFreePool(entry->u.Acl.buf);
        nfs41_fobx->acl = NULL;
        nfs41_fobx->acl_len = 0;
        RxContext->IoStatusBlock.Information = RxContext->InformationToReturn = 
            entry->u.Acl.buf_len;
        RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;
    } else {
        status = map_query_acl_error(entry->status);
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    /* only count getacl that we made an upcall for */
    if (status == STATUS_BUFFER_OVERFLOW) {
        InterlockedIncrement(&getacl.tops); 
        InterlockedAdd64(&getacl.ticks, t2.QuadPart - t1.QuadPart);
    }
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QuerySecurityInformation: delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, getacl.tops, getacl.ticks);
#endif
#endif
#ifdef DEBUG_ACL_QUERY
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_SetSecurityInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PSECURITY_DESCRIPTOR sec_desc = 
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityDescriptor;
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    SECURITY_INFORMATION info_class = 
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityInformation;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_ACL_SET
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(info_class);
#endif

    if (pVNetRootContext->read_only) {
        DbgP("Read-only mount\n");
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    /* check that ACL is present */
    if (info_class & DACL_SECURITY_INFORMATION) {
        PACL acl;
        BOOLEAN present, dacl_default;
        status = RtlGetDaclSecurityDescriptor(sec_desc, &present, &acl, 
                    &dacl_default);
        if (status) {
            DbgP("RtlGetDaclSecurityDescriptor failed %x\n", status);
            goto out;
        }
        if (present == FALSE) {
            DbgP("NO ACL present\n");
            goto out;
        }
    }

    /* we don't support sacls */
    if (info_class == SACL_SECURITY_INFORMATION  || 
            info_class == LABEL_SECURITY_INFORMATION)
        goto out;

    status = nfs41_UpcallCreate(NFS41_ACL_SET, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.Acl.query = info_class;
    entry->u.Acl.buf = sec_desc;
    entry->u.Acl.buf_len = RtlLengthSecurityDescriptor(sec_desc);
#ifdef ENABLE_TIMINGS
    InterlockedIncrement(&setacl.sops); 
    InterlockedAdd64(&setacl.size, entry->u.Acl.buf_len);    
#endif

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    status = map_query_acl_error(entry->status);
    if (!status) {
        if (!nfs41_fobx->deleg_type && entry->u.Acl.ChangeTime &&
                (SrvOpen->DesiredAccess & 
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_srvopen_list(SrvOpen, entry->u.Acl.ChangeTime);
        nfs41_fcb->changeattr = entry->u.Acl.ChangeTime;
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setacl.tops); 
    InterlockedAdd64(&setacl.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetSecurityInformation delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, setacl.tops, setacl.ticks);
#endif
#endif
#ifdef DEBUG_ACL_SET
    DbgEx();
#endif
    return status;
}

NTSTATUS map_queryfile_error(
    DWORD error)
{
    switch (error) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", error);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QueryFileInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    nfs41_updowncall_entry *entry;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_FILE_QUERY
    DbgEn();
    print_debug_filedirquery_header(RxContext);
#endif
    switch (InfoClass) {
    case FileEaInformation:
    {
        PFILE_EA_INFORMATION info =
            (PFILE_EA_INFORMATION)RxContext->Info.Buffer;
        info->EaSize = 0;
        RxContext->Info.LengthRemaining -= sizeof(FILE_EA_INFORMATION);
        status = STATUS_SUCCESS;
        goto out;
    }
#ifdef FCB_ATTR_CACHING
    case FileBasicInformation:
        if(nfs41_fcb->Flags & FCB_BASIC_INFO_CACHED) {
            RtlCopyMemory(RxContext->Info.Buffer, &nfs41_fcb->BasicInfo, 
                sizeof(nfs41_fcb->BasicInfo));
            RxContext->Info.LengthRemaining -= sizeof(nfs41_fcb->BasicInfo);
            status = STATUS_SUCCESS;
            goto out;
        }
        break;
    case FileStandardInformation:
        if(nfs41_fcb->Flags & FCB_STANDARD_INFO_CACHED) {
            RtlCopyMemory(RxContext->Info.Buffer, &nfs41_fcb->StandardInfo, 
                sizeof(nfs41_fcb->StandardInfo));
            RxContext->Info.LengthRemaining -= sizeof(nfs41_fcb->StandardInfo);
            status = STATUS_SUCCESS;
            goto out;
        }
        break;
#else
    case FileBasicInformation:
    case FileStandardInformation:
#endif
    case FileInternalInformation: 
    case FileAttributeTagInformation:
        break;
    default:
        print_error("unhandled file query class %d\n", InfoClass);
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_FILE_QUERY, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.QueryFile.InfoClass = InfoClass;
    entry->u.QueryFile.buf = RxContext->Info.Buffer;
    entry->u.QueryFile.buf_len = RxContext->Info.LengthRemaining;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->u.QueryFile.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        BOOLEAN DeletePending = FALSE;
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getattr.sops); 
        InterlockedAdd64(&getattr.size, entry->u.QueryFile.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->u.QueryFile.buf_len;
        status = STATUS_SUCCESS;

        switch (InfoClass) {
        case FileBasicInformation:
            RtlCopyMemory(&nfs41_fcb->BasicInfo, RxContext->Info.Buffer, 
                sizeof(nfs41_fcb->BasicInfo));
            nfs41_fcb->Flags |= FCB_BASIC_INFO_CACHED;
#ifdef DEBUG_FILE_QUERY
            print_basic_info(1, &nfs41_fcb->BasicInfo);
#endif
            break;
        case FileStandardInformation:
#ifndef FCB_ATTR_CACHING
            /* this a fix for RDBSS behaviour when it first calls ExtendForCache,
             * then it sends a file query irp for standard attributes and 
             * expects to receive EndOfFile of value set by the ExtendForCache.
             * It seems to cache the filesize based on that instead of sending
             * a file size query for after doing the write. 
             */
        {
            PFILE_STANDARD_INFORMATION std_info;
            std_info = (PFILE_STANDARD_INFORMATION)RxContext->Info.Buffer;
            if (nfs41_fcb->StandardInfo.AllocationSize.QuadPart > 
                    std_info->AllocationSize.QuadPart) {
#ifdef DEBUG_FILE_QUERY
                DbgP("Old AllocationSize is bigger: saving %x\n", 
                    nfs41_fcb->StandardInfo.AllocationSize.QuadPart);
#endif
                std_info->AllocationSize.QuadPart = 
                    nfs41_fcb->StandardInfo.AllocationSize.QuadPart;
            }
            if (nfs41_fcb->StandardInfo.EndOfFile.QuadPart > 
                    std_info->EndOfFile.QuadPart) {
#ifdef DEBUG_FILE_QUERY
                DbgP("Old EndOfFile is bigger: saving %x\n", 
                    nfs41_fcb->StandardInfo.EndOfFile);
#endif
                std_info->EndOfFile.QuadPart = 
                    nfs41_fcb->StandardInfo.EndOfFile.QuadPart;
            }
        }
#endif
            if (nfs41_fcb->StandardInfo.DeletePending)
                DeletePending = TRUE;
            RtlCopyMemory(&nfs41_fcb->StandardInfo, RxContext->Info.Buffer, 
                sizeof(nfs41_fcb->StandardInfo));
            nfs41_fcb->StandardInfo.DeletePending = DeletePending;
            nfs41_fcb->Flags |= FCB_STANDARD_INFO_CACHED;
#ifdef DEBUG_FILE_QUERY
            print_std_info(1, &nfs41_fcb->StandardInfo);
#endif
            break;
        }
    } else {
        status = map_queryfile_error(entry->status);
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&getattr.tops); 
    InterlockedAdd64(&getattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryFileInformation delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, getattr.tops, getattr.ticks);
#endif
#endif
#ifdef DEBUG_FILE_QUERY
    DbgEx();
#endif
    return status;
}

NTSTATUS map_setfile_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_NOT_EMPTY:               return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_NOT_SAME_DEVICE:         return STATUS_NOT_SAME_DEVICE;
    case ERROR_NOT_SUPPORTED:           return STATUS_NOT_IMPLEMENTED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_PARAMETER\n", error);
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS nfs41_SetFileInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    FILE_RENAME_INFORMATION rinfo;
    PUNICODE_STRING FileName = GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_FILE_SET
    DbgEn();
    print_debug_filedirquery_header(RxContext);
#endif

    if (pVNetRootContext->read_only) {
        DbgP("Read-only mount\n");
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    /* http://msdn.microsoft.com/en-us/library/ff469355(v=PROT.10).aspx
     * http://msdn.microsoft.com/en-us/library/ff469424(v=PROT.10).aspx
     * If Open.GrantedAccess does not contain FILE_WRITE_DATA, the operation 
     * MUST be failed with STATUS_ACCESS_DENIED.
     */
    if (InfoClass == FileAllocationInformation || 
            InfoClass == FileEndOfFileInformation) {
        if (!(SrvOpen->DesiredAccess & FILE_WRITE_DATA)) {
            status = STATUS_ACCESS_DENIED;
            goto out;
        }
    }

    switch (InfoClass) {
    case FileRenameInformation:
    {
        PFILE_RENAME_INFORMATION rinfo = 
            (PFILE_RENAME_INFORMATION)RxContext->Info.Buffer;
#ifdef DEBUG_FILE_SET
        UNICODE_STRING dst = { (USHORT)rinfo->FileNameLength,
            (USHORT)rinfo->FileNameLength, rinfo->FileName };
        DbgP("Attempting to rename to '%wZ'\n", &dst);
#endif
        if (rinfo->RootDirectory) {
            status = STATUS_NOT_SUPPORTED;
            goto out;
        }
        nfs41_fcb->Flags = 0;
    }
    break;
    case FileLinkInformation:
    {
        PFILE_LINK_INFORMATION linfo = 
            (PFILE_LINK_INFORMATION)RxContext->Info.Buffer;
#ifdef DEBUG_FILE_SET
        UNICODE_STRING dst = { (USHORT)linfo->FileNameLength,
            (USHORT)linfo->FileNameLength, linfo->FileName };
        DbgP("Attempting to add link as '%wZ'\n", &dst);
#endif
        if (linfo->RootDirectory) {
            status = STATUS_NOT_SUPPORTED;
            goto out;
        }
        nfs41_fcb->Flags = 0;
    }
    break;
    case FileDispositionInformation:
    {
        PFILE_DISPOSITION_INFORMATION dinfo =
            (PFILE_DISPOSITION_INFORMATION)RxContext->Info.Buffer;
        if (dinfo->DeleteFile) {
            // we can delete directories right away
            if (nfs41_fcb->StandardInfo.Directory)
                break;
            nfs41_fcb->Flags = 0;
            nfs41_fcb->StandardInfo.DeletePending = TRUE;
            if (RxContext->pFcb->OpenCount > 1) {
                rinfo.ReplaceIfExists = 0;
                rinfo.RootDirectory = INVALID_HANDLE_VALUE;
                rinfo.FileNameLength = 0;
                rinfo.FileName[0] = L'\0';
                InfoClass = FileRenameInformation;
                nfs41_fcb->Renamed = TRUE;
                break;
            }
        }
        status = STATUS_SUCCESS;
        goto out;
    }
    case FileBasicInformation:
    case FileAllocationInformation:
        nfs41_fcb->Flags = 0;
        break;
    case FileEndOfFileInformation:
    {
        PFILE_END_OF_FILE_INFORMATION info =
            (PFILE_END_OF_FILE_INFORMATION)RxContext->Info.Buffer;
        nfs41_fcb->StandardInfo.AllocationSize =
            nfs41_fcb->StandardInfo.EndOfFile = info->EndOfFile;
        nfs41_fcb->Flags = 0;
        break;
    }
    default:
        print_error("unknown set_file information class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_FILE_SET, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.SetFile.filename = FileName;
    entry->u.SetFile.InfoClass = InfoClass;

    if (RxContext->Info.FileInformationClass == FileDispositionInformation && 
            InfoClass == FileRenameInformation) {
        entry->u.SetFile.buf = &rinfo;
        entry->u.SetFile.buf_len = sizeof(rinfo);
    } else {
        entry->u.SetFile.buf = RxContext->Info.Buffer;
        entry->u.SetFile.buf_len = RxContext->Info.Length;
    }
#ifdef ENABLE_TIMINGS
    InterlockedIncrement(&setattr.sops); 
    InterlockedAdd64(&setattr.size, entry->u.SetFile.buf_len);
#endif

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_setfile_error(entry->status);
    if (!status) {
        if (!nfs41_fobx->deleg_type && entry->u.SetFile.ChangeTime &&
                (SrvOpen->DesiredAccess & 
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_srvopen_list(SrvOpen, entry->u.SetFile.ChangeTime);
        nfs41_fcb->changeattr = entry->u.SetFile.ChangeTime;
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setattr.tops); 
    InterlockedAdd64(&setattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetFileInformation delta = %d op=%d sum=%d\n", 
        t2.QuadPart - t1.QuadPart, setattr.tops, setattr.ticks);
#endif
#endif
#ifdef DEBUG_FILE_SET
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_SetFileInformationAtCleanup(
      IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    DbgEn();
    status = nfs41_SetFileInformation(RxContext);
    DbgEx();
    return status;
}

NTSTATUS nfs41_IsValidDirectory (
    IN OUT PRX_CONTEXT RxContext,
    IN PUNICODE_STRING DirectoryName)
{
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_ComputeNewBufferingState(
    IN OUT PMRX_SRV_OPEN pSrvOpen,
    IN PVOID pMRxContext,
    OUT ULONG *pNewBufferingState)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG flag;
    DbgEn();
    flag = PtrToUlong(pMRxContext);
    DbgP("nfs41_ComputeNewBufferingState: pSrvOpen %p Flags %08x\n", 
        pSrvOpen, pSrvOpen->BufferingFlags);
    switch(flag) {
    case DISABLE_CACHING:
        if (pSrvOpen->BufferingFlags & 
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED))
            pSrvOpen->BufferingFlags &= 
                ~(FCB_STATE_READBUFFERING_ENABLED | 
                  FCB_STATE_READCACHING_ENABLED);
        if (pSrvOpen->BufferingFlags & 
            (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED))
            pSrvOpen->BufferingFlags &= 
                ~(FCB_STATE_WRITECACHING_ENABLED | 
                  FCB_STATE_WRITEBUFFERING_ENABLED);
        pSrvOpen->BufferingFlags |= FCB_STATE_DISABLE_LOCAL_BUFFERING;
        break;
    case ENABLE_READ_CACHING:
        pSrvOpen->BufferingFlags |= 
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED);
        break;
    case ENABLE_WRITE_CACHING:
        pSrvOpen->BufferingFlags |= 
            (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
        break;
    case ENABLE_READWRITE_CACHING:
        pSrvOpen->BufferingFlags = 
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED | 
            FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
    }
    DbgP("nfs41_ComputeNewBufferingState: new Flags %08x\n", 
        pSrvOpen->BufferingFlags);
    *pNewBufferingState = pSrvOpen->BufferingFlags;

    DbgEx();
    return status;
}

void print_readwrite_args(
    PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;

    print_debug_header(RxContext);
    DbgP("Bytecount 0x%x Byteoffset 0x%x Buffer %p\n", 
        LowIoContext->ParamsFor.ReadWrite.ByteCount, 
        LowIoContext->ParamsFor.ReadWrite.ByteOffset, 
        LowIoContext->ParamsFor.ReadWrite.Buffer);
}

void enable_caching(
    PMRX_SRV_OPEN SrvOpen,
    PNFS41_FOBX nfs41_fobx,
    ULONGLONG ChangeTime)
{
    ULONG flag = 0;
    PLIST_ENTRY pEntry;
    nfs41_srvopen_list_entry *cur;
    BOOLEAN found = FALSE;

    if (SrvOpen->DesiredAccess & FILE_READ_DATA)
        flag = ENABLE_READ_CACHING;
    if (SrvOpen->DesiredAccess & FILE_WRITE_DATA)
        flag = ENABLE_WRITE_CACHING;
    if ((SrvOpen->DesiredAccess & FILE_READ_DATA) && 
        (SrvOpen->DesiredAccess & FILE_WRITE_DATA))
        flag = ENABLE_READWRITE_CACHING;

    print_caching_level(1, flag);

    if (!flag)
        return;

    RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);

    ExAcquireFastMutex(&srvopenLock);
    pEntry = openlist->head.Flink;
    DbgP("enable_caching: Looking for srv_open=%p\n", SrvOpen);
    while (!IsListEmpty(&openlist->head)) {
        cur = (nfs41_srvopen_list_entry *)CONTAINING_RECORD(pEntry,
                nfs41_srvopen_list_entry, next);
        if (cur->srv_open == SrvOpen) {
            DbgP("enable_caching: Found match\n");
            cur->skip = FALSE;
            found = TRUE;
            break;
        }
        if (pEntry->Flink == &openlist->head) {
            DbgP("enable_caching: reached end of the list\n");
            break;
        }
        pEntry = pEntry->Flink;
    }
    if (!found && nfs41_fobx->deleg_type) {
        nfs41_srvopen_list_entry *oentry;
        DbgP("enable_caching: delegation recalled: srv_open=%p\n", SrvOpen);
        oentry = RxAllocatePoolWithTag(NonPagedPool, 
            sizeof(nfs41_srvopen_list_entry), NFS41_MM_POOLTAG);
        if (oentry == NULL) return;
        oentry->srv_open = SrvOpen;
        oentry->nfs41_fobx = nfs41_fobx;
        oentry->ChangeTime = ChangeTime;
        oentry->skip = FALSE;
        InsertTailList(&openlist->head, &oentry->next);
        nfs41_fobx->deleg_type = 0;
    }
    ExReleaseFastMutex(&srvopenLock);
}

NTSTATUS map_readwrite_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_HANDLE_EOF:              return STATUS_END_OF_FILE;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    case ERROR_LOCK_VIOLATION:          return STATUS_FILE_LOCK_CONFLICT;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_NET_WRITE_FAULT\n", status);
    case ERROR_NET_WRITE_FAULT:         return STATUS_NET_WRITE_FAULT;
    }
}

NTSTATUS nfs41_Read(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;
    BOOLEAN async = FALSE;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_READ
    DbgEn();
    print_readwrite_args(RxContext);
#endif

    status = nfs41_UpcallCreate(NFS41_READ, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.ReadWrite.MdlAddress = LowIoContext->ParamsFor.ReadWrite.Buffer;
    entry->u.ReadWrite.len = LowIoContext->ParamsFor.ReadWrite.ByteCount;
    entry->u.ReadWrite.offset = LowIoContext->ParamsFor.ReadWrite.ByteOffset;
    if (FlagOn(RxContext->CurrentIrpSp->FileObject->Flags, 
            FO_SYNCHRONOUS_IO) == FALSE) {
        entry->u.ReadWrite.rxcontext = RxContext;
        async = entry->async_op = TRUE;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (async) {
        DbgP("This is asynchronous read, returning control back to the user\n");
        status = STATUS_PENDING;
        goto out;
    }

    if (entry->status == NO_ERROR) {
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&read.sops); 
        InterlockedAdd64(&read.size, entry->u.ReadWrite.len);
#endif
        status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = entry->u.ReadWrite.len;
        nfs41_fcb->Flags = 0;

        if ((!BooleanFlagOn(LowIoContext->ParamsFor.ReadWrite.Flags, 
                LOWIO_READWRITEFLAG_PAGING_IO) && 
                (SrvOpen->DesiredAccess & FILE_READ_DATA) &&
                !pVNetRootContext->nocache &&
                !(SrvOpen->BufferingFlags & 
                (FCB_STATE_READBUFFERING_ENABLED | 
                 FCB_STATE_READCACHING_ENABLED)))) {
            enable_caching(SrvOpen, nfs41_fobx, nfs41_fcb->changeattr);
        }
    } else {
        status = map_readwrite_errors(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&read.tops); 
    InterlockedAdd64(&read.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Read delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart, 
        read.tops, read.ticks);
#endif
#endif
#ifdef DEBUG_READ
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_Write(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;
    BOOLEAN async = FALSE;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_WRITE
    DbgEn();
    print_readwrite_args(RxContext);
#endif

    if (pVNetRootContext->read_only) {
        DbgP("Read-only mount\n");
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_WRITE, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.ReadWrite.MdlAddress = LowIoContext->ParamsFor.ReadWrite.Buffer;
    entry->u.ReadWrite.len = LowIoContext->ParamsFor.ReadWrite.ByteCount;
    entry->u.ReadWrite.offset = LowIoContext->ParamsFor.ReadWrite.ByteOffset;

    if (FlagOn(RxContext->CurrentIrpSp->FileObject->Flags, 
            FO_SYNCHRONOUS_IO) == FALSE) {
        entry->u.ReadWrite.rxcontext = RxContext;
        async = entry->async_op = TRUE;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (async) {
        DbgP("This is asynchronous write, returning control back to the user\n");
        status = STATUS_PENDING;
        goto out;
    }
    
    if (entry->status == NO_ERROR) {
        //update cached file attributes
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&write.sops); 
        InterlockedAdd64(&write.size, entry->u.ReadWrite.len);
#endif
        nfs41_fcb->StandardInfo.EndOfFile.QuadPart = entry->u.ReadWrite.len + 
            entry->u.ReadWrite.offset;
        status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = entry->u.ReadWrite.len;
        nfs41_fcb->Flags = 0;
        nfs41_fcb->changeattr = entry->u.ReadWrite.ChangeTime;

        //re-enable write buffering
        if ((!BooleanFlagOn(LowIoContext->ParamsFor.ReadWrite.Flags, 
                LOWIO_READWRITEFLAG_PAGING_IO) && 
                (SrvOpen->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) &&
                !pVNetRootContext->write_thru &&
                !pVNetRootContext->nocache &&
                !(SrvOpen->BufferingFlags & 
                (FCB_STATE_WRITEBUFFERING_ENABLED | 
                 FCB_STATE_WRITECACHING_ENABLED)))) {
            enable_caching(SrvOpen, nfs41_fobx, nfs41_fcb->changeattr);
        } else if (!nfs41_fobx->deleg_type) 
            nfs41_update_srvopen_list(SrvOpen, entry->u.ReadWrite.ChangeTime);

    } else {
        status = map_readwrite_errors(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&write.tops); 
    InterlockedAdd64(&write.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Write delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart, 
        write.tops, write.ticks);
#endif
#endif
#ifdef DEBUG_WRITE
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_IsLockRealizable(
    IN OUT PMRX_FCB pFcb,
    IN PLARGE_INTEGER  ByteOffset,
    IN PLARGE_INTEGER  Length,
    IN ULONG  LowIoLockFlags)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_LOCK
    DbgEn();
    DbgP("offset 0x%llx, length 0x%llx, exclusive=%u, blocking=%u\n",
        ByteOffset->QuadPart,Length->QuadPart,
        BooleanFlagOn(LowIoLockFlags, SL_EXCLUSIVE_LOCK),
        !BooleanFlagOn(LowIoLockFlags, SL_FAIL_IMMEDIATELY));
#endif

    /* NFS lock operations with length=0 MUST fail with NFS4ERR_INVAL */
    if (Length->QuadPart == 0)
        status = STATUS_NOT_SUPPORTED;

#ifdef DEBUG_LOCK
    DbgEx();
#endif
    return status;
}

NTSTATUS map_lock_errors(
    DWORD status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_LOCK_FAILED:         return STATUS_LOCK_NOT_GRANTED;
    case ERROR_NOT_LOCKED:          return STATUS_RANGE_NOT_LOCKED;
    case ERROR_ATOMIC_LOCKS_NOT_SUPPORTED: return STATUS_UNSUCCESSFUL;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_SHARING_VIOLATION:   return STATUS_SHARING_VIOLATION;
    case ERROR_FILE_INVALID:        return STATUS_FILE_INVALID;
    /* if we return ERROR_INVALID_PARAMETER, Windows translates that to
     * success!! */
    case ERROR_INVALID_PARAMETER:   return STATUS_LOCK_NOT_GRANTED;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

void print_lock_args(
    PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    const ULONG flags = LowIoContext->ParamsFor.Locks.Flags;
    print_debug_header(RxContext);
    DbgP("offset 0x%llx, length 0x%llx, exclusive=%u, blocking=%u\n",
        LowIoContext->ParamsFor.Locks.ByteOffset,
        LowIoContext->ParamsFor.Locks.Length,
        BooleanFlagOn(flags, SL_EXCLUSIVE_LOCK),
        !BooleanFlagOn(flags, SL_FAIL_IMMEDIATELY));
}


/* use exponential backoff between polls for blocking locks */
#define MSEC_TO_RELATIVE_WAIT   (-10000)
#define MIN_LOCK_POLL_WAIT      (500 * MSEC_TO_RELATIVE_WAIT) /* 500ms */
#define MAX_LOCK_POLL_WAIT      (30000 * MSEC_TO_RELATIVE_WAIT) /* 30s */

void denied_lock_backoff(
    IN OUT PLARGE_INTEGER delay)
{
    if (delay->QuadPart == 0)
        delay->QuadPart = MIN_LOCK_POLL_WAIT;
    else
        delay->QuadPart <<= 1;

    if (delay->QuadPart < MAX_LOCK_POLL_WAIT)
        delay->QuadPart = MAX_LOCK_POLL_WAIT;
}

NTSTATUS nfs41_Lock(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    const ULONG flags = LowIoContext->ParamsFor.Locks.Flags;
    LARGE_INTEGER poll_delay = {0};
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_LOCK
    DbgEn();
    print_lock_args(RxContext);
#endif

/*  RxReleaseFcbResourceForThreadInMRx(RxContext, RxContext->pFcb,
        LowIoContext->ResourceThreadId); */

    status = nfs41_UpcallCreate(NFS41_LOCK, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;
    entry->u.Lock.offset = LowIoContext->ParamsFor.Locks.ByteOffset;
    entry->u.Lock.length = LowIoContext->ParamsFor.Locks.Length;
    entry->u.Lock.exclusive = BooleanFlagOn(flags, SL_EXCLUSIVE_LOCK);
    entry->u.Lock.blocking = !BooleanFlagOn(flags, SL_FAIL_IMMEDIATELY);

retry_upcall:
    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    /* blocking locks keep trying until it succeeds */
    if (entry->status == ERROR_LOCK_FAILED && entry->u.Lock.blocking) {
        denied_lock_backoff(&poll_delay);
        DbgP("returned ERROR_LOCK_FAILED; retrying in %llums\n",
            poll_delay.QuadPart / MSEC_TO_RELATIVE_WAIT);
        KeDelayExecutionThread(KernelMode, FALSE, &poll_delay);
        entry->state = NFS41_WAITING_FOR_UPCALL;
        goto retry_upcall;
    }

    status = map_lock_errors(entry->status);
    RxContext->CurrentIrp->IoStatus.Status = status;

    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&lock.tops); 
    InterlockedAdd64(&lock.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Lock delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart,
        lock.tops, lock.ticks);
#endif
#endif
#ifdef DEBUG_LOCK
    DbgEx();
#endif
    return status;
}

void print_unlock_args(
    PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    print_debug_header(RxContext);
    if (LowIoContext->Operation == LOWIO_OP_UNLOCK_MULTIPLE) {
        PLOWIO_LOCK_LIST lock = LowIoContext->ParamsFor.Locks.LockList;
        DbgP("LOWIO_OP_UNLOCK_MULTIPLE:");
        while (lock) {
            DbgP(" (offset=%llu, length=%llu)", lock->ByteOffset, lock->Length);
            lock = lock->Next;
        }
        DbgP("\n");
    } else {
        DbgP("LOWIO_OP_UNLOCK: offset=%llu, length=%llu\n",
            LowIoContext->ParamsFor.Locks.ByteOffset,
            LowIoContext->ParamsFor.Locks.Length);
    }
}

__inline ULONG unlock_list_count(
    PLOWIO_LOCK_LIST lock)
{
    ULONG count = 0;
    while (lock) {
        count++;
        lock = lock->Next;
    }
    return count;
}

NTSTATUS nfs41_Unlock(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif
#ifdef DEBUG_LOCK
    DbgEn();
    print_lock_args(RxContext);
#endif

/*  RxReleaseFcbResourceForThreadInMRx(RxContext, RxContext->pFcb,
        LowIoContext->ResourceThreadId); */

    status = nfs41_UpcallCreate(NFS41_UNLOCK, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;

    if (LowIoContext->Operation == LOWIO_OP_UNLOCK_MULTIPLE) {
        entry->u.Unlock.count = unlock_list_count(
            LowIoContext->ParamsFor.Locks.LockList);
        RtlCopyMemory(&entry->u.Unlock.locks,
            LowIoContext->ParamsFor.Locks.LockList,
            sizeof(LOWIO_LOCK_LIST));
    } else {
        entry->u.Unlock.count = 1;
        entry->u.Unlock.locks.ByteOffset =
            LowIoContext->ParamsFor.Locks.ByteOffset;
        entry->u.Unlock.locks.Length =
            LowIoContext->ParamsFor.Locks.Length;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_lock_errors(entry->status);
    RxContext->CurrentIrp->IoStatus.Status = status;
    RxFreePool(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&unlock.tops); 
    InterlockedAdd64(&unlock.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Unlock delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart,
        unlock.tops, unlock.ticks);
#endif
#endif
#ifdef DEBUG_LOCK
    DbgEx();
#endif
    return status;
}

NTSTATUS map_symlink_errors(
    NTSTATUS status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_INVALID_REPARSE_DATA: return STATUS_IO_REPARSE_DATA_INVALID;
    case ERROR_NOT_A_REPARSE_POINT: return STATUS_NOT_A_REPARSE_POINT;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INSUFFICIENT_BUFFER: return STATUS_BUFFER_TOO_SMALL;
    case STATUS_BUFFER_TOO_SMALL:
    case ERROR_BUFFER_OVERFLOW:     return STATUS_BUFFER_OVERFLOW;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

void print_reparse_buffer(
    PREPARSE_DATA_BUFFER Reparse)
{
    UNICODE_STRING name;
    DbgP("ReparseTag:           %08X\n", Reparse->ReparseTag);
    DbgP("ReparseDataLength:    %8u\n", Reparse->ReparseDataLength);
    DbgP("Reserved:             %8u\n", Reparse->Reserved);
    DbgP("SubstituteNameOffset: %8u\n", 
         Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset);
    DbgP("SubstituteNameLength: %8u\n", 
         Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength);
    DbgP("PrintNameOffset:      %8u\n", 
         Reparse->SymbolicLinkReparseBuffer.PrintNameOffset);
    DbgP("PrintNameLength:      %8u\n", 
         Reparse->SymbolicLinkReparseBuffer.PrintNameLength);
    DbgP("Flags:                %08X\n", 
         Reparse->SymbolicLinkReparseBuffer.Flags);

    name.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset/sizeof(WCHAR)];
    name.MaximumLength = name.Length =
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength;
    DbgP("SubstituteName:       %wZ\n", &name);

    name.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];
    name.MaximumLength = name.Length =
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength;
    DbgP("PrintName:            %wZ\n", &name);
}

NTSTATUS nfs41_SetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    UNICODE_STRING TargetName;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRoot = 
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry;

#ifdef DEBUG_SYMLINK
    DbgEn();
    print_reparse_buffer(Reparse);
#endif

    if (Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        status = STATUS_IO_REPARSE_TAG_MISMATCH;
        goto out;
    }

    TargetName.MaximumLength = TargetName.Length =
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength;
    TargetName.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];

    status = nfs41_UpcallCreate(NFS41_SYMLINK, &Fobx->sec_ctx, 
        VNetRoot->session, Fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;

    entry->u.Symlink.filename = SrvOpen->pAlreadyPrefixedName;
    entry->u.Symlink.target = &TargetName;
    entry->u.Symlink.set = TRUE;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    status = map_symlink_errors(entry->status);
    RxFreePool(entry);
out:
#ifdef DEBUG_SYMLINK
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_GetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    UNICODE_STRING TargetName;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRoot = 
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry;
    const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
        SymbolicLinkReparseBuffer.PathBuffer);

#ifdef DEBUG_SYMLINK
    DbgEn();
#endif

    if (!BooleanFlagOn(RxContext->pFcb->Attributes,
        FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_NOT_A_REPARSE_POINT;
        DbgP("FILE_ATTRIBUTE_REPARSE_POINT is not set!\n");
        goto out;
    }

    if (FsCtl->OutputBufferLength < HeaderLen) {
        RxContext->InformationToReturn = HeaderLen;
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    TargetName.Buffer = (PWCH)((PBYTE)FsCtl->pOutputBuffer + HeaderLen);
    TargetName.MaximumLength = (USHORT)min(FsCtl->OutputBufferLength - 
        HeaderLen, 0xFFFF);

    status = nfs41_UpcallCreate(NFS41_SYMLINK, &Fobx->sec_ctx, 
        VNetRoot->session, Fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status)
        goto out;

    entry->u.Symlink.filename = SrvOpen->pAlreadyPrefixedName;
    entry->u.Symlink.target = &TargetName;
    entry->u.Symlink.set = FALSE;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_symlink_errors(entry->status);
    if (status == STATUS_SUCCESS) {
        /* fill in the output buffer */
        PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)
            FsCtl->pOutputBuffer;
        Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
        Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
            REPARSE_DATA_BUFFER_HEADER_SIZE;
        Reparse->Reserved = 0;
        Reparse->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
        /* PrintName and SubstituteName point to the same string */
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength = 
            TargetName.Length;
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength = TargetName.Length;
        print_reparse_buffer(Reparse);

        RxContext->IoStatusBlock.Information = HeaderLen + TargetName.Length;
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = HeaderLen + TargetName.Length;
    }
    RxFreePool(entry);
out:
#ifdef DEBUG_SYMLINK
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_FsCtl(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    DbgEn();
    print_debug_header(RxContext);
    switch (RxContext->LowIoContext.ParamsFor.FsCtl.FsControlCode) {
    case FSCTL_SET_REPARSE_POINT:
        status = nfs41_SetReparsePoint(RxContext);
        break;

    case FSCTL_GET_REPARSE_POINT:
        status = nfs41_GetReparsePoint(RxContext);
        break;
    default:
        DbgP("FsControlCode: %d\n", 
             RxContext->LowIoContext.ParamsFor.FsCtl.FsControlCode);
    }
    DbgEx();
    return status;
}

NTSTATUS nfs41_CompleteBufferingStateChangeRequest(
    IN OUT PRX_CONTEXT RxContext,
    IN OUT PMRX_SRV_OPEN SrvOpen,
    IN PVOID pContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_FsdDispatch (
    IN PDEVICE_OBJECT dev,
    IN PIRP Irp)
{
#ifdef DEBUG_FSDDISPATCH
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
#endif
    NTSTATUS status;

#ifdef DEBUG_FSDDISPATCH
    DbgEn();
    DbgP("CURRENT IRP = %d.%d\n", IrpSp->MajorFunction, IrpSp->MinorFunction);
    if(IrpSp->FileObject)
        DbgP("FileOject %p Filename %wZ\n", IrpSp->FileObject, 
                &IrpSp->FileObject->FileName);
#endif

    if (dev != (PDEVICE_OBJECT)nfs41_dev) {
        print_error("*** not ours ***\n");
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT );
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto out;
    }

    status = RxFsdDispatch((PRDBSS_DEVICE_OBJECT)dev,Irp);
    /* AGLO: 08/05/2009 - looks like RxFsdDispatch frees IrpSp */

out:
#ifdef DEBUG_FSDDISPATCH
    DbgP("IoStatus status = 0x%x info = 0x%x\n", Irp->IoStatus.Status, 
         Irp->IoStatus.Information);
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_Unimplemented(
    PRX_CONTEXT RxContext)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS nfs41_AreFilesAliased(
    PFCB a,
    PFCB b)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS nfs41_init_ops()
{
    DbgEn();

    ZeroAndInitializeNodeType(&nfs41_ops, RDBSS_NTC_MINIRDR_DISPATCH, 
        sizeof(MINIRDR_DISPATCH));

    nfs41_ops.MRxFlags = (RDBSS_MANAGE_NET_ROOT_EXTENSION |
                            RDBSS_MANAGE_V_NET_ROOT_EXTENSION |
                            RDBSS_MANAGE_FCB_EXTENSION |
                            RDBSS_MANAGE_FOBX_EXTENSION);

    nfs41_ops.MRxSrvCallSize  = 0; // srvcall extension is not handled in rdbss
    nfs41_ops.MRxNetRootSize  = sizeof(NFS41_NETROOT_EXTENSION);
    nfs41_ops.MRxVNetRootSize = sizeof(NFS41_V_NET_ROOT_EXTENSION);
    nfs41_ops.MRxFcbSize      = sizeof(NFS41_FCB);
    nfs41_ops.MRxFobxSize     = sizeof(NFS41_FOBX);

    // Mini redirector cancel routine ..
    
    nfs41_ops.MRxCancel = NULL;

    //
    // Mini redirector Start/Stop. Each mini-rdr can be started or stopped
    // while the others continue to operate.
    //

    nfs41_ops.MRxStart                = nfs41_Start;
    nfs41_ops.MRxStop                 = nfs41_Stop;
    nfs41_ops.MRxDevFcbXXXControlFile = nfs41_DevFcbXXXControlFile;

    //
    // Mini redirector name resolution.
    //

    nfs41_ops.MRxCreateSrvCall       = nfs41_CreateSrvCall;
    nfs41_ops.MRxSrvCallWinnerNotify = nfs41_SrvCallWinnerNotify;
    nfs41_ops.MRxCreateVNetRoot      = nfs41_CreateVNetRoot;
    nfs41_ops.MRxExtractNetRootName  = nfs41_ExtractNetRootName;
    nfs41_ops.MRxFinalizeSrvCall     = nfs41_FinalizeSrvCall;
    nfs41_ops.MRxFinalizeNetRoot     = nfs41_FinalizeNetRoot;
    nfs41_ops.MRxFinalizeVNetRoot    = nfs41_FinalizeVNetRoot;

    //
    // File System Object Creation/Deletion.
    //

    nfs41_ops.MRxCreate            = nfs41_Create;
    nfs41_ops.MRxCollapseOpen      = nfs41_CollapseOpen;
    nfs41_ops.MRxShouldTryToCollapseThisOpen = nfs41_ShouldTryToCollapseThisOpen;
    nfs41_ops.MRxExtendForCache    = nfs41_ExtendForCache;
    nfs41_ops.MRxExtendForNonCache = nfs41_ExtendForCache;
    nfs41_ops.MRxCloseSrvOpen      = nfs41_CloseSrvOpen;
    nfs41_ops.MRxFlush             = nfs41_Flush;
    nfs41_ops.MRxDeallocateForFcb  = nfs41_DeallocateForFcb;
    nfs41_ops.MRxDeallocateForFobx = nfs41_DeallocateForFobx;
    nfs41_ops.MRxIsLockRealizable    = nfs41_IsLockRealizable;

    //
    // File System Objects query/Set
    //

    nfs41_ops.MRxQueryDirectory       = nfs41_QueryDirectory;
    nfs41_ops.MRxQueryVolumeInfo      = nfs41_QueryVolumeInformation;
    nfs41_ops.MRxQueryEaInfo          = nfs41_QueryEaInformation;
    nfs41_ops.MRxSetEaInfo            = nfs41_SetEaInformation;
    nfs41_ops.MRxQuerySdInfo          = nfs41_QuerySecurityInformation;
    nfs41_ops.MRxSetSdInfo            = nfs41_SetSecurityInformation;
    nfs41_ops.MRxQueryFileInfo        = nfs41_QueryFileInformation;
    nfs41_ops.MRxSetFileInfo          = nfs41_SetFileInformation;

    //
    // Buffering state change
    //

    nfs41_ops.MRxComputeNewBufferingState = nfs41_ComputeNewBufferingState;

    //
    // File System Object I/O
    //

    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_READ]            = nfs41_Read;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_WRITE]           = nfs41_Write;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_SHAREDLOCK]      = nfs41_Lock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_EXCLUSIVELOCK]   = nfs41_Lock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_UNLOCK]          = nfs41_Unlock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_UNLOCK_MULTIPLE] = nfs41_Unlock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_FSCTL]           = nfs41_FsCtl;

    //
    // Miscellanous
    //

    nfs41_ops.MRxCompleteBufferingStateChangeRequest = 
        nfs41_CompleteBufferingStateChangeRequest;
    nfs41_ops.MRxIsValidDirectory     = nfs41_IsValidDirectory;

    nfs41_ops.MRxTruncate = nfs41_Unimplemented;
    nfs41_ops.MRxZeroExtend = nfs41_Unimplemented;
    nfs41_ops.MRxAreFilesAliased = nfs41_AreFilesAliased;
    nfs41_ops.MRxQueryQuotaInfo = nfs41_Unimplemented;
    nfs41_ops.MRxSetQuotaInfo = nfs41_Unimplemented;
    nfs41_ops.MRxSetVolumeInfo = nfs41_Unimplemented;

    DbgR();
    return(STATUS_SUCCESS);
}

#define RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000L))

KSTART_ROUTINE srvopen_main;
VOID srvopen_main(PVOID ctx)
{
    NTSTATUS status;
    LARGE_INTEGER timeout;

    DbgEn();
    timeout.QuadPart = RELATIVE(SECONDS(30));
    while(1) {
        PLIST_ENTRY pEntry;
        nfs41_srvopen_list_entry *cur;
        status = KeDelayExecutionThread(KernelMode, TRUE, &timeout);
        ExAcquireFastMutex(&srvopenLock);
        pEntry = openlist->head.Flink;
        while (!IsListEmpty(&openlist->head)) {
            PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext;
            PNFS41_NETROOT_EXTENSION pNetRootContext;
            nfs41_updowncall_entry *entry;
            FILE_BASIC_INFORMATION binfo;
            PNFS41_FCB nfs41_fcb;
            cur = (nfs41_srvopen_list_entry *)CONTAINING_RECORD(pEntry, 
                    nfs41_srvopen_list_entry, next);

            DbgP("srvopen_main: Checking attributes for srv_open=%p "
                "change_time=%llu skipping=%d\n", cur->srv_open, 
                cur->ChangeTime, cur->skip);
            if (cur->skip) goto out;
            pVNetRootContext = 
                NFS41GetVNetRootExtension(cur->srv_open->pVNetRoot);
            pNetRootContext = 
                NFS41GetNetRootExtension(cur->srv_open->pVNetRoot->pNetRoot);
            /* place an upcall for this srv_open */
            status = nfs41_UpcallCreate(NFS41_FILE_QUERY, 
                &cur->nfs41_fobx->sec_ctx, pVNetRootContext->session, 
                cur->nfs41_fobx->nfs41_open_state,
                pNetRootContext->nfs41d_version, 
                cur->srv_open->pAlreadyPrefixedName, &entry);
            if (status)
                goto out;
            entry->u.QueryFile.InfoClass = FileBasicInformation;
            entry->u.QueryFile.buf = &binfo;
            entry->u.QueryFile.buf_len = sizeof(binfo);

            if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
                status = STATUS_INTERNAL_ERROR;
                goto out;
            }
            if (cur->ChangeTime != entry->u.QueryFile.ChangeTime) {
                ULONG flag = DISABLE_CACHING;
                DbgP("srvopen_main: old ctime=%llu new_ctime=%llu\n", 
                    cur->ChangeTime, entry->u.QueryFile.ChangeTime);
                DbgP("srvopen_main: ************ Invalidate the cache for %wZ "
                     "************\n", cur->srv_open->pAlreadyPrefixedName);
                RxChangeBufferingState((PSRV_OPEN)cur->srv_open, 
                    ULongToPtr(flag), 1);
                cur->ChangeTime = entry->u.QueryFile.ChangeTime;
                cur->skip = TRUE;
            }
            nfs41_fcb = (PNFS41_FCB)cur->srv_open->pFcb->Context;
            nfs41_fcb->changeattr = entry->u.QueryFile.ChangeTime;
            RxFreePool(entry);
out:
            if (pEntry->Flink == &openlist->head) {
                DbgP("srvopen_main: reached end of the list\n");
                break;
            }
            pEntry = pEntry->Flink;
        }
        ExReleaseFastMutex(&srvopenLock);
    }
    DbgEx();
}

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT drv, 
    IN PUNICODE_STRING path)
{
    NTSTATUS status;
    ULONG flags = 0, i;
    UNICODE_STRING dev_name, user_dev_name;
    PNFS41_DEVICE_EXTENSION dev_exts;
    TIME_FIELDS jan_1_1970 = {1970, 1, 1, 0, 0, 0, 0, 0};
    ACCESS_MASK mask = 0;
    OBJECT_ATTRIBUTES oattrs;

    DbgEn();

    status = RxDriverEntry(drv, path);
    if (status != STATUS_SUCCESS) {
        print_error("RxDriverEntry failed: %08lx\n", status);
        goto out;
    }

    RtlInitUnicodeString(&dev_name, NFS41_DEVICE_NAME);
    SetFlag(flags, RX_REGISTERMINI_FLAG_DONT_PROVIDE_MAILSLOTS);

    status = nfs41_init_ops();
    if (status != STATUS_SUCCESS) {
        print_error("nfs41_init_ops failed to initialize dispatch table\n");
        goto out;
    }

    DbgP("calling RxRegisterMinirdr\n");
    status = RxRegisterMinirdr(&nfs41_dev, drv, &nfs41_ops, flags, &dev_name,
                sizeof(NFS41_DEVICE_EXTENSION), 
                FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE);
    if (status != STATUS_SUCCESS) {
        print_error("RxRegisterMinirdr failed: %08lx\n", status);
        goto out;
    }
    nfs41_dev->Flags |= DO_BUFFERED_IO;

    dev_exts = (PNFS41_DEVICE_EXTENSION)
        ((PBYTE)(nfs41_dev) + sizeof(RDBSS_DEVICE_OBJECT));

    RxDefineNode(dev_exts, NFS41_DEVICE_EXTENSION);
    dev_exts->DeviceObject = nfs41_dev;
    nfs41_create_volume_info((PFILE_FS_VOLUME_INFORMATION)dev_exts->VolAttrs, 
        &dev_exts->VolAttrsLen);

    RtlInitUnicodeString(&user_dev_name, NFS41_SHADOW_DEVICE_NAME);
    DbgP("calling IoCreateSymbolicLink %wZ %wZ\n", &user_dev_name, &dev_name);
    status = IoCreateSymbolicLink(&user_dev_name, &dev_name);
    if (status != STATUS_SUCCESS) {
        print_error("Device name IoCreateSymbolicLink failed: %08lx\n", status);
        goto out_unregister;
    }

    KeInitializeEvent(&upcallEvent, SynchronizationEvent, FALSE );
    ExInitializeFastMutex(&upcallLock);
    ExInitializeFastMutex(&downcallLock);
    ExInitializeFastMutex(&xidLock);
    ExInitializeFastMutex(&openOwnerLock);
    ExInitializeFastMutex(&srvopenLock);
    upcall = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_list), 
                NFS41_MM_POOLTAG);
    if (upcall == NULL) 
        goto out_unregister;
    InitializeListHead(&upcall->head);
    downcall = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_list), 
                NFS41_MM_POOLTAG);
    if (downcall == NULL) {
        RxFreePool(upcall);
        goto out_unregister;
    }
    InitializeListHead(&downcall->head);
    openlist = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_srvopen_list), 
                NFS41_MM_POOLTAG);
    if (openlist == NULL) {
        RxFreePool(upcall);
        RxFreePool(downcall);
        goto out_unregister;
    }
    InitializeListHead(&openlist->head);
    InitializeObjectAttributes(&oattrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&dev_exts->openlistHandle, mask, 
        &oattrs, NULL, NULL, &srvopen_main, NULL);
    if (status != STATUS_SUCCESS) {
        RxFreePool(upcall);
        RxFreePool(downcall);
        RxFreePool(openlist);
        goto out;
    }

    drv->DriverUnload = nfs41_driver_unload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv->MajorFunction[i] = (PDRIVER_DISPATCH)nfs41_FsdDispatch;

    RtlTimeFieldsToTime(&jan_1_1970, &unix_time_diff);

out_unregister:
    if (status != STATUS_SUCCESS)
        RxUnregisterMinirdr(nfs41_dev);
out:
    DbgEx();
    return status;
}

VOID nfs41_driver_unload(IN PDRIVER_OBJECT drv)
{
    PRX_CONTEXT RxContext;
    NTSTATUS    status;
    UNICODE_STRING dev_name, pipe_name;

    DbgEn();

    RxContext = RxCreateRxContext(NULL, nfs41_dev, RX_CONTEXT_FLAG_IN_FSP);
    if (RxContext == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto unload;
    }
    status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
    RxDereferenceAndDeleteRxContext(RxContext);

unload:
    RtlInitUnicodeString(&dev_name, NFS41_SHADOW_DEVICE_NAME);
    status = IoDeleteSymbolicLink(&dev_name);
    if (status != STATUS_SUCCESS) {
        print_error("couldn't delete device symbolic link\n");
    }
    RtlInitUnicodeString(&pipe_name, NFS41_SHADOW_PIPE_NAME);
    status = IoDeleteSymbolicLink(&pipe_name);
    if (status != STATUS_SUCCESS) {
        print_error("couldn't delete pipe symbolic link\n");
    }
    if (upcall) 
        RxFreePool(upcall);
    if (downcall)
        RxFreePool(downcall);
    RxUnload(drv);

    DbgP("driver unloaded %p\n", drv);
    DbgR();
}
