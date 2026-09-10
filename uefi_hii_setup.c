#include <efi.h>
#include <efilib.h>

#ifndef START_FORM_ID
#define START_FORM_ID 0x2710
#endif

#ifndef LAUNCHER_NAME
#define LAUNCHER_NAME L"Acer full hidden setup"
#endif

#ifndef USE_NV_UNLOCK
#define USE_NV_UNLOCK 0
#endif

#ifndef PATCH_HIDDEN_UI
#define PATCH_HIDDEN_UI 1
#endif

typedef VOID *EFI_HII_HANDLE;
typedef UINT16 EFI_FORM_ID;
typedef UINTN EFI_BROWSER_ACTION_REQUEST;

typedef struct _EFI_HII_DATABASE_PROTOCOL EFI_HII_DATABASE_PROTOCOL;
typedef struct _EFI_FORM_BROWSER2_PROTOCOL EFI_FORM_BROWSER2_PROTOCOL;

typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_NEW_PACK)(
    const EFI_HII_DATABASE_PROTOCOL *This,
    const VOID *PackageList,
    EFI_HANDLE DriverHandle,
    EFI_HII_HANDLE *Handle);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_REMOVE_PACK)(
    const EFI_HII_DATABASE_PROTOCOL *This,
    EFI_HII_HANDLE Handle);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_LIST_PACKS)(
    const EFI_HII_DATABASE_PROTOCOL *This,
    UINT8 PackageType,
    const EFI_GUID *PackageGuid,
    UINTN *HandleBufferLength,
    EFI_HII_HANDLE *Handle);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_EXPORT_PACKS)(
    const EFI_HII_DATABASE_PROTOCOL *This,
    EFI_HII_HANDLE Handle,
    UINTN *BufferSize,
    VOID *Buffer);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_UPDATE_PACKS)(
    const EFI_HII_DATABASE_PROTOCOL *This,
    EFI_HII_HANDLE Handle,
    const VOID *PackageList);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_GET_PACK_HANDLE)(
    const EFI_HII_DATABASE_PROTOCOL *This,
    EFI_HII_HANDLE PackageListHandle,
    EFI_HANDLE *DriverHandle);

typedef EFI_STATUS(EFIAPI *EFI_SEND_FORM2)(
    const EFI_FORM_BROWSER2_PROTOCOL *This,
    EFI_HII_HANDLE *Handle,
    UINTN HandleCount,
    EFI_GUID *FormSetGuid,
    EFI_FORM_ID FormId,
    const VOID *ScreenDimensions,
    EFI_BROWSER_ACTION_REQUEST *ActionRequest);

/* Only the first five database members are needed, but their positions are ABI. */
struct _EFI_HII_DATABASE_PROTOCOL {
    EFI_HII_DATABASE_NEW_PACK NewPackageList;
    EFI_HII_DATABASE_REMOVE_PACK RemovePackageList;
    EFI_HII_DATABASE_UPDATE_PACKS UpdatePackageList;
    EFI_HII_DATABASE_LIST_PACKS ListPackageLists;
    EFI_HII_DATABASE_EXPORT_PACKS ExportPackageLists;
    VOID *RegisterPackageNotify;
    VOID *UnregisterPackageNotify;
    VOID *FindKeyboardLayouts;
    VOID *GetKeyboardLayout;
    VOID *SetKeyboardLayout;
    EFI_HII_DATABASE_GET_PACK_HANDLE GetPackageListHandle;
};

struct _EFI_FORM_BROWSER2_PROTOCOL {
    EFI_SEND_FORM2 SendForm;
    VOID *BrowserCallback;
};

static EFI_GUID hii_database_guid = {
    0xef9fc172, 0xa1b2, 0x4693,
    {0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42}
};

static EFI_GUID form_browser2_guid = {
    0xb9d4c360, 0xbcfb, 0x4f9b,
    {0x92, 0x98, 0x53, 0xc1, 0x36, 0x98, 0x22, 0x58}
};

static EFI_GUID acer_setup_formset_guid = {
    0x7b59104a, 0xc00d, 0x4158,
    {0x87, 0xff, 0xf0, 0x4d, 0x63, 0x96, 0xa9, 0x15}
};

static EFI_GUID result_guid = {
    0xe9b23f6a, 0x3288, 0x4024,
    {0xa1, 0x77, 0x50, 0xea, 0xe6, 0xfc, 0xc9, 0x0e}
};

#if PATCH_HIDDEN_UI
/* Package-list GUID only; the Acer formset GUID inside IFR stays unchanged. */
static EFI_GUID unlocked_package_list_guid = {
    0x340d8c89, 0x9b6f, 0x4e80,
    {0xa2, 0x73, 0x83, 0x06, 0x2b, 0xb0, 0x90, 0x45}
};
#endif

/* EFI_GUID byte representation inside the IFR FORM_SET opcode. */
static const UINT8 acer_formset_bytes[16] = {
    0x4a, 0x10, 0x59, 0x7b, 0x0d, 0xc0, 0x58, 0x41,
    0x87, 0xff, 0xf0, 0x4d, 0x63, 0x96, 0xa9, 0x15
};

/*
 * These offsets and signatures identify the exact AMITSE image extracted from
 * this machine's Acer R01-B1 firmware.  Refuse to touch any other build.
 */
#define AMITSE_SEND_FORM_RVA          0x1fb9c
#define AMITSE_FALLBACK_CHECK_RVA     0x1fcb5
#define AMITSE_SETUP_SLOT_LOAD_RVA    0x20b1f
#define AMITSE_SETUP_SLOT_CLEAR_RVA   0x20b2f
#define AMITSE_SETUP_DATA_PTR_RVA     0x84d40
#define AMITSE_IMAGE_SIZE             0xaf960
#define AMITSE_SETUP_DATA_SIZE        0xd4efc
#define AMITSE_SETUP_DATA_FNV1A64     0x88bd1d520c37ca11ULL
#define AMITSE_SETUP_DATA_PATH        L"\\EFI\\ida-assist\\AMITSESetupData.bin"

static const UINT8 amitse_send_form_signature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74,
    0x24, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x20, 0x55,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8b, 0xec, 0x48, 0x83, 0xec, 0x50, 0x45
};

/*
 * Opcode prefixes only. Acer's loader may patch each signed RIP displacement
 * when it separates AMITSE code and data at runtime. All three decoded live
 * targets must agree before that slot is accessed.
 */
static const UINT8 amitse_fallback_check_opcode[] = {
    0x4c, 0x39, 0x35 /* cmp [rip+disp32], r14 */
};

static const UINT8 amitse_setup_slot_load_opcode[] = {
    0x48, 0x8b, 0x05 /* mov rax, [rip+disp32] */
};

static const UINT8 amitse_setup_slot_clear_opcode[] = {
    0x48, 0x89, 0x2d /* mov [rip+disp32], rbp */
};

#if USE_NV_UNLOCK
static EFI_GUID nv_lock_mailbox_guid = {
    0x504af431, 0x3025, 0x4d32,
    {0x9f, 0xbf, 0xe9, 0xf3, 0x18, 0x55, 0x55, 0x1d}
};

typedef struct __attribute__((packed)) {
    UINT32 Signature;
    UINT8 Locked;
    UINT8 Terminate;
} NV_LOCK_MAILBOX;

typedef CHAR8 NV_LOCK_MAILBOX_MUST_BE_SIX_BYTES[
    sizeof(NV_LOCK_MAILBOX) == 6 ? 1 : -1];
#endif

typedef struct {
    UINT32 Magic;
    UINT16 Version;
    UINT16 FormId;
    UINT32 HandleCount;
    UINT32 ActionRequest;
    UINT64 LocateDatabaseStatus;
    UINT64 LocateBrowserStatus;
    UINT64 ListStatus;
    UINT64 SendFormStatus;
    UINT64 UnlockStatus;
    UINT64 RelockStatus;
    UINT32 FoundFormset;
    UINT32 MatchingHandleCount;
    UINT64 ExportStatus;
    UINT64 SetupDataLoadStatus;
    UINT64 AmitseValidationStatus;
    UINT64 UiPatchStatus;
    UINT64 UiUpdateStatus;
    UINT64 UiRestoreStatus;
    UINT64 SetupDataHash;
    UINT64 AmitseImageBase;
    UINT64 PreviousSetupDataPointer;
    UINT64 InstalledSetupDataPointer;
    UINT32 StaticSuppressUnlocked;
    UINT32 StaticGrayUnlocked;
    UINT32 StaticDisableUnlocked;
    UINT32 RuntimeValidationMask;
    UINT32 Stage;
    UINT32 CopyVerified;
    UINT64 GetDriverHandleStatus;
    UINT64 NewPackageStatus;
    UINT64 RemovePackageStatus;
    UINT64 OriginalDriverHandle;
    UINT64 BrowserHiiHandle;
    UINT64 FallbackSlotAddress;
    UINT64 SnapshotLoadSlotAddress;
    UINT64 SnapshotClearSlotAddress;
    UINT8 LiveFallbackInstruction[7];
    UINT8 LiveSnapshotLoadInstruction[7];
    UINT8 LiveSnapshotClearInstruction[7];
    UINT8 DiagnosticPadding[3];
} HII_LAUNCH_RESULT;

/*
 * gnu-efi 4.0's SetMem/CopyMem entry points use the Microsoft x64 ABI, while
 * EFI_FUNCTION_WRAPPER builds call ordinary C helpers with the SysV ABI.
 * Keep these tiny helpers local so package bytes cannot be corrupted by that
 * mixed-ABI boundary.
 */
static VOID zero_bytes(VOID *destination, UINTN size)
{
    UINT8 *d = destination;
    for (UINTN i = 0; i < size; ++i)
        d[i] = 0;
}

#if PATCH_HIDDEN_UI
static VOID copy_bytes(VOID *destination, const VOID *source, UINTN size)
{
    UINT8 *d = destination;
    const UINT8 *s = source;
    for (UINTN i = 0; i < size; ++i)
        d[i] = s[i];
}
#endif

static BOOLEAN bytes_equal(const VOID *left, const VOID *right, UINTN size)
{
    const UINT8 *a = left;
    const UINT8 *b = right;
    for (UINTN i = 0; i < size; ++i) {
        if (a[i] != b[i])
            return FALSE;
    }
    return TRUE;
}

static VOID save_result(HII_LAUNCH_RESULT *result)
{
    uefi_call_wrapper(RT->SetVariable, 5,
                      L"AcerFullSetupResult", &result_guid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof(*result), result);
}

static VOID checkpoint(HII_LAUNCH_RESULT *result,
                       UINT32 stage,
                       const CHAR16 *message)
{
    result->Stage = stage;
    save_result(result);
    Print(L"Stage %u: %s\r\n", stage, message);
}

#if USE_NV_UNLOCK
static EFI_STATUS set_nv_lock(UINT8 locked)
{
    NV_LOCK_MAILBOX mailbox;
    mailbox.Signature = 0x24564e41; /* ANV$ */
    mailbox.Locked = locked;
    mailbox.Terminate = 0;
    return uefi_call_wrapper(RT->SetVariable, 5,
                             L"NvLockMailbox", &nv_lock_mailbox_guid,
                             EFI_VARIABLE_BOOTSERVICE_ACCESS,
                             sizeof(mailbox), &mailbox);
}
#endif

static BOOLEAN has_acer_formset(const UINT8 *buffer, UINTN size)
{
    for (UINTN i = 0; i + 18 <= size; ++i) {
        if (buffer[i] != 0x0e || (buffer[i + 1] & 0x7f) < 18)
            continue;
        BOOLEAN match = TRUE;
        for (UINTN j = 0; j < sizeof(acer_formset_bytes); ++j) {
            if (buffer[i + 2 + j] != acer_formset_bytes[j]) {
                match = FALSE;
                break;
            }
        }
        if (match)
            return TRUE;
    }
    return FALSE;
}

static UINT32 read_u32(const UINT8 *p)
{
    return (UINT32)p[0] |
           ((UINT32)p[1] << 8) |
           ((UINT32)p[2] << 16) |
           ((UINT32)p[3] << 24);
}

static UINT8 *decode_rip_relative_target(UINT8 *instruction)
{
    INT32 displacement = (INT32)read_u32(instruction + 3);
    return (UINT8 *)((INTN)(UINTN)(instruction + 7) +
                     (INTN)displacement);
}

static UINT64 fnv1a64(const UINT8 *buffer, UINTN size)
{
    UINT64 hash = 0xcbf29ce484222325ULL;
    for (UINTN i = 0; i < size; ++i) {
        hash ^= buffer[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static EFI_STATUS load_amitse_setup_data(EFI_HANDLE image,
                                         UINT8 **buffer_out,
                                         UINT64 *hash_out)
{
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
    EFI_STATUS status = uefi_call_wrapper(BS->HandleProtocol, 3,
                                          image,
                                          &gEfiLoadedImageProtocolGuid,
                                          (VOID **)&loaded_image);
    if (EFI_ERROR(status))
        return status;

    EFI_FILE_HANDLE root = LibOpenRoot(loaded_image->DeviceHandle);
    if (root == NULL)
        return EFI_NOT_FOUND;

    EFI_FILE_HANDLE file = NULL;
    status = uefi_call_wrapper(root->Open, 5, root, &file,
                               AMITSE_SETUP_DATA_PATH,
                               EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        uefi_call_wrapper(root->Close, 1, root);
        return status;
    }

    UINT8 *buffer = NULL;
    status = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData,
                               AMITSE_SETUP_DATA_SIZE + 1,
                               (VOID **)&buffer);
    if (!EFI_ERROR(status)) {
        UINTN size = AMITSE_SETUP_DATA_SIZE + 1;
        status = uefi_call_wrapper(file->Read, 3, file, &size, buffer);
        if (!EFI_ERROR(status) && size != AMITSE_SETUP_DATA_SIZE)
            status = EFI_BAD_BUFFER_SIZE;
        if (!EFI_ERROR(status) &&
            (read_u32(buffer) != 0x46505324 || /* $SPF */
             read_u32(buffer + 4) != 0x00000200 ||
             read_u32(buffer + 8) != 0x00000210 ||
             read_u32(buffer + 0x44) != AMITSE_SETUP_DATA_SIZE))
            status = EFI_COMPROMISED_DATA;
        if (!EFI_ERROR(status)) {
            *hash_out = fnv1a64(buffer, AMITSE_SETUP_DATA_SIZE);
            if (*hash_out != AMITSE_SETUP_DATA_FNV1A64)
                status = EFI_CRC_ERROR;
        }
    }

    uefi_call_wrapper(file->Close, 1, file);
    uefi_call_wrapper(root->Close, 1, root);
    if (EFI_ERROR(status)) {
        if (buffer != NULL)
            uefi_call_wrapper(BS->FreePool, 1, buffer);
        return status;
    }

    *buffer_out = buffer;
    return EFI_SUCCESS;
}

static EFI_STATUS install_amitse_setup_data(EFI_FORM_BROWSER2_PROTOCOL *browser,
                                            UINT8 *setup_data,
                                            HII_LAUNCH_RESULT *result)
{
    UINTN send_form = (UINTN)browser->SendForm;
    if (send_form < AMITSE_SEND_FORM_RVA)
        return EFI_COMPROMISED_DATA;

    UINT8 *base = (UINT8 *)(send_form - AMITSE_SEND_FORM_RVA);
    result->AmitseImageBase = (UINT64)(UINTN)base;

    /*
     * This AMI loader does not preserve a conventional PE header at the
     * runtime code base, so header-field checks reject the right image. Pin
     * the relative layout instead with the exact callable SendForm entry and
     * three independent RIP-relative instructions. Acer patches their signed
     * displacements when it relocates the data section, so validate the opcode
     * prefixes, decode the live targets, and require all three to agree.
     */
    if (bytes_equal(base + AMITSE_SEND_FORM_RVA,
                    amitse_send_form_signature,
                    sizeof(amitse_send_form_signature)))
        result->RuntimeValidationMask |= 1;
    UINT8 *fallback_instruction = base + AMITSE_FALLBACK_CHECK_RVA;
    UINT8 *snapshot_load_instruction = base + AMITSE_SETUP_SLOT_LOAD_RVA;
    UINT8 *snapshot_clear_instruction = base + AMITSE_SETUP_SLOT_CLEAR_RVA;
    for (UINTN i = 0; i < 7; ++i) {
        result->LiveFallbackInstruction[i] = fallback_instruction[i];
        result->LiveSnapshotLoadInstruction[i] = snapshot_load_instruction[i];
        result->LiveSnapshotClearInstruction[i] = snapshot_clear_instruction[i];
    }

    if (bytes_equal(fallback_instruction,
                    amitse_fallback_check_opcode,
                    sizeof(amitse_fallback_check_opcode)))
        result->RuntimeValidationMask |= 2;
    if (bytes_equal(snapshot_load_instruction,
                    amitse_setup_slot_load_opcode,
                    sizeof(amitse_setup_slot_load_opcode)))
        result->RuntimeValidationMask |= 4;
    if (bytes_equal(snapshot_clear_instruction,
                    amitse_setup_slot_clear_opcode,
                    sizeof(amitse_setup_slot_clear_opcode)))
        result->RuntimeValidationMask |= 8;
    if ((result->RuntimeValidationMask & 15) != 15)
        return EFI_INCOMPATIBLE_VERSION;

    UINT8 *fallback_slot = decode_rip_relative_target(fallback_instruction);
    UINT8 *snapshot_load_slot =
        decode_rip_relative_target(snapshot_load_instruction);
    UINT8 *snapshot_clear_slot =
        decode_rip_relative_target(snapshot_clear_instruction);
    result->FallbackSlotAddress = (UINT64)(UINTN)fallback_slot;
    result->SnapshotLoadSlotAddress = (UINT64)(UINTN)snapshot_load_slot;
    result->SnapshotClearSlotAddress = (UINT64)(UINTN)snapshot_clear_slot;
    if (fallback_slot != snapshot_load_slot ||
        fallback_slot != snapshot_clear_slot ||
        ((UINTN)fallback_slot & 7) != 0)
        return EFI_COMPROMISED_DATA;
    result->RuntimeValidationMask |= 16;

    volatile UINT8 **setup_data_slot = (volatile UINT8 **)fallback_slot;
    UINT8 *old_pointer = (UINT8 *)*setup_data_slot;
    result->PreviousSetupDataPointer = (UINT64)(UINTN)old_pointer;

    /* If AMITSE already initialized itself, its own pointer is preferable. */
    if (old_pointer != NULL) {
        result->InstalledSetupDataPointer = (UINT64)(UINTN)old_pointer;
        return EFI_SUCCESS;
    }

    *setup_data_slot = setup_data;
    if (*setup_data_slot != setup_data)
        return EFI_WRITE_PROTECTED;

    result->InstalledSetupDataPointer = (UINT64)(UINTN)setup_data;
    return EFI_SUCCESS;
}

#if PATCH_HIDDEN_UI
static EFI_STATUS unlock_static_ifr_conditions(UINT8 *package_list,
                                               UINTN buffer_size,
                                               HII_LAUNCH_RESULT *result)
{
    if (buffer_size < 24)
        return EFI_COMPROMISED_DATA;

    UINT32 list_size = read_u32(package_list + 16);
    if (list_size != buffer_size)
        return EFI_BAD_BUFFER_SIZE;

    UINTN package_offset = 20;
    while (package_offset < list_size) {
        if (package_offset + 4 > list_size)
            return EFI_COMPROMISED_DATA;

        UINT32 header = read_u32(package_list + package_offset);
        UINT32 package_size = header & 0x00ffffff;
        UINT8 package_type = (UINT8)(header >> 24);
        if (package_size < 4 || package_offset + package_size > list_size)
            return EFI_COMPROMISED_DATA;

        if (package_type == 0x02) { /* EFI_HII_PACKAGE_FORMS */
            UINTN opcode_offset = package_offset + 4;
            UINTN package_end = package_offset + package_size;
            while (opcode_offset < package_end) {
                if (opcode_offset + 2 > package_end)
                    return EFI_COMPROMISED_DATA;
                UINT8 opcode = package_list[opcode_offset];
                UINT8 header_byte = package_list[opcode_offset + 1];
                UINT8 opcode_size = header_byte & 0x7f;
                if (opcode_size < 2 || opcode_offset + opcode_size > package_end)
                    return EFI_COMPROMISED_DATA;

                UINTN expression = opcode_offset + opcode_size;
                if ((header_byte & 0x80) != 0 && expression + 2 <= package_end &&
                    package_list[expression] == 0x46 && /* EFI_IFR_TRUE_OP */
                    package_list[expression + 1] == 0x02) {
                    if (opcode == 0x0a) /* EFI_IFR_SUPPRESS_IF_OP */
                        result->StaticSuppressUnlocked++;
                    else if (opcode == 0x19) /* EFI_IFR_GRAY_OUT_IF_OP */
                        result->StaticGrayUnlocked++;
                    else if (opcode == 0x1e) /* EFI_IFR_DISABLE_IF_OP */
                        result->StaticDisableUnlocked++;
                    else {
                        opcode_offset += opcode_size;
                        continue;
                    }
                    package_list[expression] = 0x47; /* EFI_IFR_FALSE_OP */
                }
                opcode_offset += opcode_size;
            }
        }
        package_offset += package_size;
    }

    /*
     * These baselines (73 SuppressIf, 37 GrayOutIf, 1 DisableIf; 111 total)
     * are the exact static counts compiled into the R01-B1 Setup driver IFR
     * (research/reversing/Setup-899407D7.bin). The LIVE HII database, however,
     * merges runtime IFR (AMI label / UpdateForm insertions) into the exported
     * package, so the runtime package legitimately contains MORE static
     * SuppressIf{TRUE} blocks than the offline image. On this machine the live
     * export carries 79 SuppressIf{TRUE} (six runtime-added), which made the
     * former exact `!= 73` test reject a perfectly valid firmware with
     * EFI_INCOMPATIBLE_VERSION at stage 5.
     *
     * The formset identity is already pinned upstream (has_acer_formset() plus
     * a single matching handle), and every patched byte is proven to be an
     * exact TRUE->FALSE flip below, so use the compiled-in counts as a lower
     * bound instead of an equality. A clean full walk is still required.
     */
    if (package_offset != list_size ||
        result->StaticSuppressUnlocked < 73 ||
        result->StaticGrayUnlocked < 37 ||
        result->StaticDisableUnlocked < 1)
        return EFI_INCOMPATIBLE_VERSION;

    return EFI_SUCCESS;
}

static EFI_STATUS verify_static_patch_delta(const UINT8 *original,
                                            const UINT8 *patched,
                                            UINTN size,
                                            UINTN expected_differences)
{
    UINTN differences = 0;
    for (UINTN i = 0; i < size; ++i) {
        if (original[i] == patched[i])
            continue;
        if (original[i] != 0x46 || patched[i] != 0x47)
            return EFI_COMPROMISED_DATA;
        differences++;
    }
    /* Delta must equal exactly the number of conditions we counted+flipped. */
    return differences == expected_differences ? EFI_SUCCESS
                                               : EFI_COMPROMISED_DATA;
}
#endif

static VOID wait_for_user_reboot(VOID)
{
    EFI_INPUT_KEY key;
    Print(L"Press ENTER to cold-reboot to the normal Ubuntu boot entry.\r\n");
    Print(L"The launcher will not reboot until you press ENTER.\r\n");
    while (TRUE) {
        EFI_STATUS key_status = uefi_call_wrapper(
            ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &key);
        if (!EFI_ERROR(key_status) && key.UnicodeChar == CHAR_CARRIAGE_RETURN)
            break;
        uefi_call_wrapper(BS->Stall, 1, 100000);
    }
    uefi_call_wrapper(RT->ResetSystem, 4,
                      EfiResetCold, EFI_SUCCESS, 0, NULL);
    while (TRUE)
        uefi_call_wrapper(BS->Stall, 1, 1000000);
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);

    HII_LAUNCH_RESULT result;
    zero_bytes(&result, sizeof(result));
    result.Magic = 0x31494948; /* HII1 */
    result.Version = 9;
    result.FormId = START_FORM_ID;
    result.LocateDatabaseStatus = EFI_NOT_STARTED;
    result.LocateBrowserStatus = EFI_NOT_STARTED;
    result.ListStatus = EFI_NOT_STARTED;
    result.SendFormStatus = EFI_NOT_STARTED;
    result.UnlockStatus = EFI_NOT_STARTED;
    result.RelockStatus = EFI_NOT_STARTED;
    result.ExportStatus = EFI_NOT_STARTED;
    result.SetupDataLoadStatus = EFI_NOT_STARTED;
    result.AmitseValidationStatus = EFI_NOT_STARTED;
    result.UiPatchStatus = EFI_NOT_STARTED;
    result.UiUpdateStatus = EFI_NOT_STARTED;
    result.UiRestoreStatus = EFI_NOT_STARTED;
    result.GetDriverHandleStatus = EFI_NOT_STARTED;
    result.NewPackageStatus = EFI_NOT_STARTED;
    result.RemovePackageStatus = EFI_NOT_STARTED;
    save_result(&result);

    Print(L"%s\r\n", LAUNCHER_NAME);
    Print(L"Opening Acer Setup formset 7B59104A-C00D-4158-87FF-F04D6396A915, "
          L"form 0x%x\r\n", START_FORM_ID);
    checkpoint(&result, 1, L"locating HII database and form browser");

    EFI_HII_DATABASE_PROTOCOL *database = NULL;
    EFI_FORM_BROWSER2_PROTOCOL *browser = NULL;
    EFI_STATUS status = uefi_call_wrapper(BS->LocateProtocol, 3,
                                          &hii_database_guid, NULL,
                                          (VOID **)&database);
    result.LocateDatabaseStatus = status;
    if (EFI_ERROR(status)) {
        save_result(&result);
        Print(L"HII database protocol unavailable: %r\r\n", status);
        goto user_reboot;
    }
    checkpoint(&result, 2, L"HII database located; locating form browser");

    status = uefi_call_wrapper(BS->LocateProtocol, 3,
                               &form_browser2_guid, NULL,
                               (VOID **)&browser);
    result.LocateBrowserStatus = status;
    if (EFI_ERROR(status)) {
        save_result(&result);
        Print(L"Form Browser2 protocol unavailable: %r\r\n", status);
        goto user_reboot;
    }
    checkpoint(&result, 3, L"form browser located; enumerating HII handles");

    UINTN handles_size = 0;
    status = uefi_call_wrapper(database->ListPackageLists, 5,
                               database, 0x02, NULL,
                               &handles_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL ||
        handles_size == 0 ||
        handles_size % sizeof(EFI_HII_HANDLE) != 0) {
        result.ListStatus = status;
        save_result(&result);
        Print(L"HII forms handle query failed: %r, size=0x%lx\r\n",
              status, handles_size);
        if (status == EFI_SUCCESS)
            status = EFI_COMPROMISED_DATA;
        goto user_reboot;
    }

    EFI_HII_HANDLE *handles = NULL;
    status = uefi_call_wrapper(BS->AllocatePool, 3,
                               EfiLoaderData, handles_size,
                               (VOID **)&handles);
    if (EFI_ERROR(status)) {
        result.ListStatus = status;
        save_result(&result);
        goto user_reboot;
    }

    status = uefi_call_wrapper(database->ListPackageLists, 5,
                               database, 0x02, NULL,
                               &handles_size, handles);
    result.ListStatus = status;
    result.HandleCount = (UINT32)(handles_size / sizeof(EFI_HII_HANDLE));
    if (EFI_ERROR(status) || result.HandleCount == 0) {
        save_result(&result);
        Print(L"HII forms handle enumeration failed: %r\r\n", status);
        if (!EFI_ERROR(status))
            status = EFI_NOT_FOUND;
        goto user_reboot;
    }
    checkpoint(&result, 4, L"HII handles enumerated; selecting Acer formset");

    /*
     * AMI rejects SendForm when unrelated package-list handles are supplied.
     * Export each list and pass only the one containing Acer's Setup formset.
     */
    EFI_HII_HANDLE setup_hii_handle = NULL;
#if PATCH_HIDDEN_UI
    UINT8 *setup_package = NULL;
    UINTN setup_package_size = 0;
#endif
    EFI_BROWSER_ACTION_REQUEST action = 0;
    for (UINTN h = 0; h < result.HandleCount; ++h) {
        UINTN package_size = 0;
        status = uefi_call_wrapper(database->ExportPackageLists, 4,
                                   database, handles[h],
                                   &package_size, NULL);
        if ((status != EFI_BUFFER_TOO_SMALL &&
             status != EFI_OUT_OF_RESOURCES) || package_size == 0)
            continue;

        UINT8 *package = NULL;
        status = uefi_call_wrapper(BS->AllocatePool, 3,
                                   EfiLoaderData, package_size,
                                   (VOID **)&package);
        if (EFI_ERROR(status))
            continue;
        status = uefi_call_wrapper(database->ExportPackageLists, 4,
                                   database, handles[h],
                                   &package_size, package);
        result.ExportStatus = status;
        if (!EFI_ERROR(status) && has_acer_formset(package, package_size)) {
            setup_hii_handle = handles[h];
            result.FoundFormset = 1;
            result.MatchingHandleCount++;
#if PATCH_HIDDEN_UI
            if (setup_package == NULL) {
                setup_package = package;
                setup_package_size = package_size;
                package = NULL;
            }
#endif
        }
        if (package != NULL)
            uefi_call_wrapper(BS->FreePool, 1, package);
    }

    if (setup_hii_handle == NULL || result.MatchingHandleCount != 1) {
        save_result(&result);
        Print(L"Acer Setup HII handle selection failed: matches=%u export=%r\r\n",
              result.MatchingHandleCount, result.ExportStatus);
        status = setup_hii_handle == NULL ? EFI_NOT_FOUND : EFI_COMPROMISED_DATA;
        goto user_reboot;
    }
    checkpoint(&result, 5, L"unique Acer Setup package exported");

    EFI_HII_HANDLE browser_hii_handle = setup_hii_handle;
#if PATCH_HIDDEN_UI
    EFI_HII_HANDLE duplicate_hii_handle = NULL;
    EFI_HANDLE setup_driver_handle = NULL;
    UINT8 *patched_package = NULL;
#endif

#if PATCH_HIDDEN_UI
    status = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData,
                               setup_package_size,
                               (VOID **)&patched_package);
    if (EFI_ERROR(status)) {
        result.UiPatchStatus = status;
        goto user_reboot;
    }
    copy_bytes(patched_package, setup_package, setup_package_size);
    if (!bytes_equal(patched_package, setup_package, setup_package_size)) {
        result.UiPatchStatus = EFI_COMPROMISED_DATA;
        status = result.UiPatchStatus;
        Print(L"Local package copy self-check failed; refusing registration.\r\n");
        goto user_reboot;
    }
    result.CopyVerified = 1;
    result.UiPatchStatus = unlock_static_ifr_conditions(
        patched_package, setup_package_size, &result);
    if (!EFI_ERROR(result.UiPatchStatus))
        result.UiPatchStatus = verify_static_patch_delta(
            setup_package, patched_package, setup_package_size,
            (UINTN)result.StaticSuppressUnlocked +
            (UINTN)result.StaticGrayUnlocked +
            (UINTN)result.StaticDisableUnlocked);
    if (EFI_ERROR(result.UiPatchStatus)) {
        Print(L"Static hidden-option patch rejected this firmware: %r\r\n",
              result.UiPatchStatus);
        status = result.UiPatchStatus;
        goto user_reboot;
    }
    result.CopyVerified = 2;
    checkpoint(&result, 6,
               L"unlocked package copy passed exact 111-byte delta check");
#else
    result.CopyVerified = 1;
    result.UiPatchStatus = EFI_SUCCESS;
    result.UiUpdateStatus = EFI_SUCCESS;
    result.UiRestoreStatus = EFI_SUCCESS;
    checkpoint(&result, 6,
               L"using Acer's untouched HII package for direct-form test");
#endif

    UINT8 *setup_data = NULL;
    checkpoint(&result, 7, L"loading hash-pinned AMITSE Setup data");
    result.SetupDataLoadStatus = load_amitse_setup_data(
        image, &setup_data, &result.SetupDataHash);
    if (EFI_ERROR(result.SetupDataLoadStatus)) {
        Print(L"AMITSE Setup-data fallback load failed: %r\r\n",
              result.SetupDataLoadStatus);
        status = result.SetupDataLoadStatus;
        goto user_reboot;
    }
    checkpoint(&result, 8, L"AMITSE Setup data loaded and hash verified");

    checkpoint(&result, 9, L"validating exact AMITSE image and data slot");
    result.AmitseValidationStatus = install_amitse_setup_data(
        browser, setup_data, &result);
    if (EFI_ERROR(result.AmitseValidationStatus)) {
        Print(L"AMITSE runtime identity check/fallback install failed: %r\r\n",
              result.AmitseValidationStatus);
        status = result.AmitseValidationStatus;
        goto user_reboot;
    }
    checkpoint(&result, 10, L"AMITSE data slot installed and verified");

#if PATCH_HIDDEN_UI
    checkpoint(&result, 11, L"resolving Acer Setup driver handle");
    result.GetDriverHandleStatus = uefi_call_wrapper(
        database->GetPackageListHandle, 3,
        database, setup_hii_handle, &setup_driver_handle);
    if (EFI_ERROR(result.GetDriverHandleStatus) || setup_driver_handle == NULL) {
        status = EFI_ERROR(result.GetDriverHandleStatus)
                     ? result.GetDriverHandleStatus : EFI_NOT_FOUND;
        Print(L"Acer Setup driver-handle lookup failed: %r\r\n", status);
        goto user_reboot;
    }
    result.OriginalDriverHandle = (UINT64)(UINTN)setup_driver_handle;

    /* Give the duplicate a unique package-list GUID, not a new formset GUID. */
    copy_bytes(patched_package, &unlocked_package_list_guid,
               sizeof(unlocked_package_list_guid));
    checkpoint(&result, 12,
               L"registering isolated unlocked HII package copy");
    result.NewPackageStatus = uefi_call_wrapper(
        database->NewPackageList, 4,
        database, patched_package, setup_driver_handle,
        &duplicate_hii_handle);
    result.UiUpdateStatus = result.NewPackageStatus;
    if (EFI_ERROR(result.NewPackageStatus) || duplicate_hii_handle == NULL) {
        status = EFI_ERROR(result.NewPackageStatus)
                     ? result.NewPackageStatus : EFI_NOT_FOUND;
        Print(L"Unlocked HII package registration failed: %r\r\n", status);
        goto user_reboot;
    }
    browser_hii_handle = duplicate_hii_handle;
    result.BrowserHiiHandle = (UINT64)(UINTN)browser_hii_handle;
    checkpoint(&result, 13, L"isolated unlocked HII package registered");
#else
    result.GetDriverHandleStatus = EFI_SUCCESS;
    result.NewPackageStatus = EFI_SUCCESS;
    result.RemovePackageStatus = EFI_SUCCESS;
    result.BrowserHiiHandle = (UINT64)(UINTN)browser_hii_handle;
    checkpoint(&result, 13, L"original Acer HII handle selected");
#endif

    Print(L"Found %u HII form handles and the exact Acer Setup handle.\r\n",
          result.HandleCount);
#if PATCH_HIDDEN_UI
    Print(L"Unlocked %u static hidden, %u grayed, and %u disabled UI blocks.\r\n",
          result.StaticSuppressUnlocked,
          result.StaticGrayUnlocked,
          result.StaticDisableUnlocked);
#else
    Print(L"Direct-form mode: the live Acer HII package was not modified.\r\n");
#endif
    Print(L"Installed verified AMITSE Setup-data fallback at 0x%lx.\r\n",
          result.InstalledSetupDataPointer);
#if USE_NV_UNLOCK
    checkpoint(&result, 14, L"unlocking AMI setup-variable mailbox");
    result.UnlockStatus = set_nv_lock(0);
    if (EFI_ERROR(result.UnlockStatus)) {
        save_result(&result);
        Print(L"AMI NvLockMailbox unlock failed: %r\r\n",
              result.UnlockStatus);
        status = result.UnlockStatus;
        goto remove_duplicate;
    }
    Print(L"AMI setup-variable mailbox unlocked for this browser session.\r\n");
#endif
    checkpoint(&result, 15, L"entering AMI form browser");
    status = uefi_call_wrapper(browser->SendForm, 8,
                               browser, &browser_hii_handle, 1,
                               &acer_setup_formset_guid, START_FORM_ID,
                               NULL, &action);
    result.SendFormStatus = status;
    result.ActionRequest = (UINT32)action;
    checkpoint(&result, 16, L"AMI form browser returned");

#if USE_NV_UNLOCK
remove_duplicate:
#endif
#if PATCH_HIDDEN_UI
    if (duplicate_hii_handle != NULL) {
        checkpoint(&result, 17, L"removing isolated unlocked HII package");
        result.RemovePackageStatus = uefi_call_wrapper(
            database->RemovePackageList, 2,
            database, duplicate_hii_handle);
        result.UiRestoreStatus = result.RemovePackageStatus;
    }
#endif
#if USE_NV_UNLOCK
    if (result.UnlockStatus == EFI_SUCCESS) {
        checkpoint(&result, 18, L"relocking AMI setup-variable mailbox");
        result.RelockStatus = set_nv_lock(1);
    }
#endif
    result.Stage = 19;
    save_result(&result);

    Print(L"Form browser returned: status=%r action=%u\r\n", status, action);
#if PATCH_HIDDEN_UI
    Print(L"Isolated unlocked HII package removal: %r\r\n",
          result.RemovePackageStatus);
#endif
#if USE_NV_UNLOCK
    Print(L"AMI setup-variable mailbox relock: %r\r\n",
          result.RelockStatus);
    if (EFI_ERROR(result.RelockStatus)) {
        Print(L"WARNING: mailbox relock failed. Press ENTER below to reset.\r\n");
    }
#endif
    if (!EFI_ERROR(status) && action == 1) {
        Print(L"The browser requested reset. It will wait for your ENTER key.\r\n");
    }

user_reboot:
    save_result(&result);
    wait_for_user_reboot();
    return status;
}
