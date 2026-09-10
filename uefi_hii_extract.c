#include <efi.h>
#include <efilib.h>

typedef VOID *EFI_HII_HANDLE;

typedef struct _EFI_HII_DATABASE_PROTOCOL EFI_HII_DATABASE_PROTOCOL;
typedef struct _EFI_HII_CONFIG_ACCESS_PROTOCOL EFI_HII_CONFIG_ACCESS_PROTOCOL;

typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_LIST_PACKS)(
    const EFI_HII_DATABASE_PROTOCOL *, UINT8, const EFI_GUID *,
    UINTN *, EFI_HII_HANDLE *);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_EXPORT_PACKS)(
    const EFI_HII_DATABASE_PROTOCOL *, EFI_HII_HANDLE,
    UINTN *, VOID *);
typedef EFI_STATUS(EFIAPI *EFI_HII_DATABASE_GET_PACK_HANDLE)(
    const EFI_HII_DATABASE_PROTOCOL *, EFI_HII_HANDLE, EFI_HANDLE *);
typedef EFI_STATUS(EFIAPI *EFI_HII_ACCESS_EXTRACT_CONFIG)(
    const EFI_HII_CONFIG_ACCESS_PROTOCOL *, const CHAR16 *,
    CHAR16 **, CHAR16 **);

struct _EFI_HII_DATABASE_PROTOCOL {
    VOID *NewPackageList;
    VOID *RemovePackageList;
    VOID *UpdatePackageList;
    EFI_HII_DATABASE_LIST_PACKS ListPackageLists;
    EFI_HII_DATABASE_EXPORT_PACKS ExportPackageLists;
    VOID *RegisterPackageNotify;
    VOID *UnregisterPackageNotify;
    VOID *FindKeyboardLayouts;
    VOID *GetKeyboardLayout;
    VOID *SetKeyboardLayout;
    EFI_HII_DATABASE_GET_PACK_HANDLE GetPackageListHandle;
};

struct _EFI_HII_CONFIG_ACCESS_PROTOCOL {
    EFI_HII_ACCESS_EXTRACT_CONFIG ExtractConfig;
    VOID *RouteConfig;
    VOID *Callback;
};

static EFI_GUID hii_database_guid = {
    0xef9fc172, 0xa1b2, 0x4693,
    {0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42}
};

static EFI_GUID config_access_guid = {
    0x330d4706, 0xf2a0, 0x4e4f,
    {0xa3, 0x69, 0xb6, 0x6f, 0xa8, 0xd5, 0x43, 0x85}
};

static EFI_GUID result_guid = {
    0x7d34b513, 0x0824, 0x491f,
    {0x9e, 0xe3, 0xe3, 0xe4, 0x55, 0x44, 0xb2, 0x46}
};

/* EFI_GUID byte representation within the IFR FORM_SET opcode. */
static const UINT8 acer_formset_bytes[16] = {
    0x4a, 0x10, 0x59, 0x7b, 0x0d, 0xc0, 0x58, 0x41,
    0x87, 0xff, 0xf0, 0x4d, 0x63, 0x96, 0xa9, 0x15
};

enum { TEXT_CAPACITY = 2048 };

typedef struct {
    UINT32 Magic;
    UINT16 Version;
    UINT16 FoundFormset;
    UINT32 FormHandleCount;
    UINT32 CopiedCharacters;
    UINT64 LocateDatabaseStatus;
    UINT64 ListStatus;
    UINT64 ExportStatus;
    UINT64 GetDriverHandleStatus;
    UINT64 GetConfigAccessStatus;
    UINT64 ExtractStatus;
    CHAR16 Text[TEXT_CAPACITY];
} HII_EXTRACT_RESULT;

static VOID save_result(HII_EXTRACT_RESULT *result)
{
    uefi_call_wrapper(RT->SetVariable, 5,
                      L"AcerHiiExtractResult", &result_guid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof(*result), result);
}

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

static VOID zero_bytes(VOID *destination, UINTN size)
{
    UINT8 *d = destination;
    for (UINTN i = 0; i < size; ++i)
        d[i] = 0;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);

    HII_EXTRACT_RESULT *result = NULL;
    EFI_STATUS status = uefi_call_wrapper(BS->AllocatePool, 3,
                                          EfiLoaderData, sizeof(*result),
                                          (VOID **)&result);
    if (EFI_ERROR(status))
        return status;
    zero_bytes(result, sizeof(*result));
    result->Magic = 0x31584948; /* HIX1 */
    result->Version = 1;
    result->LocateDatabaseStatus = EFI_NOT_STARTED;
    result->ListStatus = EFI_NOT_STARTED;
    result->ExportStatus = EFI_NOT_STARTED;
    result->GetDriverHandleStatus = EFI_NOT_STARTED;
    result->GetConfigAccessStatus = EFI_NOT_STARTED;
    result->ExtractStatus = EFI_NOT_STARTED;
    save_result(result);

    Print(L"Acer Setup HII ConfigAccess extractor\r\n");

    EFI_HII_DATABASE_PROTOCOL *database = NULL;
    status = uefi_call_wrapper(BS->LocateProtocol, 3,
                               &hii_database_guid, NULL,
                               (VOID **)&database);
    result->LocateDatabaseStatus = status;
    if (EFI_ERROR(status)) {
        save_result(result);
        return status;
    }

    UINTN handles_size = 0;
    status = uefi_call_wrapper(database->ListPackageLists, 5,
                               database, 0x02, NULL,
                               &handles_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || handles_size == 0) {
        result->ListStatus = status;
        save_result(result);
        return status;
    }

    EFI_HII_HANDLE *handles = NULL;
    status = uefi_call_wrapper(BS->AllocatePool, 3,
                               EfiLoaderData, handles_size,
                               (VOID **)&handles);
    if (EFI_ERROR(status))
        return status;
    status = uefi_call_wrapper(database->ListPackageLists, 5,
                               database, 0x02, NULL,
                               &handles_size, handles);
    result->ListStatus = status;
    result->FormHandleCount = (UINT32)(handles_size / sizeof(*handles));
    if (EFI_ERROR(status)) {
        save_result(result);
        return status;
    }

    EFI_HII_HANDLE setup_hii_handle = NULL;
    for (UINTN h = 0; h < result->FormHandleCount; ++h) {
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
        result->ExportStatus = status;
        if (!EFI_ERROR(status) && has_acer_formset(package, package_size)) {
            setup_hii_handle = handles[h];
            result->FoundFormset = 1;
            break;
        }
    }

    if (setup_hii_handle == NULL) {
        save_result(result);
        Print(L"Acer Setup formset HII handle not found\r\n");
        return EFI_NOT_FOUND;
    }

    EFI_HANDLE driver_handle = NULL;
    status = uefi_call_wrapper(database->GetPackageListHandle, 3,
                               database, setup_hii_handle, &driver_handle);
    result->GetDriverHandleStatus = status;
    if (EFI_ERROR(status)) {
        save_result(result);
        return status;
    }

    EFI_HII_CONFIG_ACCESS_PROTOCOL *access = NULL;
    status = uefi_call_wrapper(BS->HandleProtocol, 3,
                               driver_handle, &config_access_guid,
                               (VOID **)&access);
    result->GetConfigAccessStatus = status;
    if (EFI_ERROR(status)) {
        save_result(result);
        Print(L"Setup driver has no ConfigAccess protocol: %r\r\n", status);
        return status;
    }

    CHAR16 *progress = NULL;
    CHAR16 *text = NULL;
    status = uefi_call_wrapper(access->ExtractConfig, 4,
                               access, NULL, &progress, &text);
    result->ExtractStatus = status;
    if (text != NULL) {
        UINTN i;
        for (i = 0; i + 1 < TEXT_CAPACITY && text[i] != 0; ++i)
            result->Text[i] = text[i];
        result->Text[i] = 0;
        result->CopiedCharacters = (UINT32)i;
    }
    save_result(result);

    Print(L"ExtractConfig(NULL): %r, copied %u characters\r\n",
          status, result->CopiedCharacters);
    uefi_call_wrapper(BS->Stall, 1, 2000000);
    return status;
}
