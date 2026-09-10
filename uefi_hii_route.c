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
typedef EFI_STATUS(EFIAPI *EFI_HII_ACCESS_ROUTE_CONFIG)(
    const EFI_HII_CONFIG_ACCESS_PROTOCOL *, const CHAR16 *, CHAR16 **);

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
    EFI_HII_ACCESS_ROUTE_CONFIG RouteConfig;
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

static EFI_GUID sasetup_guid = {
    0x72c5e28c, 0x7783, 0x43a1,
    {0x87, 0x67, 0xfa, 0xd7, 0x3f, 0xcc, 0xaf, 0xa4}
};

static EFI_GUID result_guid = {
    0xf7f09867, 0xa2de, 0x40e7,
    {0x87, 0x9a, 0x86, 0x10, 0xdd, 0x53, 0x0f, 0xa9}
};

/* EFI_GUID byte representation within the IFR FORM_SET opcode. */
static const UINT8 acer_formset_bytes[16] = {
    0x4a, 0x10, 0x59, 0x7b, 0x0d, 0xc0, 0x58, 0x41,
    0x87, 0xff, 0xf0, 0x4d, 0x63, 0x96, 0xa9, 0x15
};

/*
 * This header was returned by Acer's live Setup ConfigAccess protocol.
 * Only GUID and NAME differ from the returned Setup-varstore header; the
 * PATH identifies the same driver/formset handle.
 */
static const CHAR16 sasetup_ebh_request[] =
    L"GUID=8ce2c5728377a1438767fad73fccafa4"
    L"&NAME=0053006100530065007400750070"
    L"&PATH=0407140067f3605c05a59a41859e2a4ff6ca6fe5"
    L"04061400d7079489fe99d8439a2179ec328cac21"
    L"040314004a10597b0dc0584187fff04d6396a915"
    L"7fff0400"
    L"&OFFSET=404&WIDTH=1";

enum { TEXT_CAPACITY = 512, EBH_OFFSET = 0x404 };

typedef struct {
    UINT32 Magic;
    UINT16 Version;
    UINT8 RouteAttempted;
    UINT8 FoundFormset;
    UINT32 FormHandleCount;
    UINT32 ResponseCharacters;
    UINT64 LocateDatabaseStatus;
    UINT64 ListStatus;
    UINT64 ExportStatus;
    UINT64 GetDriverHandleStatus;
    UINT64 GetConfigAccessStatus;
    UINT64 GetVariableBeforeStatus;
    UINT64 ExtractStatus;
    UINT64 RouteStatus;
    UINT64 GetVariableAfterStatus;
    UINT64 ProgressOffset;
    UINT64 BeforeSize;
    UINT64 AfterSize;
    UINT32 BeforeAttributes;
    UINT32 AfterAttributes;
    UINT8 BeforeEbh;
    UINT8 ExtractedEbh;
    UINT8 AfterEbh;
    UINT8 Reserved;
    CHAR16 Response[TEXT_CAPACITY];
} HII_ROUTE_RESULT;

static VOID save_result(HII_ROUTE_RESULT *result)
{
    uefi_call_wrapper(RT->SetVariable, 5,
                      L"AcerHiiRouteResult", &result_guid,
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

static UINT8 hex_nibble(CHAR16 c)
{
    if (c >= L'0' && c <= L'9')
        return (UINT8)(c - L'0');
    if (c >= L'a' && c <= L'f')
        return (UINT8)(c - L'a' + 10);
    if (c >= L'A' && c <= L'F')
        return (UINT8)(c - L'A' + 10);
    return 0xff;
}

static CHAR16 *find_text(CHAR16 *haystack, const CHAR16 *needle)
{
    if (*needle == 0)
        return haystack;
    for (; *haystack != 0; ++haystack) {
        UINTN i = 0;
        while (needle[i] != 0 && haystack[i] == needle[i])
            ++i;
        if (needle[i] == 0)
            return haystack;
    }
    return NULL;
}

static EFI_STATUS read_sasetup(UINT8 **data, UINTN *size, UINT32 *attributes)
{
    *data = NULL;
    *size = 0;
    EFI_STATUS status = uefi_call_wrapper(RT->GetVariable, 5,
                                          L"SaSetup", &sasetup_guid,
                                          attributes, size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || *size <= EBH_OFFSET)
        return status;
    status = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, *size,
                               (VOID **)data);
    if (EFI_ERROR(status))
        return status;
    return uefi_call_wrapper(RT->GetVariable, 5,
                             L"SaSetup", &sasetup_guid,
                             attributes, size, *data);
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

    HII_ROUTE_RESULT *result = NULL;
    EFI_STATUS status = uefi_call_wrapper(BS->AllocatePool, 3,
                                          EfiLoaderData, sizeof(*result),
                                          (VOID **)&result);
    if (EFI_ERROR(status))
        return status;
    zero_bytes(result, sizeof(*result));
    result->Magic = 0x31524948; /* HIR1 */
    result->Version = 1;
    result->LocateDatabaseStatus = EFI_NOT_STARTED;
    result->ListStatus = EFI_NOT_STARTED;
    result->ExportStatus = EFI_NOT_STARTED;
    result->GetDriverHandleStatus = EFI_NOT_STARTED;
    result->GetConfigAccessStatus = EFI_NOT_STARTED;
    result->GetVariableBeforeStatus = EFI_NOT_STARTED;
    result->ExtractStatus = EFI_NOT_STARTED;
    result->RouteStatus = EFI_NOT_STARTED;
    result->GetVariableAfterStatus = EFI_NOT_STARTED;
    save_result(result);

    Print(L"Acer SaSetup HII safe route test\r\n");

    UINT8 *before = NULL;
    UINTN before_size = 0;
    result->GetVariableBeforeStatus = read_sasetup(
        &before, &before_size, &result->BeforeAttributes);
    result->BeforeSize = before_size;
    if (!EFI_ERROR(result->GetVariableBeforeStatus) &&
        before_size > EBH_OFFSET)
        result->BeforeEbh = before[EBH_OFFSET];

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
        return status;
    }

    CHAR16 *progress = NULL;
    CHAR16 *response = NULL;
    status = uefi_call_wrapper(access->ExtractConfig, 4, access,
                               sasetup_ebh_request, &progress, &response);
    result->ExtractStatus = status;
    if (response != NULL) {
        UINTN i;
        for (i = 0; i + 1 < TEXT_CAPACITY && response[i] != 0; ++i)
            result->Response[i] = response[i];
        result->Response[i] = 0;
        result->ResponseCharacters = (UINT32)i;
        CHAR16 *value = find_text(response, L"&VALUE=");
        if (value != NULL) {
            UINT8 high = hex_nibble(value[7]);
            UINT8 low = hex_nibble(value[8]);
            if (high != 0xff && low != 0xff)
                result->ExtractedEbh = (UINT8)((high << 4) | low);
        }
    }
    if (progress != NULL)
        result->ProgressOffset = (UINT64)(progress - sasetup_ebh_request);

    /* Route only the exact response returned by ExtractConfig: no value edit. */
    if (!EFI_ERROR(status) && response != NULL &&
        !EFI_ERROR(result->GetVariableBeforeStatus) &&
        result->BeforeEbh == result->ExtractedEbh) {
        progress = NULL;
        result->RouteAttempted = 1;
        result->RouteStatus = uefi_call_wrapper(access->RouteConfig, 3,
                                                access, response, &progress);
        if (progress != NULL)
            result->ProgressOffset = (UINT64)(progress - response);
    }

    UINT8 *after = NULL;
    UINTN after_size = 0;
    result->GetVariableAfterStatus = read_sasetup(
        &after, &after_size, &result->AfterAttributes);
    result->AfterSize = after_size;
    if (!EFI_ERROR(result->GetVariableAfterStatus) &&
        after_size > EBH_OFFSET)
        result->AfterEbh = after[EBH_OFFSET];
    save_result(result);

    Print(L"Extract: %r; identical RouteConfig: %r; EBH %u -> %u\r\n",
          result->ExtractStatus, result->RouteStatus,
          result->BeforeEbh, result->AfterEbh);
    uefi_call_wrapper(BS->Stall, 1, 2500000);
    return EFI_SUCCESS;
}
