#include <efi.h>
#include <efilib.h>

#ifndef TARGET_EBH
#define TARGET_EBH 1
#endif

#ifndef RESET_ON_SUCCESS
#define RESET_ON_SUCCESS 0
#endif

#if TARGET_EBH != 0 && TARGET_EBH != 1
#error TARGET_EBH must be zero or one
#endif

enum {
    SA_SETUP_SIZE = 0x578,
    EBH_OFFSET = 0x404,
};

static EFI_GUID sa_setup_guid = {
    0x72c5e28c, 0x7783, 0x43a1,
    {0x87, 0x67, 0xfa, 0xd7, 0x3f, 0xcc, 0xaf, 0xa4}
};

/* Private result variable, readable from Linux after the app returns/resets. */
static EFI_GUID result_guid = {
    0x3c744b90, 0x60ee, 0x4d74,
    {0xa2, 0x1e, 0xf4, 0x42, 0x31, 0xe4, 0x73, 0x19}
};

typedef struct {
    UINT32 Magic;             /* "EBH1" in little endian */
    UINT16 Version;
    UINT8 Target;
    UINT8 ResetRequested;
    UINT8 OldValue;
    UINT8 VerifiedValue;
    UINT16 Reserved;
    UINT32 Attributes;
    UINT64 DataSize;
    UINT64 InitialGetStatus;
    UINT64 SetStatus;
    UINT64 VerifyStatus;
} EBH_RESULT;

static VOID set_result(EBH_RESULT *result)
{
    uefi_call_wrapper(RT->SetVariable, 5,
                      L"EbhProbeResult", &result_guid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof(*result), result);
}

static BOOLEAN same_bytes(const UINT8 *a, const UINT8 *b, UINTN size)
{
    for (UINTN i = 0; i < size; ++i) {
        if (a[i] != b[i])
            return FALSE;
    }
    return TRUE;
}

static VOID zero_bytes(VOID *destination, UINTN size)
{
    UINT8 *d = destination;
    for (UINTN i = 0; i < size; ++i)
        d[i] = 0;
}

static VOID copy_bytes(VOID *destination, const VOID *source, UINTN size)
{
    UINT8 *d = destination;
    const UINT8 *s = source;
    for (UINTN i = 0; i < size; ++i)
        d[i] = s[i];
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);

    EBH_RESULT result;
    zero_bytes(&result, sizeof(result));
    result.Magic = 0x31484245;
    result.Version = 1;
    result.Target = TARGET_EBH;
    result.ResetRequested = RESET_ON_SUCCESS;
    result.OldValue = 0xff;
    result.VerifiedValue = 0xff;
    result.InitialGetStatus = EFI_NOT_STARTED;
    result.SetStatus = EFI_NOT_STARTED;
    result.VerifyStatus = EFI_NOT_STARTED;
    set_result(&result);

    Print(L"Acer Raptor Lake Extended Bank Hashing setup probe\r\n");
    Print(L"Target SaSetup[0x404] = %d; reset on success = %d\r\n",
          TARGET_EBH, RESET_ON_SUCCESS);

    UINTN size = 0;
    UINT32 attrs = 0;
    EFI_STATUS status = uefi_call_wrapper(RT->GetVariable, 5,
                                          L"SaSetup", &sa_setup_guid,
                                          &attrs, &size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || size != SA_SETUP_SIZE) {
        result.InitialGetStatus = status;
        result.DataSize = size;
        result.Attributes = attrs;
        set_result(&result);
        Print(L"GetVariable size query failed: status=%r size=0x%lx\r\n",
              status, size);
        return status == EFI_SUCCESS ? EFI_COMPROMISED_DATA : status;
    }

    UINT8 *data = NULL;
    UINT8 *expected = NULL;
    UINT8 *verify = NULL;
    status = uefi_call_wrapper(BS->AllocatePool, 3,
                               EfiLoaderData, size, (VOID **)&data);
    if (EFI_ERROR(status))
        return status;
    status = uefi_call_wrapper(BS->AllocatePool, 3,
                               EfiLoaderData, size, (VOID **)&expected);
    if (EFI_ERROR(status))
        return status;
    status = uefi_call_wrapper(BS->AllocatePool, 3,
                               EfiLoaderData, size, (VOID **)&verify);
    if (EFI_ERROR(status))
        return status;

    UINTN actual = size;
    status = uefi_call_wrapper(RT->GetVariable, 5,
                               L"SaSetup", &sa_setup_guid,
                               &attrs, &actual, data);
    result.InitialGetStatus = status;
    result.DataSize = actual;
    result.Attributes = attrs;
    if (EFI_ERROR(status) || actual != SA_SETUP_SIZE || attrs != 0x7 ||
        data[EBH_OFFSET] > 1) {
        set_result(&result);
        Print(L"GetVariable validation failed: status=%r size=0x%lx "
              L"attrs=0x%x value=0x%x\r\n",
              status, actual, attrs,
              actual > EBH_OFFSET ? data[EBH_OFFSET] : 0xff);
        return EFI_COMPROMISED_DATA;
    }

    result.OldValue = data[EBH_OFFSET];
    copy_bytes(expected, data, size);
    expected[EBH_OFFSET] = TARGET_EBH;
    Print(L"Current value: %d\r\n", result.OldValue);

    status = uefi_call_wrapper(RT->SetVariable, 5,
                               L"SaSetup", &sa_setup_guid,
                               attrs, size, expected);
    result.SetStatus = status;
    if (EFI_ERROR(status)) {
        set_result(&result);
        Print(L"SetVariable failed: %r\r\n", status);
        return status;
    }

    UINT32 verify_attrs = 0;
    UINTN verify_size = size;
    status = uefi_call_wrapper(RT->GetVariable, 5,
                               L"SaSetup", &sa_setup_guid,
                               &verify_attrs, &verify_size, verify);
    result.VerifyStatus = status;
    if (!EFI_ERROR(status) && verify_size > EBH_OFFSET)
        result.VerifiedValue = verify[EBH_OFFSET];

    if (EFI_ERROR(status) || verify_size != size || verify_attrs != attrs ||
        !same_bytes(expected, verify, size)) {
        set_result(&result);
        Print(L"Readback mismatch: status=%r size=0x%lx attrs=0x%x "
              L"value=0x%x\r\n",
              status, verify_size, verify_attrs, result.VerifiedValue);
        return EFI_COMPROMISED_DATA;
    }

    set_result(&result);
    Print(L"Verified SaSetup[0x404]: %d -> %d\r\n",
          result.OldValue, result.VerifiedValue);

#if RESET_ON_SUCCESS
    Print(L"Cold reset in three seconds...\r\n");
    uefi_call_wrapper(BS->Stall, 1, 3000000);
    uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold,
                      EFI_SUCCESS, 0, NULL);
    return EFI_DEVICE_ERROR;
#else
    Print(L"Returning to the firmware boot manager in three seconds...\r\n");
    uefi_call_wrapper(BS->Stall, 1, 3000000);
    return EFI_SUCCESS;
#endif
}
