#include <efi.h>
#include <efilib.h>

#ifndef TARGET_EBH
#define TARGET_EBH 1
#endif

#ifndef RESET_ON_SUCCESS
#define RESET_ON_SUCCESS 0
#endif

#ifndef REQUIRE_CURRENT_TARGET
#define REQUIRE_CURRENT_TARGET 0
#endif

#ifndef REQUIRED_OLD_EBH
#define REQUIRED_OLD_EBH -1
#endif

#if REQUIRED_OLD_EBH < -1 || REQUIRED_OLD_EBH > 1
#error REQUIRED_OLD_EBH must be -1, zero, or one
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

/* AMI NvramSmm recognizes this boot-services-only control mailbox. */
static EFI_GUID nv_lock_mailbox_guid = {
    0x504af431, 0x3025, 0x4d32,
    {0x9f, 0xbf, 0xe9, 0xf3, 0x18, 0x55, 0x55, 0x1d}
};

static EFI_GUID result_guid = {
    0x0dd7f125, 0x305e, 0x442d,
    {0xa7, 0xf4, 0x9a, 0xbd, 0x7e, 0x87, 0xb4, 0xe8}
};

typedef struct __attribute__((packed)) {
    UINT32 Signature; /* "ANV$" */
    UINT8 Locked;
    UINT8 Terminate;
} NV_LOCK_MAILBOX;

typedef CHAR8 NV_LOCK_MAILBOX_MUST_BE_SIX_BYTES[
    sizeof(NV_LOCK_MAILBOX) == 6 ? 1 : -1];

typedef struct {
    UINT32 Magic; /* "NVE1" */
    UINT16 Version;
    UINT8 Target;
    UINT8 ResetRequested;
    UINT8 OldValue;
    UINT8 VerifiedValue;
    UINT8 RelockAttempted;
    UINT8 Reserved;
    UINT32 Attributes;
    UINT64 DataSize;
    UINT64 InitialGetStatus;
    UINT64 UnlockStatus;
    UINT64 SetStatus;
    UINT64 VerifyStatus;
    UINT64 RelockStatus;
} NV_EBH_RESULT;

static VOID save_result(NV_EBH_RESULT *result)
{
    uefi_call_wrapper(RT->SetVariable, 5,
                      L"AcerNvUnlockEbhResult", &result_guid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof(*result), result);
}

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

    NV_EBH_RESULT result;
    zero_bytes(&result, sizeof(result));
    result.Magic = 0x3145564e;
    result.Version = 1;
    result.Target = TARGET_EBH;
    result.ResetRequested = RESET_ON_SUCCESS;
    result.OldValue = 0xff;
    result.VerifiedValue = 0xff;
    result.InitialGetStatus = EFI_NOT_STARTED;
    result.UnlockStatus = EFI_NOT_STARTED;
    result.SetStatus = EFI_NOT_STARTED;
    result.VerifyStatus = EFI_NOT_STARTED;
    result.RelockStatus = EFI_NOT_STARTED;
    save_result(&result);

    Print(L"Acer AMI NvLockMailbox EBH %s test\r\n",
          TARGET_EBH == 1 ? L"safe no-op" : L"disable");

    UINTN size = 0;
    UINT32 attrs = 0;
    EFI_STATUS status = uefi_call_wrapper(RT->GetVariable, 5,
                                          L"SaSetup", &sa_setup_guid,
                                          &attrs, &size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || size != SA_SETUP_SIZE) {
        result.InitialGetStatus = status;
        result.DataSize = size;
        result.Attributes = attrs;
        save_result(&result);
        Print(L"SaSetup size query failed: %r size=0x%lx\r\n", status, size);
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
        save_result(&result);
        Print(L"SaSetup validation failed: %r size=0x%lx attrs=0x%x\r\n",
              status, actual, attrs);
        return EFI_COMPROMISED_DATA;
    }

    result.OldValue = data[EBH_OFFSET];
    copy_bytes(expected, data, size);
    expected[EBH_OFFSET] = TARGET_EBH;
    Print(L"Current EBH=%u; guarded target=%u\r\n",
          result.OldValue, TARGET_EBH);

#if REQUIRE_CURRENT_TARGET
    if (result.OldValue != TARGET_EBH) {
        result.SetStatus = EFI_ABORTED;
        save_result(&result);
        Print(L"Safe no-op guard refused a value change.\r\n");
        return EFI_ABORTED;
    }
#endif
#if REQUIRED_OLD_EBH >= 0
    if (result.OldValue != REQUIRED_OLD_EBH) {
        result.SetStatus = EFI_ABORTED;
        save_result(&result);
        Print(L"Required-old-value guard refused: expected %u, got %u.\r\n",
              REQUIRED_OLD_EBH, result.OldValue);
        return EFI_ABORTED;
    }
#endif

    result.UnlockStatus = set_nv_lock(0);
    if (!EFI_ERROR(result.UnlockStatus)) {
        result.SetStatus = uefi_call_wrapper(RT->SetVariable, 5,
                                             L"SaSetup", &sa_setup_guid,
                                             attrs, size, expected);
        if (!EFI_ERROR(result.SetStatus)) {
            UINT32 verify_attrs = 0;
            UINTN verify_size = size;
            result.VerifyStatus = uefi_call_wrapper(RT->GetVariable, 5,
                                                    L"SaSetup", &sa_setup_guid,
                                                    &verify_attrs, &verify_size,
                                                    verify);
            if (!EFI_ERROR(result.VerifyStatus) &&
                verify_size == size && verify_attrs == attrs &&
                same_bytes(expected, verify, size))
                result.VerifiedValue = verify[EBH_OFFSET];
            else if (!EFI_ERROR(result.VerifyStatus))
                result.VerifyStatus = EFI_COMPROMISED_DATA;
        }
    }

    /* Always restore AMI's ReadyToBoot state before returning or resetting. */
    result.RelockAttempted = 1;
    result.RelockStatus = set_nv_lock(1);
    save_result(&result);

    Print(L"unlock=%r write=%r verify=%r relock=%r; EBH %u -> %u\r\n",
          result.UnlockStatus, result.SetStatus, result.VerifyStatus,
          result.RelockStatus, result.OldValue, result.VerifiedValue);

    if (EFI_ERROR(result.UnlockStatus))
        status = result.UnlockStatus;
    else if (EFI_ERROR(result.SetStatus))
        status = result.SetStatus;
    else if (EFI_ERROR(result.VerifyStatus))
        status = result.VerifyStatus;
    else if (EFI_ERROR(result.RelockStatus))
        status = result.RelockStatus;
    else
        status = EFI_SUCCESS;

#if RESET_ON_SUCCESS
    if (!EFI_ERROR(status) && result.VerifiedValue == TARGET_EBH) {
        Print(L"Verified and relocked. Cold reset in three seconds.\r\n");
        uefi_call_wrapper(BS->Stall, 1, 3000000);
        uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold,
                          EFI_SUCCESS, 0, NULL);
        return EFI_DEVICE_ERROR;
    }
#endif

    Print(L"Returning to firmware in three seconds.\r\n");
    uefi_call_wrapper(BS->Stall, 1, 3000000);
    return status;
}
