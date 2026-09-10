#include <efi.h>
#include <efilib.h>

static EFI_GUID sentinel_guid = {
    0x3c9c940d, 0x5f5c, 0x4e99,
    {0xb0, 0x99, 0x49, 0xf9, 0xc0, 0xd3, 0x32, 0x79}
};

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);
    UINT32 reached = 0x53454e54; /* SENT */
    uefi_call_wrapper(RT->SetVariable, 5,
                      L"ChainloadSentinelReached", &sentinel_guid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof(reached), &reached);
    Print(L"CHAINLOAD_SENTINEL: Ubuntu fallback path started successfully.\r\n");
    while (TRUE)
        uefi_call_wrapper(BS->Stall, 1, 1000000);
    return EFI_SUCCESS;
}
