# Result on Acer Predator PO7-650 / Core i9-13900KF

Test date: 2026-08-13

## Platform

- CPU: Intel family 6, model `0xb7`, stepping 1 (Raptor Lake-S)
- Host bridge: `8086:a700`
- Firmware: Acer/AMI R01-B1, 2024-09-23
- Memory: 64 GiB DDR5, four 16 GiB single-rank DIMMs
- MCHBAR: enabled at physical `0xfedc0000`

## Live decoder state

Both memory channels report:

```text
MAD_DIMM_CH0 @ MCHBAR+0xd80c = 0xd0100010
MAD_DIMM_CH1 @ MCHBAR+0xd810 = 0xd0100010
DECODER_EBH = 3: XaB enabled, XbB enabled
```

Intel describes `DECODER_EBH` as extended address-decoder bank hashing. This is
the closest documented Raptor Lake equivalent to the AMD bank-swizzle control,
but the register-level policy is `BIOS: RW, SMM: R, OS: R`.

The protected SMM range is:

```text
SMRR base = 0x7f000006
SMRR mask = 0xff000c00
range     = 0x7f000000-0x7fffffff (16 MiB), valid and locked
```

## Non-decoder write-policy test

`policy_probe` briefly requested that PCI `00:00.0` clear only `MCHBAREN`
(offset `0x48`, bit 0), read it back, and restored it. It never wrote a DRAM
decoder register. A separate watchdog issued a redundant restore after 50 ms.

Observed result:

```text
MCHBAR low byte: original=0x01 clear-readback=0x01
restore-readback=0x01 watchdog-readback=0x01
result: clear write completed but was ignored/filtered
restore verified; MCHBAR is enabled with its original value
```

The Linux PCI configuration write returned success, but the system agent did
not change the register. That directly demonstrates post-boot write filtering
for MCHBAR on this system. Because Intel assigns the decoder registers the same
BIOS-RW/SMM-R/OS-R classification, the evidence strongly predicts that an OS
write to `MAD_DIMM` is filtered too. We did not prove that by changing EBH,
because doing so in a live multi-core, DMA-active OS can corrupt arbitrary
memory and storage.

## Hidden firmware control

The extracted Acer Setup IFR contains the exact control that initializes the
decoder during memory training:

```text
Form                   Memory Configuration (0x27ae)
Question               Extended Bank Hashing (0x5c0)
Variable               SaSetup / 72C5E28C-7783-43A1-8767-FAD73FCCAFA4
Offset                  0x404
Disabled / enabled      0 / 1 (enabled is the default and current value)
```

The raw Setup formset root at `0x2710` also links Intel's full Advanced and
Chipset trees that Acer's normal OEM front end does not expose. Dedicated HII
launchers for the complete root, Memory Configuration, and UEFI Variables
Protection forms have been built, VM-tested, and installed on the ESP.

The first `Boot000A` hardware run found 10 HII form handles and successfully
performed the AMI mailbox unlock/relock, but `SendForm` returned
`EFI_SECURITY_VIOLATION`. That build passed all 10 unrelated handles. Version 3
then exported every package list, selected the unique handle owning Acer
formset `7B59104A-C00D-4158-87FF-F04D6396A915`, and passed only that handle.
The second hardware run still returned the same raw
`EFI_SECURITY_VIOLATION` (`0x800000000000001a`), proving the handle selection
was not the remaining gate.

Reverse engineering AMITSE's `SendForm` path located the failure: when its
internal Setup-data pointer is null, AMITSE reads the `AMITSESetupData`
freeform section from a protected firmware volume. That read returns the
observed security status to an external boot application. The exact extracted
`$SPF` payload is 872,188 bytes, SHA-256
`cb8f3c86de505fd488f9ea2b028781a22682963b4d720a7bdfe9cd6223730f6f`.

Version 4 verified the exact R01-B1 AMITSE image and supplied that hash-pinned
`$SPF` pointer, but its first hardware run hung while updating the package
list. The built code exposed a mixed-ABI defect: gnu-efi 4.0's `SetMem` and
`CopyMem` entry points expected Microsoft x64 register arguments, while the
`EFI_FUNCTION_WRAPPER` application called ordinary C helpers using SysV. The
result structure remained partly uninitialized and the copied HII bytes were
corrupted. The machine was hard-reset; `SaSetup[0x404]` and live
`DECODER_EBH=3` remained unchanged.

Version 5 removes every such call in the project-owned EFI applications and
uses local byte loops. The direct Memory Configuration build does not mutate
or duplicate HII: it selects Acer's original unique handle, supplies the
verified AMITSE data pointer, and opens form `0x27ae`. `Extended Bank Hashing`
is unconditional inside that form. The full-root build separately makes a
byte-identical package copy, verifies an exact 111-byte `TRUE` to `FALSE`
delta (73 SuppressIf, 37 GrayOutIf, one DisableIf), gives only the package-list
header a new GUID, and registers/removes that isolated copy. The final v5
binaries are strict-warning-clean apart from gnu-efi's wrapper pedantry and
OVMF-tested through the expected four checkpoints.

The first v5 hardware run reached stage 9, with the package and `$SPF` hash
checks passing, then deliberately returned `EFI_INCOMPATIBLE_VERSION` from its
runtime-image guard. The captured derived AMITSE base was consistent with the
exact `SendForm` RVA, but Acer's runtime loader had not retained the
conventional PE header which v5 also required. EBH remained `1` in `SaSetup`
and `DECODER_EBH=3` in both live channel registers.

Version 6 retained exact offline RIP-displacement bytes. Its hardware result
mask was `1`: the exact 32-byte `SendForm` entry matched, while both
RIP-relative data references differed live. IDA confirms the offline
instructions at `0x1fcb5`, `0x20b1f`, and `0x20b2f` all resolve to
`qword_84D40`; the mismatch is consistent with Acer relocating AMITSE data
separately and patching those signed displacements.

Version 8 validates the exact `SendForm` entry plus the three instruction
opcode prefixes, decodes each signed displacement from live RAM, and requires
all three targets to be identical and eight-byte aligned. Only that derived
slot is used; `image_base + 0x84d40` is no longer assumed. It records the live
instructions and targets before any slot write. The v8 launchers are
strict-compiled, OVMF-smoke-tested, installed, and hash-verified on the ESP.
Persistent BootOrder remains Ubuntu-only and no one-shot boot is armed.

Version 9 fixes the real stage-5 blocker, which the AMITSE image-guard history
above had masked. The 2026-08-16 hardware run of `uefi-full-setup-unlocked.efi`
(form 0x2710) returned `EFI_INCOMPATIBLE_VERSION`, but not from the AMITSE
runtime guard — `AcerFullSetupResult` recorded `Stage=5`,
`UiPatchStatus=0x8000000000000019`, `RuntimeValidationMask=0`, and
`StaticSuppressUnlocked=79`. The AMITSE guard at stage 9-10 was never reached.

`unlock_static_ifr_conditions()` required the SuppressIf count to be exactly 73.
The extracted R01-B1 Setup driver IFR (`research/reversing/Setup-899407D7.bin`,
formset at 0x3ecd8) does contain exactly 73 SuppressIf-TRUE, 37 GrayOutIf-TRUE,
and 1 DisableIf-TRUE — confirmed by both a scope-tracked walk and the launcher's
own linear walk (clean, ending exactly at the package boundary). The live HII
database, however, merges runtime IFR (AMI label / `UpdateForm` insertions) into
the exported package, so the runtime package legitimately carries 79
SuppressIf-TRUE (six runtime-added); GrayOutIf and DisableIf are unchanged. The
exact `!= 73` and `== 111`-delta equalities therefore rejected a valid firmware.

Version 9 uses the compiled-in counts as a lower bound (>= 73 / 37 / 1) plus a
clean full walk, and requires the byte delta to equal the number of conditions
actually counted and flipped, rather than a hardcoded 111. Formset identity is
still pinned by `has_acer_formset()` and a single matching handle, and every
patched byte is still proven to be an exact `0x46`->`0x47` (TRUE->FALSE) flip, so
nothing outside Acer's own static conditions can be altered.

## Setup-variable write protection

Four independent lower-level tests initially failed:

- Linux runtime `SetVariable`: `EFI_WRITE_PROTECTED`
- UEFI Boot Services `SetVariable`: `EFI_WRITE_PROTECTED`
- Acer Setup driver's HII `RouteConfig`: `EFI_WRITE_PROTECTED`
- direct SPI programming of both redundant NVAR copies: reported completion,
  but SMM_BWP left every byte unchanged

`AmiSetupNVLockDxe` and `NvramSmm` reveal the intended bypass used by AMI's
own setup application. `Setup[0xcb4]` is the visible-hidden option “Password
protection of Runtime Variables” and is currently `1`. When enabled, the DXE
driver sends a boot-services-only six-byte mailbox:

```text
variable  NvLockMailbox / 504AF431-3025-4D32-9FBF-E9F31855551D
format    41 4e 56 24  LL TT      ("ANV$", locked, terminate)
setup     41 4e 56 24  00 00      unlock
boot      41 4e 56 24  01 00      relock
```

The SMM implementation explicitly recognizes the name and GUID, validates the
`ANV$` signature, and copies byte 4 to its internal lock flag. The
`uefi-nv-unlock-safe1.efi` hardware test is prepared to prove this path using a
strict byte-identical `SaSetup` write before any real setting is changed.

## Current conclusion

The literal AMD MMIO write does not transfer to this machine as a
software-only root/kernel primitive:

1. The analogous bank-hash control exists and is enabled.
2. It is configured by Intel FSP/MRC during firmware memory initialization.
3. This host bridge demonstrably filters post-boot OS writes to a register with
   the same access classification.
4. SMRAM is protected by a valid, locked 16 MiB SMRR.

However, the Acer firmware does expose a vendor mailbox capable of temporarily
unlocking the setup variable that controls Intel's analogous decoder setting.
The remaining experiment is to verify that mailbox, disable EBH across a cold
boot, then create an intentional S3 policy/live-decoder mismatch and search for
physical aliases. No Intel exploit claim is established until those hardware
tests succeed and an alias crosses a protected boundary.

## Sources

- Intel, *13th Generation Intel Core Processor Datasheet, Volume 2 of 2*:
  https://cdrdv2-public.intel.com/743846/743846-001.pdf
- Acer PO7-650 support page and R01-B1 image:
  https://www.acer.com/it-it/support/product-support/Predator_PO7-650/downloads
- Intel on the physical-interposer Battering RAM research:
  https://www.intel.com/content/www/us/en/developer/articles/news/more-information-encrypted-memory-frameworks.html
