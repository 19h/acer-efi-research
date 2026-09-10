# Intel DRAM decoder read-only probe

This probe inventories the relevant Raptor Lake-S host-bridge and DRAM-decoder
registers. It only opens PCI configuration space, `/dev/mem`, and MSR devices
read-only, and only maps MCHBAR with `PROT_READ`.

Build and run:

```sh
make
sudo ./probe
```

Do not turn this into a live register-write test under the normal OS. Changing
DRAM address decoding while other CPUs or DMA devices are active can corrupt
memory and persistent storage.

`policy_probe` is a separate, explicit transient test. It does not touch DRAM
decode: it briefly requests that PCI `00:00.0` clear `MCHBAREN`, reads back the
result, restores the byte immediately, and has an independent 50 ms watchdog
restore. This can test enforcement of MCHBAR's documented post-boot access
policy, but cannot by itself prove the policy of `MAD_DIMM`.

`ebh_var` reads or updates the exact hidden setup control found in the extracted
firmware IFR:

```text
SaSetup GUID:   72C5E28C-7783-43A1-8767-FAD73FCCAFA4
SaSetup offset: 0x404
Prompt:         Extended Bank Hashing
Values:         0 = disabled, 1 = enabled (default)
```

`ebh_var get` is read-only. `ebh_var set` submits the complete, validated
1,404-byte efivarfs image and optionally creates an exclusive backup first.
The caller must deliberately clear and restore efivarfs's immutable flag with
`chattr -i` / `chattr +i` around a write.

The original three `make uefi` applications perform the same validated update
while UEFI boot services are active. On this Acer firmware, ordinary
`SetVariable` and HII `RouteConfig` calls are rejected after ReadyToBoot with
`EFI_WRITE_PROTECTED`.

Reverse engineering identified the vendor's intended setup handshake:

```text
Setup[0xcb4] = 1    Password protection of Runtime Variables
NvLockMailbox GUID  504AF431-3025-4D32-9FBF-E9F31855551D
payload             "ANV$", locked, terminate  (six bytes total)
unlock              "ANV$", 0, 0
relock              "ANV$", 1, 0
```

`uefi-nv-unlock-safe1.efi` exercises this path without changing EBH. It refuses
to run its write phase unless the existing and target values are both `1`,
unlocks, submits the complete byte-identical `SaSetup`, verifies every byte,
and always relocks. `uefi-nv-unlock-set0-reset.efi` is the guarded follow-up:
it changes only `SaSetup[0x404]`, verifies the complete variable, relocks, and
cold-resets. Both record status in `AcerNvUnlockEbhResult`.

The HII launchers open Acer's normally unreachable raw formset directly:

```text
uefi-full-setup-unlocked.efi            form 0x2710, complete raw Setup root
uefi-memory-setup-unlocked.efi          form 0x27ae, Memory Configuration
uefi-var-protection-setup-unlocked.efi  form 0x28f3, UEFI Variables Protection
```

The unlocked variants apply the mailbox unlock only while the form browser is
open and relock on every normal return path. They never reset automatically:
after the browser returns, including a relock failure or reset request, the
launcher keeps the result visible and waits for Enter before cold-resetting to
the normal Ubuntu-only boot order.

Launcher version 3 exported each HII package list and passed only the unique
handle containing Acer's Setup formset. Hardware still returned
`EFI_SECURITY_VIOLATION`. Reverse engineering AMITSE showed that the rejection
was its failed protected-firmware-volume read of the `AMITSESetupData` `$SPF`
blob, not the selected handle or form.

Version 4 supplied that hash-pinned blob but hung while replacing the live HII
package. Disassembly of the built application found the exact cause: gnu-efi
4.0's `SetMem` and `CopyMem` symbols use the Microsoft x64 ABI, while this
`EFI_FUNCTION_WRAPPER` build called ordinary helpers with the SysV ABI. The
result structure was not zeroed and the HII copy was corrupted before AMI saw
it.

Version 5 uses local byte loops and no direct gnu-efi memory helpers. The
Memory Configuration launcher passes Acer's original package and opens form
`0x27ae` without modifying HII at all. The complete-root launcher instead
registers an isolated package-list copy, with a new package-list GUID, in which
only 73 unconditional static SuppressIf, 37 GrayOutIf, and one DisableIf TRUE
expression are changed to FALSE. It removes that duplicate on browser return;
no firmware image is flashed. The direct launcher reaches every expected
pre-browser checkpoint under OVMF and stops cleanly when the Acer formset is
absent.

The first v5 hardware run reached stage 9 and then deliberately rejected the
runtime AMITSE image. Its recorded derived base was internally consistent with
the exact `SendForm` RVA, but Acer's loader had not preserved the conventional
PE header that v5 also required. A v6 diagnostic then showed that the exact
32-byte `SendForm` entry matched while two offline RIP-relative data-reference
windows did not. IDA confirms all three instructions reference `qword_84D40`
in the file; the live mismatch indicates Acer patches their displacements when
placing AMITSE data separately from code.

Version 8 validates the exact `SendForm` entry and the opcode prefixes of three
independent references inside AMITSE, decodes each signed live RIP
displacement, and requires all three to resolve to the same aligned runtime
slot. It uses that derived slot rather than `image_base + 0x84d40`. The live
instruction bytes and all three targets are recorded before any slot write.
The v8 binaries are installed, while BootOrder remains Ubuntu-only and no
one-shot boot is armed.
