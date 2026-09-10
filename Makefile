CC ?= cc
CFLAGS += -O2 -Wall -Wextra -Wpedantic

.PHONY: all clean uefi uefi-setup

all: probe policy_probe ebh_var

EFI_CFLAGS = -I/usr/include/efi -I/usr/include/efi/x86_64 \
	-DEFI_FUNCTION_WRAPPER -fpic -ffreestanding -fno-stack-protector \
	-fno-stack-check -fshort-wchar -mno-red-zone -maccumulate-outgoing-args \
	-Wall -Wextra -Wpedantic
EFI_LDFLAGS = -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds \
	-shared -Bsymbolic /usr/lib/crt0-efi-x86_64.o
EFI_SECTIONS = -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
	-j .rodata -j .rel -j .rela -j .rel.* -j .rela.* -j .reloc

probe: probe.c
	$(CC) $(CFLAGS) -o $@ $<

policy_probe: policy_probe.c
	$(CC) $(CFLAGS) -o $@ $<

ebh_var: ebh_var.c
	$(CC) $(CFLAGS) -o $@ $<

uefi: uefi-ebh-test1.efi uefi-ebh-set0-reset.efi uefi-ebh-set1.efi \
	uefi-nv-unlock-safe1.efi uefi-nv-unlock-set0-reset.efi \
	uefi-nv-unlock-set1-no-reset.efi

uefi-setup: uefi-full-setup.efi uefi-memory-setup.efi \
	uefi-var-protection-setup.efi uefi-full-setup-unlocked.efi \
	uefi-memory-setup-unlocked.efi uefi-var-protection-setup-unlocked.efi \
	uefi-hii-extract.efi uefi-hii-route-safe.efi

uefi-ebh-test1.o: uefi_ebh.c
	/usr/bin/gcc $(EFI_CFLAGS) -DTARGET_EBH=1 -DRESET_ON_SUCCESS=0 -c -o $@ $<

uefi-ebh-set0-reset.o: uefi_ebh.c
	/usr/bin/gcc $(EFI_CFLAGS) -DTARGET_EBH=0 -DRESET_ON_SUCCESS=1 -c -o $@ $<

uefi-ebh-set1.o: uefi_ebh.c
	/usr/bin/gcc $(EFI_CFLAGS) -DTARGET_EBH=1 -DRESET_ON_SUCCESS=0 -c -o $@ $<

uefi-nv-unlock-safe1.o: uefi_nv_unlock_ebh.c
	/usr/bin/gcc $(EFI_CFLAGS) -DTARGET_EBH=1 -DRESET_ON_SUCCESS=0 \
		-DREQUIRE_CURRENT_TARGET=1 -c -o $@ $<

uefi-nv-unlock-set0-reset.o: uefi_nv_unlock_ebh.c
	/usr/bin/gcc $(EFI_CFLAGS) -DTARGET_EBH=0 -DRESET_ON_SUCCESS=1 -c -o $@ $<

uefi-nv-unlock-set1-no-reset.o: uefi_nv_unlock_ebh.c
	/usr/bin/gcc $(EFI_CFLAGS) -DTARGET_EBH=1 -DRESET_ON_SUCCESS=0 \
		-DREQUIRED_OLD_EBH=0 -c -o $@ $<

uefi-full-setup.o: uefi_hii_setup.c
	/usr/bin/gcc $(EFI_CFLAGS) -DSTART_FORM_ID=0x2710 \
		-DPATCH_HIDDEN_UI=1 \
		-DLAUNCHER_NAME='L"Acer full hidden setup"' -c -o $@ $<

uefi-memory-setup.o: uefi_hii_setup.c
	/usr/bin/gcc $(EFI_CFLAGS) -DSTART_FORM_ID=0x27AE \
		-DPATCH_HIDDEN_UI=0 \
		-DLAUNCHER_NAME='L"Acer direct memory setup"' -c -o $@ $<

uefi-var-protection-setup.o: uefi_hii_setup.c
	/usr/bin/gcc $(EFI_CFLAGS) -DSTART_FORM_ID=0x28F3 \
		-DPATCH_HIDDEN_UI=0 \
		-DLAUNCHER_NAME='L"Acer UEFI variable protection setup"' -c -o $@ $<

uefi-full-setup-unlocked.o: uefi_hii_setup.c
	/usr/bin/gcc $(EFI_CFLAGS) -DUSE_NV_UNLOCK=1 -DSTART_FORM_ID=0x2710 \
		-DPATCH_HIDDEN_UI=1 \
		-DLAUNCHER_NAME='L"Acer full hidden setup (unlocked)"' -c -o $@ $<

uefi-memory-setup-unlocked.o: uefi_hii_setup.c
	/usr/bin/gcc $(EFI_CFLAGS) -DUSE_NV_UNLOCK=1 -DSTART_FORM_ID=0x27AE \
		-DPATCH_HIDDEN_UI=0 \
		-DLAUNCHER_NAME='L"Acer direct memory setup (unlocked)"' -c -o $@ $<

uefi-var-protection-setup-unlocked.o: uefi_hii_setup.c
	/usr/bin/gcc $(EFI_CFLAGS) -DUSE_NV_UNLOCK=1 -DSTART_FORM_ID=0x28F3 \
		-DPATCH_HIDDEN_UI=0 \
		-DLAUNCHER_NAME='L"Acer UEFI variable protection (unlocked)"' -c -o $@ $<

uefi-hii-extract.o: uefi_hii_extract.c
	/usr/bin/gcc $(EFI_CFLAGS) -c -o $@ $<

uefi-hii-route-safe.o: uefi_hii_route.c
	/usr/bin/gcc $(EFI_CFLAGS) -c -o $@ $<

uefi-chain-sentinel.o: uefi_chain_sentinel.c
	/usr/bin/gcc $(EFI_CFLAGS) -c -o $@ $<

%.so: %.o
	/usr/bin/ld $(EFI_LDFLAGS) -o $@ $< -L/usr/lib -lgnuefi -lefi

%.efi: %.so
	/usr/bin/objcopy $(EFI_SECTIONS) -O pei-x86-64 --subsystem efi-app $< $@

clean:
	$(RM) probe policy_probe ebh_var uefi-ebh-*.o uefi-ebh-*.so uefi-ebh-*.efi \
		uefi-nv-unlock-*.o uefi-nv-unlock-*.so uefi-nv-unlock-*.efi \
		uefi-full-setup.o uefi-full-setup.so uefi-full-setup.efi \
		uefi-memory-setup.o uefi-memory-setup.so uefi-memory-setup.efi \
		uefi-var-protection-setup.o uefi-var-protection-setup.so \
		uefi-var-protection-setup.efi \
		uefi-full-setup-unlocked.o uefi-full-setup-unlocked.so \
		uefi-full-setup-unlocked.efi \
		uefi-memory-setup-unlocked.o uefi-memory-setup-unlocked.so \
		uefi-memory-setup-unlocked.efi \
		uefi-var-protection-setup-unlocked.o \
		uefi-var-protection-setup-unlocked.so \
		uefi-var-protection-setup-unlocked.efi \
		uefi-hii-extract.o uefi-hii-extract.so uefi-hii-extract.efi \
		uefi-hii-route-safe.o uefi-hii-route-safe.so uefi-hii-route-safe.efi
