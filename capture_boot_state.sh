#!/bin/sh
set -eu

project=/media/null/ares/intel-dram-alias
marker="$project/ARM_CAPTURE_NEXT_BOOT"
[ -e "$marker" ] || exit 0

stamp=$(date +%Y%m%d-%H%M%S)
output="$project/research/boot-capture-$stamp.txt"
temporary=$(mktemp "$project/research/.boot-capture-$stamp.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

{
    echo "capture_time=$(date --iso-8601=seconds)"
    echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
    echo "kernel=$(uname -srvmo)"
    echo
    echo "== EFI boot state =="
    efibootmgr -v || true
    echo
    echo "== SaSetup =="
    "$project/ebh_var" get || true
    echo
    echo "== Live decoder =="
    "$project/probe" || true
    echo
    echo "== UEFI app result =="
    result=$(find /sys/firmware/efi/efivars -maxdepth 1 -type f \
        -iname 'EbhProbeResult-3c744b90-60ee-4d74-a21e-f44231e47319' \
        -print -quit)
    if [ -n "$result" ]; then
        xxd -g 1 "$result"
    else
        echo "result variable not present"
    fi
    echo
    echo "== Acer HII ConfigAccess result =="
    hii_result=$(find /sys/firmware/efi/efivars -maxdepth 1 -type f \
        -iname 'AcerHiiExtractResult-7d34b513-0824-491f-9ee3-e3e45544b246' \
        -print -quit)
    if [ -n "$hii_result" ]; then
        xxd -g 1 "$hii_result"
    else
        echo "result variable not present"
    fi
    echo
    echo "== Acer HII safe RouteConfig result =="
    route_result=$(find /sys/firmware/efi/efivars -maxdepth 1 -type f \
        -iname 'AcerHiiRouteResult-f7f09867-a2de-40e7-879a-8610dd530fa9' \
        -print -quit)
    if [ -n "$route_result" ]; then
        xxd -g 1 "$route_result"
    else
        echo "result variable not present"
    fi
    echo
    echo "== AMI NvLockMailbox EBH result =="
    nv_result=$(find /sys/firmware/efi/efivars -maxdepth 1 -type f \
        -iname 'AcerNvUnlockEbhResult-0dd7f125-305e-442d-a7f4-9abd7e87b4e8' \
        -print -quit)
    if [ -n "$nv_result" ]; then
        xxd -g 1 "$nv_result"
    else
        echo "result variable not present"
    fi
    echo
    echo "== Acer full Setup launcher result =="
    setup_result=$(find /sys/firmware/efi/efivars -maxdepth 1 -type f \
        -iname 'AcerFullSetupResult-e9b23f6a-3288-4024-a177-50eae6fcc90e' \
        -print -quit)
    if [ -n "$setup_result" ]; then
        xxd -g 8 "$setup_result"
    else
        echo "result variable not present"
    fi
    echo
    echo "== Previous-boot tail =="
    journalctl -b -1 -n 120 --no-pager || true
} >"$temporary" 2>&1

chmod 0644 "$temporary"
mv "$temporary" "$output"
mv "$marker" "$project/CAPTURED_BOOT_$stamp"
sync -f "$output"
trap - EXIT HUP INT TERM
