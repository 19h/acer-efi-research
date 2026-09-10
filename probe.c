#define _GNU_SOURCE

#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Read-only Raptor Lake DRAM decoder inventory.
 *
 * This program intentionally contains no write-capable open, mapping, or I/O
 * path.  It cannot test register writability and it must not be extended to do
 * so in a running multi-core OS: changing address decoding while memory is in
 * use can corrupt memory or storage.
 */

static const char *pci_config = "/sys/bus/pci/devices/0000:00:00.0/config";

static void die(const char *what)
{
    fprintf(stderr, "error: %s: %s\n", what, strerror(errno));
    exit(EXIT_FAILURE);
}

static void read_exact_at(int fd, void *buf, size_t count, off_t offset,
                          const char *what)
{
    ssize_t got = pread(fd, buf, count, offset);
    if (got < 0)
        die(what);
    if ((size_t)got != count) {
        fprintf(stderr, "error: short read of %s (%zd/%zu bytes)\n",
                what, got, count);
        exit(EXIT_FAILURE);
    }
}

static uint16_t pci_u16(int fd, off_t offset, const char *name)
{
    uint16_t value;
    read_exact_at(fd, &value, sizeof(value), offset, name);
    return value;
}

static uint32_t pci_u32(int fd, off_t offset, const char *name)
{
    uint32_t value;
    read_exact_at(fd, &value, sizeof(value), offset, name);
    return value;
}

static uint64_t pci_u64(int fd, off_t offset, const char *name)
{
    uint64_t value;
    read_exact_at(fd, &value, sizeof(value), offset, name);
    return value;
}

static bool read_msr(unsigned cpu, uint32_t msr, uint64_t *value)
{
    char path[64];
    snprintf(path, sizeof(path), "/dev/cpu/%u/msr", cpu);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t got = pread(fd, value, sizeof(*value), msr);
    int saved = errno;
    close(fd);
    errno = saved;
    return got == (ssize_t)sizeof(*value);
}

static void print_smrr(unsigned cpu)
{
    uint64_t cap, base, mask;
    if (!read_msr(cpu, 0xfe, &cap) ||
        !read_msr(cpu, 0x1f2, &base) ||
        !read_msr(cpu, 0x1f3, &mask)) {
        printf("  CPU %-2u: unavailable (%s)\n", cpu, strerror(errno));
        return;
    }

    /* Client SMRR is below 4 GiB on this platform. */
    uint64_t addr_mask = UINT64_C(0xfffff000);
    uint64_t range_base = base & addr_mask;
    uint64_t range_size = ((~mask) & addr_mask) + UINT64_C(0x1000);
    printf("  CPU %-2u: MTRRCAP=%#010" PRIx64
           " SMRR_BASE=%#010" PRIx64 " SMRR_MASK=%#010" PRIx64,
           cpu, cap, base, mask);
    if (mask & (UINT64_C(1) << 11))
        printf(" => [%#010" PRIx64 ", %#010" PRIx64 "] (%" PRIu64
               " MiB), valid%s\n",
               range_base, range_base + range_size - 1,
               range_size >> 20,
               (mask & (UINT64_C(1) << 10)) ? ", locked" : "");
    else
        printf(" => invalid\n");
}

static const char *ddr_type(unsigned value)
{
    static const char *const names[] = {
        "DDR4", "DDR5", "LPDDR5", "LPDDR4"
    };
    return value < 4 ? names[value] : "reserved";
}

static void print_dimm(unsigned channel, uint32_t value)
{
    unsigned ebh = (value >> 30) & 3;
    unsigned bg0 = (value >> 28) & 3;
    unsigned small_size = (value >> 16) & 0x7f;
    unsigned large_size = value & 0x7f;
    unsigned small_ranks = ((value >> 26) & 3) + 1;
    unsigned large_ranks = ((value >> 9) & 3) + 1;

    printf("MAD_DIMM_CH%u +%#06x = %#010x\n",
           channel, channel ? 0xd810 : 0xd80c, value);
    printf("  DECODER_EBH=%u (XaB=%s, XbB=%s), BG0 option=%u\n",
           ebh, (ebh & 1) ? "on" : "off", (ebh & 2) ? "on" : "off", bg0);
    printf("  DIMM L=%u.%u GiB/%u rank(s), DIMM S=%u.%u GiB/%u rank(s)\n",
           large_size / 2, (large_size & 1) ? 5 : 0, large_ranks,
           small_size / 2, (small_size & 1) ? 5 : 0, small_ranks);
}

static uint32_t mmio_u32(const volatile uint8_t *mmio, size_t offset)
{
    return *(const volatile uint32_t *)(mmio + offset);
}

int main(void)
{
    unsigned eax, ebx, ecx, edx;
    char vendor[13] = {0};
    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        fprintf(stderr, "error: CPUID unavailable\n");
        return EXIT_FAILURE;
    }
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);

    __cpuid(1, eax, ebx, ecx, edx);
    unsigned family = ((eax >> 8) & 0xf) + ((eax >> 20) & 0xff);
    unsigned model = ((eax >> 4) & 0xf) | ((eax >> 12) & 0xf0);
    unsigned stepping = eax & 0xf;

    printf("Intel DRAM decoder read-only probe\n");
    printf("CPU: %s family %#x model %#x stepping %#x\n",
           vendor, family, model, stepping);
    if (strcmp(vendor, "GenuineIntel") || family != 6 || model != 0xb7) {
        fprintf(stderr, "error: this decoder is specific to Raptor Lake-S "
                        "(family 6, model 0xb7)\n");
        return EXIT_FAILURE;
    }

    int cfg = open(pci_config, O_RDONLY | O_CLOEXEC);
    if (cfg < 0)
        die(pci_config);
    uint16_t vendor_id = pci_u16(cfg, 0x00, "PCI vendor ID");
    uint16_t device_id = pci_u16(cfg, 0x02, "PCI device ID");
    uint64_t mchbar_raw = pci_u64(cfg, 0x48, "MCHBAR");
    uint64_t mchbar = mchbar_raw & ((UINT64_C(1) << 42) - 1) &
                      ~((UINT64_C(1) << 17) - 1);
    uint32_t dpr = pci_u32(cfg, 0x5c, "DPR");
    uint64_t tom = pci_u64(cfg, 0xa0, "TOM") & ~UINT64_C(0xfffff);
    uint64_t touud = pci_u64(cfg, 0xa8, "TOUUD") & ~UINT64_C(0xfffff);
    uint32_t tsegmb = pci_u32(cfg, 0xb8, "TSEGMB") & 0xfff00000U;
    uint32_t tolud = pci_u32(cfg, 0xbc, "TOLUD") & 0xfff00000U;
    close(cfg);

    printf("Host bridge: %04x:%04x\n", vendor_id, device_id);
    if (vendor_id != 0x8086 || device_id != 0xa700) {
        fprintf(stderr, "error: expected Raptor Lake-S host bridge 8086:a700\n");
        return EXIT_FAILURE;
    }
    printf("MCHBAR: raw=%#014" PRIx64 " base=%#014" PRIx64 " enabled=%s\n",
           mchbar_raw, mchbar, (mchbar_raw & 1) ? "yes" : "no");
    printf("Memory boundaries: TOM=%#014" PRIx64 " TOUUD=%#014" PRIx64
           " TOLUD=%#010x TSEGMB=%#010x DPR=%#010x\n",
           tom, touud, tolud, tsegmb, dpr);
    if (!(mchbar_raw & 1)) {
        fprintf(stderr, "error: MCHBAR is disabled\n");
        return EXIT_FAILURE;
    }

    const size_t map_size = 0x20000;
    int mem = open("/dev/mem", O_RDONLY | O_SYNC | O_CLOEXEC);
    if (mem < 0)
        die("/dev/mem (run as root)");
    void *mapping = mmap(NULL, map_size, PROT_READ, MAP_SHARED, mem, mchbar);
    if (mapping == MAP_FAILED)
        die("read-only MCHBAR mmap");
    const volatile uint8_t *mmio = mapping;

    uint32_t inter = mmio_u32(mmio, 0xd800);
    uint32_t intra0 = mmio_u32(mmio, 0xd804);
    uint32_t intra1 = mmio_u32(mmio, 0xd808);
    uint32_t dimm0 = mmio_u32(mmio, 0xd80c);
    uint32_t dimm1 = mmio_u32(mmio, 0xd810);
    uint32_t channel_hash = mmio_u32(mmio, 0xd824);
    uint32_t channel_ehash = mmio_u32(mmio, 0xd828);

    printf("\nAddress-decoder registers (all reads):\n");
    printf("MAD_INTER_CHANNEL +0xd800 = %#010x (DDR type %s)\n",
           inter, ddr_type(inter & 7));
    printf("MAD_INTRA_CH0    +0xd804 = %#010x (EIM=%s)\n",
           intra0, (intra0 & (1U << 8)) ? "on" : "off");
    printf("MAD_INTRA_CH1    +0xd808 = %#010x (EIM=%s)\n",
           intra1, (intra1 & (1U << 8)) ? "on" : "off");
    print_dimm(0, dimm0);
    print_dimm(1, dimm1);
    printf("CHANNEL_HASH     +0xd824 = 0x%08x\n", channel_hash);
    printf("CHANNEL_EHASH    +0xd828 = 0x%08x\n", channel_ehash);

    if (munmap(mapping, map_size) < 0)
        die("munmap");
    close(mem);

    printf("\nSMRR state (MSR reads):\n");
    print_smrr(0);
    if (access("/dev/cpu/16/msr", F_OK) == 0)
        print_smrr(16);

    printf("\nInterpretation:\n");
    printf("  DECODER_EBH changes DRAM bank hashing and is the closest documented\n");
    printf("  analogue to the AMD BankSwizzleMode primitive. Intel's 13th-gen\n");
    printf("  datasheet classifies MCHBAR D800-D810 as BIOS RW, SMM R, OS R.\n");
    printf("  This probe establishes configuration only; it does not establish\n");
    printf("  that an OS write is accepted, nor that useful aliases would result.\n");
    return EXIT_SUCCESS;
}
