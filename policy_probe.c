#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Narrow post-boot access-policy probe for Raptor Lake.
 *
 * This does NOT write any DRAM decoder register. It briefly requests that the
 * host bridge stop decoding the otherwise-unused MCHBAR MMIO window by clearing
 * PCI 00:00.0 offset 0x48 bit 0, reads it back, and restores it immediately.
 * A watchdog independently restores the original byte after 50 ms.
 *
 * MCHBAREN is chosen because toggling it does not change DRAM addressing or
 * contents. Intel nevertheless gives MCHBAR itself the same BIOS-RW/SMM-R/OS-R
 * register-level access classification as the MAD decoder registers. This test
 * therefore tells us whether that classification is enforced for MCHBAR; it
 * does not prove that MAD_DIMM has identical enforcement.
 */

static const char *config_path =
    "/sys/bus/pci/devices/0000:00:00.0/config";

static void fail(const char *what)
{
    fprintf(stderr, "error: %s: %s\n", what, strerror(errno));
    exit(EXIT_FAILURE);
}

static uint8_t read_byte(int fd)
{
    uint8_t value;
    ssize_t got = pread(fd, &value, 1, 0x48);
    if (got < 0)
        fail("read MCHBAR low byte");
    if (got != 1) {
        fprintf(stderr, "error: short PCI configuration read\n");
        exit(EXIT_FAILURE);
    }
    return value;
}

static bool write_byte(int fd, uint8_t value)
{
    ssize_t put = pwrite(fd, &value, 1, 0x48);
    return put == 1;
}

static void pin_and_lock(void)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus) < 0)
        fail("pin to CPU 0");
    if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
        fail("mlockall");
}

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "--run") != 0) {
        fprintf(stderr,
                "usage: sudo %s --run\n"
                "This transiently toggles only MCHBAREN, never DRAM decode.\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    pin_and_lock();
    int fd = open(config_path, O_RDWR | O_CLOEXEC | O_SYNC);
    if (fd < 0)
        fail(config_path);
    uint8_t original = read_byte(fd);
    if (!(original & 1)) {
        fprintf(stderr, "error: MCHBAR was already disabled (byte %#04x)\n",
                original);
        return EXIT_FAILURE;
    }
    uint8_t disabled = original & (uint8_t)~1U;

    pid_t watchdog = fork();
    if (watchdog < 0)
        fail("fork watchdog");
    if (watchdog == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 50000000};
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR)
            ;
        int watchdog_fd = open(config_path, O_RDWR | O_CLOEXEC | O_SYNC);
        if (watchdog_fd >= 0) {
            (void)write_byte(watchdog_fd, original);
            close(watchdog_fd);
        }
        _exit(0);
    }

    errno = 0;
    bool clear_request_completed = write_byte(fd, disabled);
    int clear_errno = errno;
    uint8_t after_clear = read_byte(fd);

    errno = 0;
    bool restore_request_completed = write_byte(fd, original);
    int restore_errno = errno;
    uint8_t after_immediate_restore = read_byte(fd);

    int status;
    if (waitpid(watchdog, &status, 0) < 0)
        fail("wait for watchdog");
    uint8_t final = read_byte(fd);
    close(fd);

    printf("MCHBAR low byte: original=%#04x clear-readback=%#04x "
           "restore-readback=%#04x watchdog-readback=%#04x\n",
           original, after_clear, after_immediate_restore, final);
    if (!clear_request_completed)
        printf("clear request rejected by kernel: %s\n", strerror(clear_errno));
    else if (after_clear & 1)
        printf("result: clear write completed but was ignored/filtered\n");
    else
        printf("result: clear write was accepted by the host bridge\n");

    if (!restore_request_completed)
        printf("immediate restore request failed: %s\n",
               strerror(restore_errno));
    if (!(final & 1) || final != original) {
        fprintf(stderr, "FATAL: watchdog did not restore the original byte\n");
        return EXIT_FAILURE;
    }
    printf("restore verified; MCHBAR is enabled with its original value\n");
    return EXIT_SUCCESS;
}
