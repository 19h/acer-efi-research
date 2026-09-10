#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Read or update Acer's runtime SaSetup variable.
 *
 * IFR in this firmware maps SaSetup byte 0x404 to "Extended Bank Hashing".
 * efivarfs prepends the four-byte EFI attribute word, so the byte's file
 * offset is 0x408.  Writes always submit the complete variable image.
 *
 * efivarfs marks non-standard variables immutable.  Deliberately leave that
 * policy to the caller: use chattr -i immediately before `set`, and chattr +i
 * immediately afterward.  Refusing unexpected sizes/attributes/current
 * values is intentional because a partial or misplaced update is unsafe.
 */

static const char *const default_path =
    "/sys/firmware/efi/efivars/"
    "SaSetup-72c5e28c-7783-43a1-8767-fad73fccafa4";

enum {
    EFI_ATTR_SIZE = 4,
    SA_SETUP_SIZE = 0x578,
    EBH_VAR_OFFSET = 0x404,
    EBH_FILE_OFFSET = EFI_ATTR_SIZE + EBH_VAR_OFFSET,
    EXPECTED_FILE_SIZE = EFI_ATTR_SIZE + SA_SETUP_SIZE,
};

static void fail(const char *what)
{
    fprintf(stderr, "error: %s: %s\n", what, strerror(errno));
    exit(EXIT_FAILURE);
}

static void read_full(const char *path, uint8_t *buf, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail(path);

    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, buf + done, size - done);
        if (n < 0)
            fail("read variable");
        if (n == 0) {
            errno = EIO;
            fail("short variable read");
        }
        done += (size_t)n;
    }

    uint8_t extra;
    ssize_t n = read(fd, &extra, 1);
    if (n < 0)
        fail("check variable length");
    if (n != 0) {
        errno = EOVERFLOW;
        fail("unexpectedly long variable");
    }
    if (close(fd) < 0)
        fail("close variable after read");
}

static void validate(const uint8_t *buf)
{
    uint32_t attrs;
    memcpy(&attrs, buf, sizeof(attrs));
    if (attrs != 0x7) {
        fprintf(stderr, "error: unexpected EFI attributes %#010" PRIx32
                        " (expected 0x00000007)\n",
                attrs);
        exit(EXIT_FAILURE);
    }
    if (buf[EBH_FILE_OFFSET] > 1) {
        fprintf(stderr, "error: unexpected SaSetup[0x404] value %#x\n",
                buf[EBH_FILE_OFFSET]);
        exit(EXIT_FAILURE);
    }
}

static void save_backup(const char *path, const uint8_t *buf, size_t size)
{
    if (path == NULL)
        return;

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        fail("create backup");

    size_t done = 0;
    while (done < size) {
        ssize_t n = write(fd, buf + done, size - done);
        if (n < 0)
            fail("write backup");
        if (n == 0) {
            errno = EIO;
            fail("short backup write");
        }
        done += (size_t)n;
    }
    if (fsync(fd) < 0)
        fail("fsync backup");
    if (close(fd) < 0)
        fail("close backup");
}

static void write_full(const char *path, const uint8_t *buf, size_t size)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        fail("open variable for write (is immutable set?)");

    ssize_t n = write(fd, buf, size);
    if (n < 0)
        fail("write complete variable");
    if ((size_t)n != size) {
        fprintf(stderr, "error: short variable write (%zd/%zu bytes)\n",
                n, size);
        exit(EXIT_FAILURE);
    }
    if (fsync(fd) < 0 && errno != EINVAL)
        fail("fsync variable");
    if (close(fd) < 0)
        fail("close variable after write");
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--path efivarfs-file] get\n"
            "       %s [--path efivarfs-file] set 0|1 [backup-file]\n",
            argv0, argv0);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    const char *path = default_path;
    int arg = 1;
    if (argc >= 3 && strcmp(argv[1], "--path") == 0) {
        path = argv[2];
        arg = 3;
    }
    if (arg >= argc)
        usage(argv[0]);

    struct stat st;
    if (stat(path, &st) < 0)
        fail(path);
    if (st.st_size != EXPECTED_FILE_SIZE) {
        fprintf(stderr, "error: unexpected variable size %jd (expected %u)\n",
                (intmax_t)st.st_size, EXPECTED_FILE_SIZE);
        return EXIT_FAILURE;
    }

    uint8_t buf[EXPECTED_FILE_SIZE];
    read_full(path, buf, sizeof(buf));
    validate(buf);

    if (strcmp(argv[arg], "get") == 0) {
        if (arg + 1 != argc)
            usage(argv[0]);
        printf("SaSetup[0x404] ExtendedBankHashing = %u\n",
               buf[EBH_FILE_OFFSET]);
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[arg], "set") != 0 ||
        (arg + 2 != argc && arg + 3 != argc))
        usage(argv[0]);

    char *end = NULL;
    errno = 0;
    unsigned long requested = strtoul(argv[arg + 1], &end, 0);
    if (errno || end == argv[arg + 1] || *end != '\0' || requested > 1)
        usage(argv[0]);

    const char *backup = (arg + 3 == argc) ? argv[arg + 2] : NULL;
    save_backup(backup, buf, sizeof(buf));
    unsigned old = buf[EBH_FILE_OFFSET];
    buf[EBH_FILE_OFFSET] = (uint8_t)requested;
    write_full(path, buf, sizeof(buf));

    uint8_t verify[EXPECTED_FILE_SIZE];
    read_full(path, verify, sizeof(verify));
    validate(verify);
    if (memcmp(buf, verify, sizeof(buf)) != 0) {
        fprintf(stderr, "error: variable readback differs from submitted image\n");
        return EXIT_FAILURE;
    }

    printf("SaSetup[0x404] ExtendedBankHashing: %u -> %lu (verified)\n",
           old, requested);
    return EXIT_SUCCESS;
}
