#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Minimal Android/Bionic ABI surface required by LINE 4.0.3 libamp.so. */
unsigned char __sF[3 * 256];

static unsigned short compat_ctype_storage[384];
static int compat_tolower_storage[384];
static int compat_toupper_storage[384];

const unsigned short *_ctype_ = compat_ctype_storage + 128;
const int *_tolower_tab_ = compat_tolower_storage + 128;
const int *_toupper_tab_ = compat_toupper_storage + 128;

__attribute__((constructor)) static void init_ctype_tables(void) {
    for (int c = -128; c < 256; ++c) {
        unsigned char uc = (unsigned char)c;
        unsigned short flags = 0;
        if (isalnum(uc)) flags |= 0x0001;
        if (isalpha(uc)) flags |= 0x0002;
        if (iscntrl(uc)) flags |= 0x0004;
        if (isdigit(uc)) flags |= 0x0008;
        if (isgraph(uc)) flags |= 0x0010;
        if (islower(uc)) flags |= 0x0020;
        if (isprint(uc)) flags |= 0x0040;
        if (ispunct(uc)) flags |= 0x0080;
        if (isspace(uc)) flags |= 0x0100;
        if (isupper(uc)) flags |= 0x0200;
        if (isxdigit(uc)) flags |= 0x0400;
        if (isblank(uc)) flags |= 0x0800;
        compat_ctype_storage[c + 128] = flags;
        compat_tolower_storage[c + 128] = tolower(uc);
        compat_toupper_storage[c + 128] = toupper(uc);
    }
}

int *__errno(void) {
    return &errno;
}

int __system_property_get(const char *name, char *value) {
    (void)name;
    if (value) value[0] = '\0';
    return 0;
}

int __android_log_print(int priority, const char *tag, const char *fmt, ...) {
    (void)priority;
    va_list ap;
    fprintf(stderr, "[libamp:%s] ", tag ? tag : "?");
    va_start(ap, fmt);
    int result = vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return result;
}

uint64_t android_getCpuFeatures(void) { return 0; }
int android_getCpuFamily(void) { return 1; }
int android_getCpuCount(void) { return 1; }
