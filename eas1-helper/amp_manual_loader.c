#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct {
    uint8_t *base;
    size_t size;
} loaded_image;

enum {
    HELPER_MAGIC = 0x31415345,
    OP_ENCRYPT_KEY = 1,
    OP_DECRYPT_KEY = 2,
    OP_RESET_CODEC = 3,
    OP_ENCODE = 4,
    OP_DECODE = 5,
};

typedef struct {
    uint32_t magic;
    uint32_t operation;
    uint32_t length;
} helper_request;

typedef struct {
    uint32_t magic;
    int32_t status;
    uint32_t length;
} helper_response;

static int read_full(int fd, void *buffer, size_t length) {
    uint8_t *cursor = buffer;
    while (length) {
        ssize_t count = read(fd, cursor, length);
        if (count == 0) return 0;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return 1;
}

static int write_full(int fd, const void *buffer, size_t length) {
    const uint8_t *cursor = buffer;
    while (length) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

static int run_helper_server(const loaded_image *image, const char *socket_path) {
    typedef void (*codec_dispatch_init_fn)(int architecture);
    typedef void (*key_transform_fn)(uint8_t key[30]);
    typedef void *(*encoder_create_fn)(int, int, int, int *);
    typedef int (*encoder_encode_fn)(void *, const int16_t *, int, uint8_t *, int);
    typedef void (*encoder_destroy_fn)(void *);
    typedef void *(*decoder_create_fn)(int, int, int *);
    typedef int (*decoder_decode_fn)(void *, const uint8_t *, int, int16_t *, int, int);
    typedef void (*decoder_destroy_fn)(void *);

    codec_dispatch_init_fn dispatch_init = (codec_dispatch_init_fn)(image->base + 0x151acc);
    key_transform_fn encrypt_key = (key_transform_fn)(image->base + 0x45625);
    key_transform_fn decrypt_key = (key_transform_fn)(image->base + 0x456bd);
    encoder_create_fn encoder_create = (encoder_create_fn)(image->base + 0x14dd78);
    encoder_encode_fn encoder_encode = (encoder_encode_fn)(image->base + 0x14de68);
    encoder_destroy_fn encoder_destroy = (encoder_destroy_fn)(image->base + 0x15026c);
    decoder_create_fn decoder_create = (decoder_create_fn)(image->base + 0x150fcc);
    decoder_decode_fn decoder_decode = (decoder_decode_fn)(image->base + 0x1519a4);
    decoder_destroy_fn decoder_destroy = (decoder_destroy_fn)(image->base + 0x151234);
    void *encoder = NULL;
    void *decoder = NULL;
    dispatch_init(0);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) return -1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) return -1;
    strcpy(address.sun_path, socket_path);
    unlink(socket_path);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(socket_path, 0660) != 0 || listen(server, 4) != 0) {
        close(server);
        return -1;
    }
    fprintf(stderr, "eas1 helper listening: %s\n", socket_path);

    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (;;) {
            helper_request request;
            int read_status = read_full(client, &request, sizeof(request));
            if (read_status <= 0) break;
            if (request.magic != HELPER_MAGIC || request.length > 4096) break;
            uint8_t input[4096];
            uint8_t output[4096];
            if (read_full(client, input, request.length) <= 0) break;
            int status = 0;
            uint32_t output_length = 0;

            if (request.operation == OP_ENCRYPT_KEY || request.operation == OP_DECRYPT_KEY) {
                if (request.length != 30) status = -10;
                else {
                    memcpy(output, input, 30);
                    if (request.operation == OP_ENCRYPT_KEY) encrypt_key(output);
                    else decrypt_key(output);
                    output_length = 30;
                }
            } else if (request.operation == OP_RESET_CODEC) {
                if (request.length != 0) status = -11;
                else {
                    if (encoder) encoder_destroy(encoder);
                    if (decoder) decoder_destroy(decoder);
                    int encoder_error = -1;
                    int decoder_error = -1;
                    encoder = encoder_create(16000, 1, 2048, &encoder_error);
                    decoder = decoder_create(16000, 1, &decoder_error);
                    if (!encoder || !decoder || encoder_error || decoder_error) status = -12;
                }
            } else if (request.operation == OP_ENCODE) {
                if (!encoder || request.length != 640) status = -20;
                else {
                    int encoded = encoder_encode(encoder, (const int16_t *)input, 320, output, 1500);
                    if (encoded <= 0 || encoded > 1500) status = encoded ? encoded : -21;
                    else output_length = (uint32_t)encoded;
                }
            } else if (request.operation == OP_DECODE) {
                if (!decoder || request.length == 0 || request.length > 1500) status = -30;
                else {
                    int decoded = decoder_decode(decoder, input, (int)request.length,
                                                 (int16_t *)output, 320, 0);
                    if (decoded <= 0 || decoded > 320) status = decoded ? decoded : -31;
                    else output_length = (uint32_t)decoded * 2;
                }
            } else {
                status = -40;
            }

            helper_response response = {HELPER_MAGIC, status, output_length};
            if (write_full(client, &response, sizeof(response)) != 0 ||
                (output_length && write_full(client, output, output_length) != 0)) break;
        }
        close(client);
    }
    if (encoder) encoder_destroy(encoder);
    if (decoder) decoder_destroy(decoder);
    close(server);
    unlink(socket_path);
    return -1;
}

static int eas1_roundtrip(const loaded_image *image) {
    typedef void (*codec_dispatch_init_fn)(int architecture);
    typedef void *(*encoder_create_fn)(int sample_rate, int channels, int application, int *error);
    typedef int (*encoder_encode_fn)(void *encoder, const int16_t *pcm, int samples,
                                     uint8_t *output, int output_size);
    typedef void (*encoder_destroy_fn)(void *encoder);
    typedef void *(*decoder_create_fn)(int sample_rate, int channels, int *error);
    typedef int (*decoder_decode_fn)(void *decoder, const uint8_t *input, int input_size,
                                     int16_t *pcm, int samples, int decode_fec);
    typedef void (*decoder_destroy_fn)(void *decoder);

    codec_dispatch_init_fn codec_dispatch_init = (codec_dispatch_init_fn)(image->base + 0x151acc);
    encoder_create_fn encoder_create = (encoder_create_fn)(image->base + 0x14dd78);
    encoder_encode_fn encoder_encode = (encoder_encode_fn)(image->base + 0x14de68);
    encoder_destroy_fn encoder_destroy = (encoder_destroy_fn)(image->base + 0x15026c);
    decoder_create_fn decoder_create = (decoder_create_fn)(image->base + 0x150fcc);
    decoder_decode_fn decoder_decode = (decoder_decode_fn)(image->base + 0x1519a4);
    decoder_destroy_fn decoder_destroy = (decoder_destroy_fn)(image->base + 0x151234);

    /* Select the portable ARM implementation; Android normally does this globally. */
    codec_dispatch_init(0);

    int encoder_error = -999;
    int decoder_error = -999;
    void *encoder = encoder_create(16000, 1, 2048, &encoder_error);
    void *decoder = decoder_create(16000, 1, &decoder_error);
    fprintf(stderr, "eas1 create: encoder=%p error=%d decoder=%p error=%d\n",
            encoder, encoder_error, decoder, decoder_error);
    if (!encoder || !decoder || encoder_error != 0 || decoder_error != 0) return -1;

    int16_t input[320];
    int16_t decoded[320];
    uint8_t packet[1500];
    for (unsigned i = 0; i < 320; ++i) {
        input[i] = ((i / 18) & 1) ? 10000 : -10000;
        decoded[i] = 0;
    }

    int packet_size = encoder_encode(encoder, input, 320, packet, sizeof(packet));
    fprintf(stderr, "eas1 encode: bytes=%d\n", packet_size);
    if (packet_size <= 0 || packet_size > (int)sizeof(packet)) return -1;

    int decoded_samples = decoder_decode(decoder, packet, packet_size, decoded, 320, 0);
    long long energy = 0;
    for (unsigned i = 0; i < 320; ++i) energy += (long long)decoded[i] * decoded[i];
    fprintf(stderr, "eas1 decode: samples=%d energy=%lld first=%d\n",
            decoded_samples, energy, decoded[0]);

    encoder_destroy(encoder);
    decoder_destroy(decoder);
    return decoded_samples == 320 && energy > 0 ? 0 : -1;
}

static int srtp_key_roundtrip(const loaded_image *image) {
    typedef void (*key_transform_fn)(uint8_t key[30]);
    key_transform_fn encrypt_key = (key_transform_fn)(image->base + 0x45625);
    key_transform_fn decrypt_key = (key_transform_fn)(image->base + 0x456bd);
    uint8_t original[30];
    uint8_t transformed[30];
    for (unsigned i = 0; i < sizeof(original); ++i) original[i] = (uint8_t)(i * 7 + 3);
    memcpy(transformed, original, sizeof(transformed));
    encrypt_key(transformed);
    int first_block_changed = memcmp(transformed, original, 16) != 0;
    int salt_unchanged = memcmp(transformed + 16, original + 16, 14) == 0;
    decrypt_key(transformed);
    int restored = memcmp(transformed, original, sizeof(original)) == 0;
    fprintf(stderr, "SRTP key transform: changed=%d saltUnchanged=%d restored=%d\n",
            first_block_changed, salt_unchanged, restored);
    return first_block_changed && salt_unchanged && restored ? 0 : -1;
}

static int load_global(const char *name) {
    void *handle = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "dependency %s: %s\n", name, dlerror());
        return -1;
    }
    return 0;
}

static void *resolve_symbol(const Elf32_Sym *sym, const char *name, uint8_t *base) {
    if (sym->st_shndx != SHN_UNDEF) return base + sym->st_value;
    dlerror();
    void *result = dlsym(RTLD_DEFAULT, name);
    const char *error = dlerror();
    if (!error) return result;
    if (ELF32_ST_BIND(sym->st_info) == STB_WEAK) return NULL;
    fprintf(stderr, "unresolved symbol: %s (%s)\n", name, error);
    return (void *)(uintptr_t)UINTPTR_MAX;
}

static int apply_relocations(
    uint8_t *base,
    size_t image_size,
    const uint8_t *file,
    size_t file_size,
    const Elf32_Ehdr *ehdr
) {
    const Elf32_Shdr *sections = (const Elf32_Shdr *)(file + ehdr->e_shoff);
    if (ehdr->e_shoff + (size_t)ehdr->e_shnum * sizeof(*sections) > file_size) return -1;

    size_t applied[256] = {0};
    for (unsigned section_index = 0; section_index < ehdr->e_shnum; ++section_index) {
        const Elf32_Shdr *rel_section = &sections[section_index];
        if (rel_section->sh_type != SHT_REL) continue;
        if (rel_section->sh_offset + rel_section->sh_size > file_size) return -1;
        if (rel_section->sh_link >= ehdr->e_shnum) return -1;

        const Elf32_Shdr *sym_section = &sections[rel_section->sh_link];
        if (sym_section->sh_type != SHT_DYNSYM || sym_section->sh_link >= ehdr->e_shnum) return -1;
        const Elf32_Shdr *str_section = &sections[sym_section->sh_link];
        if (sym_section->sh_offset + sym_section->sh_size > file_size) return -1;
        if (str_section->sh_offset + str_section->sh_size > file_size) return -1;

        const Elf32_Sym *symbols = (const Elf32_Sym *)(file + sym_section->sh_offset);
        size_t symbol_count = sym_section->sh_size / sizeof(*symbols);
        const char *strings = (const char *)(file + str_section->sh_offset);
        const Elf32_Rel *rels = (const Elf32_Rel *)(file + rel_section->sh_offset);
        size_t rel_count = rel_section->sh_size / sizeof(*rels);

        for (size_t i = 0; i < rel_count; ++i) {
            unsigned type = ELF32_R_TYPE(rels[i].r_info);
            unsigned symbol_index = ELF32_R_SYM(rels[i].r_info);
            if (rels[i].r_offset > image_size - sizeof(uint32_t)) return -1;
            uint32_t *where = (uint32_t *)(base + rels[i].r_offset);

            if (type == R_ARM_RELATIVE) {
                *where += (uint32_t)(uintptr_t)base;
            } else if (type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT) {
                if (symbol_index >= symbol_count) return -1;
                const Elf32_Sym *symbol = &symbols[symbol_index];
                if (symbol->st_name >= str_section->sh_size) return -1;
                const char *name = strings + symbol->st_name;
                void *address = resolve_symbol(symbol, name, base);
                if (address == (void *)(uintptr_t)UINTPTR_MAX) return -1;
                *where = (uint32_t)(uintptr_t)address;
            } else if (type != R_ARM_NONE) {
                fprintf(stderr, "unsupported relocation: %u\n", type);
                return -1;
            }
            if (type < 256) applied[type]++;
        }
    }

    fprintf(stderr, "relocations: relative=%zu glob=%zu jump=%zu\n",
            applied[R_ARM_RELATIVE], applied[R_ARM_GLOB_DAT], applied[R_ARM_JUMP_SLOT]);
    return 0;
}

static int load_image(const char *path, loaded_image *result) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat stat_buffer;
    if (fstat(fd, &stat_buffer) != 0 || stat_buffer.st_size < (off_t)sizeof(Elf32_Ehdr)) {
        close(fd);
        return -1;
    }
    size_t file_size = (size_t)stat_buffer.st_size;
    uint8_t *file = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file == MAP_FAILED) return -1;

    const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)file;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS32 || ehdr->e_machine != EM_ARM ||
        ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf32_Phdr) > file_size) {
        munmap(file, file_size);
        return -1;
    }

    const Elf32_Phdr *programs = (const Elf32_Phdr *)(file + ehdr->e_phoff);
    uint32_t maximum = 0;
    for (unsigned i = 0; i < ehdr->e_phnum; ++i) {
        if (programs[i].p_type != PT_LOAD) continue;
        uint64_t end = (uint64_t)programs[i].p_vaddr + programs[i].p_memsz;
        if (end > UINT32_MAX || programs[i].p_offset + programs[i].p_filesz > file_size) {
            munmap(file, file_size);
            return -1;
        }
        if (end > maximum) maximum = (uint32_t)end;
    }
    size_t image_size = (maximum + 4095u) & ~4095u;
    uint8_t *base = mmap(NULL, image_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        munmap(file, file_size);
        return -1;
    }

    for (unsigned i = 0; i < ehdr->e_phnum; ++i) {
        if (programs[i].p_type != PT_LOAD) continue;
        memcpy(base + programs[i].p_vaddr, file + programs[i].p_offset, programs[i].p_filesz);
        memset(base + programs[i].p_vaddr + programs[i].p_filesz, 0,
               programs[i].p_memsz - programs[i].p_filesz);
    }

    if (apply_relocations(base, image_size, file, file_size, ehdr) != 0) {
        munmap(base, image_size);
        munmap(file, file_size);
        return -1;
    }
    __builtin___clear_cache((char *)base, (char *)base + image_size);
    munmap(file, file_size);
    result->base = base;
    result->size = image_size;
    return 0;
}

int main(int argc, char **argv) {
    int server_mode = argc == 4 && strcmp(argv[1], "--server") == 0;
    if (argc != 2 && !server_mode) {
        fprintf(stderr, "usage: %s LIBAMP | --server SOCKET LIBAMP\n", argv[0]);
        return 2;
    }
    const char *library_path = server_mode ? argv[3] : argv[1];
    const char *dependencies[] = {
        "libm.so.6", "libdl.so.2", "libstdc++.so.6", "libGLESv2.so.2", "libgcc_s.so.1"
    };
    for (unsigned i = 0; i < sizeof(dependencies) / sizeof(dependencies[0]); ++i) {
        if (load_global(dependencies[i]) != 0) return 1;
    }

    loaded_image image = {0};
    if (load_image(library_path, &image) != 0) {
        fprintf(stderr, "manual load failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "manual load succeeded: base=%p size=%zu\n", image.base, image.size);

    typedef const char *(*codec_name_fn)(void);
    codec_name_fn codec_name = (codec_name_fn)(image.base + 0x2083d);
    const char *name = codec_name();
    fprintf(stderr, "codec name: %s\n", name ? name : "(null)");
    if (!name || strcmp(name, "eas1") != 0) _exit(1);
    if (server_mode) {
        int result = run_helper_server(&image, argv[2]);
        fprintf(stderr, "eas1 helper stopped: %s\n", strerror(errno));
        _exit(result == 0 ? 0 : 1);
    }
    int key_roundtrip = srtp_key_roundtrip(&image);
    fprintf(stderr, "SRTP key roundtrip: %s\n", key_roundtrip == 0 ? "PASS" : "FAIL");
    if (key_roundtrip != 0) _exit(1);
    int roundtrip = eas1_roundtrip(&image);
    fprintf(stderr, "eas1 roundtrip: %s\n", roundtrip == 0 ? "PASS" : "FAIL");
    _exit(roundtrip == 0 ? 0 : 1);
}
