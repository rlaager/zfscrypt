#pragma once
#include <stdint.h>

#define zfscrypt_err_os(value, message) zfscrypt_err_os_create((value), (message), __FILE__, __LINE__, __func__)

#define zfscrypt_err_pam(value, message) zfscrypt_err_pam_create((value), (message), __FILE__, __LINE__, __func__)

#define zfscrypt_err_zfs(value, message) zfscrypt_err_zfs_create((value), (message), __FILE__, __LINE__, __func__)

typedef enum zfscrypt_err_type {
    ZFSCRYPT_ERR_OS,
    ZFSCRYPT_ERR_PAM,
    ZFSCRYPT_ERR_ZFS
} zfscrypt_err_type;

typedef struct zfscrypt_err {
    zfscrypt_err_type type;
    int value;
    const char* description;
    const char* message;
    const char* file;
    int line;
    const char* function;
} zfscrypt_err_t;

zfscrypt_err_t zfscrypt_err_os_create(const int value, const char* message, const char* file, const int line, const char* function);
zfscrypt_err_t zfscrypt_err_pam_create(const int value, const char* message, const char* file, const int line, const char* function);
zfscrypt_err_t zfscrypt_err_zfs_create(const int value, const char* message, const char* file, const int line, const char* function);

int zfscrypt_err_for_pam(zfscrypt_err_t err);

// FIXME Binary compatible dummy of libzfs_handle_t, because fields of libzfs_handle struct are unknown to compiler and importing <libzfs_impl.h> which defines libzfs_handle results in compiler error about missing <sys/zfs_ioctl.h> header.
typedef struct libzfs_dummy {
    int libzfs_error;
    int dummy_1;
    void* dummy_2;
    void* dummy_3;
    void* dummy_4;
    void* dummy_5;
    void* dummy_6;
    uint64_t dummy_7;
    int dummy_8;
    char dummy_9[1024];
    char libzfs_desc[1024];
} libzfs_dummy_t;
