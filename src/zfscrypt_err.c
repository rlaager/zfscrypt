#include "zfscrypt_err.h"

#include <assert.h>
#include <libzfs.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

zfscrypt_err_t zfscrypt_err_os_create(const int value, const char* message, const char* file, const int line, const char* function) {
    return (zfscrypt_err_t) {
        .type = ZFSCRYPT_ERR_OS,
        .value = abs(value),
        .description = strerror(abs(value)),
        .message = message,
        .file = file,
        .line = line,
        .function = function,
    };
}

zfscrypt_err_t zfscrypt_err_pam_create(const int value, const char* message, const char* file, const int line, const char* function) {
    return (zfscrypt_err_t) {
        .type = ZFSCRYPT_ERR_PAM,
        .value = abs(value),
        // This is safe because pam_strerror never wants to uses the first argument, see https://github.com/linux-pam/linux-pam/blob/master/libpam/pam_strerror.c
        .description = pam_strerror(NULL, abs(value)),
        .message = message,
        .file = file,
        .line = line,
        .function = function,
    };
}

zfscrypt_err_t zfscrypt_err_zfs_create(const int value, const char* message, const char* file, const int line, const char* function) {
    // FIXME This is the implementation of the ugly libzfs_handle workaround.
    libzfs_dummy_t dummy;
    dummy.libzfs_error = abs(value);
    dummy.libzfs_desc[0] = '\0';
    zfscrypt_err_t err = {
        .type = ZFSCRYPT_ERR_ZFS,
        .value = abs(value),
        .description = libzfs_error_description((libzfs_handle_t*) &dummy),
        .message = message,
        .file = file,
        .line = line,
        .function = function,
    };
    return err;
}

int zfscrypt_err_for_pam(zfscrypt_err_t err) {
    if (err.value == 0)
        return PAM_SUCCESS;
    switch (err.type) {
    case ZFSCRYPT_ERR_OS:
    case ZFSCRYPT_ERR_ZFS:
        return PAM_SYSTEM_ERR;
    case ZFSCRYPT_ERR_PAM:
        return err.value;
    default:
        // unreachable
        return PAM_SYSTEM_ERR;
    }
}
