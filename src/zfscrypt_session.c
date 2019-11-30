#include "zfscrypt_session.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "zfscrypt_utils.h"

// public functions

zfscrypt_err_t zfscrypt_session_counter_update(int* result, const char* base_dir, const char* file_name, const int delta) {
    int err = make_private_dir(base_dir);
    if (err)
        return zfscrypt_err_os(err, "Could not create private dir");

    defer(free_ptr) char* path = strfmt("%s/%s", base_dir, file_name);
    if (path == NULL)
        return zfscrypt_err_os(errno, "Memory allocation failed");
    const int fd = open_exclusive(path, O_RDWR | O_CLOEXEC | O_CREAT | O_NOFOLLOW);
    if (fd < 0)
        return zfscrypt_err_os(fd, "Could not open file exclusively");

    defer(close_file) FILE* file = fdopen(fd, "w+");
    if (file == NULL)
        return zfscrypt_err_os(errno, "Could not create file from fd");
    int value = 0;
    (void) fscanf(file, "%d", &value);
    value = value < 0 ? 0 : value;
    value += delta;
    value = value < 0 ? 0 : value;
    rewind(file);
    err = fprintf(file, "%d", value);
    if (err < 0)
        return zfscrypt_err_os(errno, "Could not write file");
    *result = value;
    return zfscrypt_err_os(0, "Updated session counter");
}
