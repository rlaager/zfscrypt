#pragma once
#include <libzfs.h>
#include <stdbool.h>

#include "zfscrypt_context.h"
#include "zfscrypt_err.h"

typedef struct zfscrypt_dataset {
    zfscrypt_context_t* context;
    zfs_handle_t* handle;
    const char* key;
    const char* new_key;
} zfscrypt_dataset_t;

typedef zfscrypt_err_t (*zfscrypt_dataset_iter_f)(zfscrypt_dataset_t*);

typedef struct zfscrypt_dataset_iter {
    zfscrypt_context_t* context;
    zfscrypt_dataset_iter_f callback;
    const char* key;
    const char* new_key;
} zfscrypt_dataset_iter_t;

// public functions

zfscrypt_err_t zfscrypt_dataset_lock_all(zfscrypt_context_t* context);
zfscrypt_err_t zfscrypt_dataset_unlock_all(zfscrypt_context_t* context, const char* key);
zfscrypt_err_t zfscrypt_dataset_update_all(zfscrypt_context_t* context, const char* old_key, const char* new_key);

// private methods, high level

bool zfscrypt_dataset_locked(zfscrypt_dataset_t* self);
bool zfscrypt_dataset_unlocked(zfscrypt_dataset_t* self);

zfscrypt_err_t zfscrypt_dataset_lock(zfscrypt_dataset_t* self);
zfscrypt_err_t zfscrypt_dataset_unlock(zfscrypt_dataset_t* self);
zfscrypt_err_t zfscrypt_dataset_update(zfscrypt_dataset_t* self);

// private methods, low level

bool zfscrypt_dataset_key_loaded(zfscrypt_dataset_t* self);

int zfscrypt_dataset_load_key(zfscrypt_dataset_t* self);
int zfscrypt_dataset_unload_key(zfscrypt_dataset_t* self);
int zfscrypt_dataset_change_key(zfscrypt_dataset_t* self);

bool zfscrypt_dataset_mounted(zfscrypt_dataset_t* self);

int zfscrypt_dataset_mount(zfscrypt_dataset_t* self);
int zfscrypt_dataset_unmount(zfscrypt_dataset_t* self);

// private methods, validation

int zfscrypt_dataset_properties_get_user(zfscrypt_dataset_t* self, const char** user);
bool zfscrypt_dataset_has_matching_user(zfscrypt_dataset_t* self);
bool zfscrypt_dataset_has_mountpoint(zfscrypt_dataset_t* self);
bool zfscrypt_dataset_can_mount(zfscrypt_dataset_t* self);
bool zfscrypt_dataset_is_encrypted(zfscrypt_dataset_t* self);
bool zfscrypt_dataset_does_prompt(zfscrypt_dataset_t* self);
bool zfscrypt_dataset_has_passphrase(zfscrypt_dataset_t* self);

bool zfscrypt_dataset_valid(zfscrypt_dataset_t* self);

// private functions, iteration

int zfscrypt_dataset_filesystem_visitor(zfs_handle_t* handle, void* data);
int zfscrypt_dataset_root_visitor(zfs_handle_t* handle, void* data);

zfscrypt_err_t zfscrypt_dataset_iter(zfscrypt_context_t* context, const char* key, const char* new_key, zfscrypt_dataset_iter_f callback);

// private constants

extern const char ZFSCRYPT_USER_PROPERTY[];

// FIXME Copied from /usr/include/libzfs/sys/zio.h because including <sys/zio.h> results in compiler error about unknown type rlim64_t
enum zio_encrypt {
    ZIO_CRYPT_INHERIT = 0,
    ZIO_CRYPT_ON,
    ZIO_CRYPT_OFF,
    ZIO_CRYPT_AES_128_CCM,
    ZIO_CRYPT_AES_192_CCM,
    ZIO_CRYPT_AES_256_CCM,
    ZIO_CRYPT_AES_128_GCM,
    ZIO_CRYPT_AES_192_GCM,
    ZIO_CRYPT_AES_256_GCM,
    ZIO_CRYPT_FUNCTIONS
};
