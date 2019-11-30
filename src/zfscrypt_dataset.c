#include "zfscrypt_dataset.h"

#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zfscrypt_utils.h"

// Note regarding error handling with libzfs: Normally functions return directly an errno code, but zfs_(un)mount returns just -1 on error

// public functions

zfscrypt_err_t zfscrypt_dataset_lock_all(zfscrypt_context_t* context) {
    return zfscrypt_dataset_iter(context, NULL, NULL, zfscrypt_dataset_lock);
}

zfscrypt_err_t zfscrypt_dataset_unlock_all(zfscrypt_context_t* context, const char* key) {
    return zfscrypt_dataset_iter(context, key, NULL, zfscrypt_dataset_unlock);
}

zfscrypt_err_t zfscrypt_dataset_update_all(zfscrypt_context_t* context, const char* old_key, const char* new_key) {
    return zfscrypt_dataset_iter(context, old_key, new_key, zfscrypt_dataset_update);
}

// public methods

bool zfscrypt_dataset_locked(zfscrypt_dataset_t* self) {
    return !zfscrypt_dataset_key_loaded(self) && !zfscrypt_dataset_mounted(self);
}

bool zfscrypt_dataset_unlocked(zfscrypt_dataset_t* self) {
    return zfscrypt_dataset_key_loaded(self) && zfscrypt_dataset_mounted(self);
}

zfscrypt_err_t zfscrypt_dataset_lock(zfscrypt_dataset_t* self) {
    int err = 0;
    if (zfscrypt_dataset_mounted(self))
        err = zfscrypt_dataset_unmount(self);
    if (!err && zfscrypt_dataset_key_loaded(self))
        err = zfscrypt_dataset_unload_key(self);
    return zfscrypt_err_zfs(err, "Locked dataset");
}

zfscrypt_err_t zfscrypt_dataset_unlock(zfscrypt_dataset_t* self) {
    int err = 0;
    if (!zfscrypt_dataset_key_loaded(self))
        err = zfscrypt_dataset_load_key(self);
    if (!err && !zfscrypt_dataset_mounted(self))
        err = zfscrypt_dataset_mount(self);
    return zfscrypt_err_zfs(err, "Unlocked dataset");
}

zfscrypt_err_t zfscrypt_dataset_update(zfscrypt_dataset_t* self) {
    int err = 0;
    const bool loaded = zfscrypt_dataset_key_loaded(self);
    if (!loaded)
        err = zfscrypt_dataset_load_key(self);
    if (!err)
        err = zfscrypt_dataset_change_key(self);
    if (!loaded)
        (void) zfscrypt_dataset_unload_key(self);
    return zfscrypt_err_zfs(err, "Updated dataset key");
}

// private methods, locking and unlocking

bool zfscrypt_dataset_key_loaded(zfscrypt_dataset_t* self) {
    const int status = zfs_prop_get_int(self->handle, ZFS_PROP_KEYSTATUS);
    return status == ZFS_KEYSTATUS_AVAILABLE;
}

int zfscrypt_dataset_load_key(zfscrypt_dataset_t* self) {
    // libzfs does not provide an interface that simply takes a string as passphrase,
    // instead it wants to read the key from stdin itself (or from a file).
    int in_fds[2];
    pipe(in_fds);
    const pid_t pid = fork();
    if (pid < 0) {
        return -errno;
    } else if (pid == 0) {
        dup2(in_fds[0], STDIN_FILENO);
        close(in_fds[0]);
        close(in_fds[1]);
        // zfs_crypto_load_key(zfs_handle_t *zhp, boolean_t noop, char *alt_keylocation)
        const int err = zfs_crypto_load_key(self->handle, B_FALSE, NULL);
        exit(err);
    } else {
        close(in_fds[0]);
        write(in_fds[1], self->key, strlen(self->key));
        close(in_fds[1]);
        int rc = 0;
        const int pid2 = waitpid(pid, &rc, 0);
        return pid2 < 0 ? -errno : -WEXITSTATUS(rc);
    }
}

int zfscrypt_dataset_unload_key(zfscrypt_dataset_t* self) {
    return zfs_crypto_unload_key(self->handle);
}

int zfscrypt_dataset_change_key(zfscrypt_dataset_t* self) {
    // libzfs does not provide an direct interface to change datasets keys,
    // it always wants to read them from stdin itself.
    int in_fds[2];
    pipe(in_fds);
    const pid_t pid = fork();
    if (pid < 0) {
        return -errno;
    } else if (pid == 0) {
        dup2(in_fds[0], STDIN_FILENO);
        close(in_fds[0]);
        close(in_fds[1]);
        // zfs_crypto_rewrap(zfs_handle_t *zhp, nvlist_t *raw_props, boolean_t inheritkey)
        exit(zfs_crypto_rewrap(self->handle, NULL, B_FALSE));
    } else {
        close(in_fds[0]);
        write(in_fds[1], self->new_key, strlen(self->new_key));
        close(in_fds[1]);
        int rc;
        const int pid2 = waitpid(pid, &rc, 0);
        return pid2 < 0 ? -errno : -WEXITSTATUS(rc);
    }
}

bool zfscrypt_dataset_mounted(zfscrypt_dataset_t* self) {
    return zfs_is_mounted(self->handle, NULL);
}

int zfscrypt_dataset_mount(zfscrypt_dataset_t* self) {
    // zfs_mount(zfs_handle_t *zhp, const char *options, int flags)
    const int err = zfs_mount(self->handle, NULL, 0);
    return err < 0 ? libzfs_errno(self->context->libzfs) : 0;
}

int zfscrypt_dataset_unmount(zfscrypt_dataset_t* self) {
    // zfs_unmount(zfs_handle_t *zhp, const char *mountpoint, int flags)
    const int err = zfs_unmount(self->handle, NULL, 0);
    return err < 0 ? libzfs_errno(self->context->libzfs) : 0;
}

// private methods, validation

int zfscrypt_dataset_properties_get_user(zfscrypt_dataset_t* self, const char** user) {
    nvlist_t* props = zfs_get_user_props(self->handle);
    nvlist_t* prop = NULL;
    const int err = nvlist_lookup_nvlist(props, ZFSCRYPT_USER_PROPERTY, &prop);
    if (err)
        return err;
    return nvlist_lookup_string(prop, ZPROP_VALUE, (char**) user);
}

bool zfscrypt_dataset_has_matching_user(zfscrypt_dataset_t* self) {
    const char* user = NULL;
    const int err = zfscrypt_dataset_properties_get_user(self, &user);
    return !err && streq(user, self->context->user);
}

bool zfscrypt_dataset_has_mountpoint(zfscrypt_dataset_t* self) {
    char mountpoint[ZFS_MAXPROPLEN];
    const int err = zfs_prop_get(self->handle, ZFS_PROP_MOUNTPOINT, mountpoint, sizeof(mountpoint), NULL, NULL, 0, B_FALSE);
    return !err && strnq(mountpoint, ZFS_MOUNTPOINT_NONE);
}

bool zfscrypt_dataset_can_mount(zfscrypt_dataset_t* self) {
    const int canmount = zfs_prop_get_int(self->handle, ZFS_PROP_CANMOUNT);
    return canmount != ZFS_CANMOUNT_OFF;
}

bool zfscrypt_dataset_is_encrypted(zfscrypt_dataset_t* self) {
    const int encryption = zfs_prop_get_int(self->handle, ZFS_PROP_ENCRYPTION);
    return encryption != ZIO_CRYPT_OFF;
}

bool zfscrypt_dataset_does_prompt(zfscrypt_dataset_t* self) {
    // FIXME What's up with keylocation? Why does zfs_prop_get_int always return 0? Use enum ZFS_KEYLOCATION_PROMPT
    // int keylocation = 0;
    // err = zfs_prop_get_numeric(zfs_handle, ZFS_PROP_KEYLOCATION, &keylocation, NULL, NULL, 0);
    char keylocation[ZFS_MAXPROPLEN];
    const int err = zfs_prop_get(self->handle, ZFS_PROP_KEYLOCATION, keylocation, sizeof(keylocation), NULL, NULL, 0, B_TRUE);
    return !err && streq(keylocation, "prompt");
}

bool zfscrypt_dataset_has_passphrase(zfscrypt_dataset_t* self) {
    const int keyformat = zfs_prop_get_int(self->handle, ZFS_PROP_KEYFORMAT);
    return keyformat == ZFS_KEYFORMAT_PASSPHRASE;
}

bool zfscrypt_dataset_valid(zfscrypt_dataset_t* self) {
    return zfscrypt_dataset_has_matching_user(self) && zfscrypt_dataset_has_mountpoint(self) && zfscrypt_dataset_can_mount(self) && zfscrypt_dataset_is_encrypted(self) && zfscrypt_dataset_does_prompt(self) && zfscrypt_dataset_has_passphrase(self);
}

// private methods, iteration

int zfscrypt_dataset_filesystem_visitor(zfs_handle_t* handle, void* data) {
    zfscrypt_dataset_iter_t* iter = data;
    zfscrypt_dataset_t dataset = {.context = iter->context, .handle = handle, .key = iter->key, .new_key = iter->new_key};
    if (zfscrypt_dataset_valid(&dataset)) {
        const zfscrypt_err_t err = iter->callback(&dataset);
        zfscrypt_context_log_err(iter->context, err);
    }
    return zfs_iter_filesystems(handle, zfscrypt_dataset_filesystem_visitor, data);
}

int zfscrypt_dataset_root_visitor(zfs_handle_t* handle, void* data) {
    return zfs_iter_filesystems(handle, zfscrypt_dataset_filesystem_visitor, data);
}

zfscrypt_err_t zfscrypt_dataset_iter(zfscrypt_context_t* context, const char* key, const char* new_key, zfscrypt_dataset_iter_f callback) {
    zfscrypt_dataset_iter_t iter = {.context = context, .callback = callback, .key = key, .new_key = new_key};
    const int err = zfs_iter_root(context->libzfs, zfscrypt_dataset_root_visitor, &iter);
    return zfscrypt_err_zfs(err, "Iterated over all datasets");
}

// private constants

const int zfscrypt_dataset_iter_error_len = 32;
const char ZFSCRYPT_USER_PROPERTY[] = "io.github.benkerry:zfscrypt_user";
