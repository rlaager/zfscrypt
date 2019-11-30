#pragma once
#include <libzfs.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <stdbool.h>

#include "zfscrypt_err.h"

typedef struct zfscrypt_context {
    pam_handle_t* pam;
    libzfs_handle_t* libzfs;
    bool debug;
    const char* runtime_dir;
    const char* user;
    struct pam_modutil_privs privs;
    gid_t groups[PAM_MODUTIL_NGROUPS];
} zfscrypt_context_t;

// public methods

zfscrypt_err_t zfscrypt_context_begin(zfscrypt_context_t* self, pam_handle_t* handle, int flags, int argc, const char** argv);

int zfscrypt_context_end(zfscrypt_context_t* self, zfscrypt_err_t err);

void zfscrypt_context_log(zfscrypt_context_t* self, const int level, const char* format, ...);

// function itself does not fail, always returns err argument
zfscrypt_err_t zfscrypt_context_log_err(zfscrypt_context_t* self, zfscrypt_err_t err);

// gets token from pam items and stores it in pam data
zfscrypt_err_t zfscrypt_context_persist_token(zfscrypt_context_t* self);

// gets token from pam data, fallback to interactive input
zfscrypt_err_t zfscrypt_context_restore_token(zfscrypt_context_t* self, const char** token);

// deletes token from pam data
zfscrypt_err_t zfscrypt_context_clear_token(zfscrypt_context_t* self);

// gets tokens from pam data
zfscrypt_err_t zfscrypt_context_get_tokens(zfscrypt_context_t* self, const char** old_token, const char** new_token);

zfscrypt_err_t zfscrypt_context_drop_privs(zfscrypt_context_t* self);
zfscrypt_err_t zfscrypt_context_regain_privs(zfscrypt_context_t* self);

// private methods

void zfscrypt_parse_args(zfscrypt_context_t* self, int argc, const char** argv);

zfscrypt_err_t zfscrypt_context_pam_get_user(zfscrypt_context_t* self, const char** user);

zfscrypt_err_t zfscrypt_context_pam_items_get_token(zfscrypt_context_t* self, const char** token);
zfscrypt_err_t zfscrypt_context_pam_items_get_old_token(zfscrypt_context_t* self, const char** token);
zfscrypt_err_t zfscrypt_context_pam_ask_token(zfscrypt_context_t* self, const char** token);
zfscrypt_err_t zfscrypt_context_pam_get_tokens(zfscrypt_context_t* self, const char** old_token, const char** new_token);

zfscrypt_err_t zfscrypt_context_pam_data_set_token(zfscrypt_context_t* self, const char* token);
zfscrypt_err_t zfscrypt_context_pam_data_get_token(zfscrypt_context_t* self, const char** token);
zfscrypt_err_t zfscrypt_context_pam_data_clear_token(zfscrypt_context_t* self);

// private constants

extern const char ZFSCRYPT_CONTEXT_ARG_DEBUG[];
extern const char ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR[];
extern const size_t ZFSCRYPT_CONTEXT_ARG_RUNTIME_DIR_LEN;
