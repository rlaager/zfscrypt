#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <string.h>
#include <syslog.h>

#include "zfscrypt_context.h"
#include "zfscrypt_dataset.h"
#include "zfscrypt_err.h"
#include "zfscrypt_session.h"
#include "zfscrypt_utils.h"

/*
 * Stores authentication token in pam data
 */
extern int pam_sm_authenticate(pam_handle_t* handle, int flags, int argc, const char** argv) {
    zfscrypt_context_t context;
    zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
    if (!err.value)
        err = zfscrypt_context_drop_privs(&context);
    if (!err.value)
        err = zfscrypt_context_persist_token(&context);
    if (context.privs.is_dropped)
        (void) zfscrypt_context_regain_privs(&context);
    return zfscrypt_context_end(&context, err);
}

/*
 * No-op
 *
 * In this function we check that the user is allowed in the system. We already know
 * that he's authenticated, but we could apply restrictions based on time of the day,
 * resources in the system etc.
 */
extern int pam_sm_acct_mgmt(unused pam_handle_t* handle, unused int flags, unused int argc, unused const char** argv) {
    return PAM_IGNORE;
}

/*
 * No-op
 *
 * We could have many more information of the user other then password and username.
 * These are the credentials. For example, a kerberos ticket. Here we establish those
 * and make them visible to the application.
 */
extern int pam_sm_setcred(unused pam_handle_t* handle, unused int flags, unused int argc, unused const char** argv) {
    return PAM_IGNORE;
}

/*
 * Counts active sessions, reads authentication token from pam data, executes zfs load-key and zfs mount
 *
 * When the application wants to open a session, this function is called. Here we should
 * build the user environment (setting environment variables, mounting directories etc).
 */
extern int pam_sm_open_session(pam_handle_t* handle, int flags, int argc, char const** argv) {
    zfscrypt_context_t context;
    zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
    int counter = 0;
    const char* token = NULL;
    if (!err.value) {
        err = zfscrypt_context_log_err(
            &context,
            zfscrypt_session_counter_update(&counter, context.runtime_dir, context.user, +1));
    }
    if (counter == 1) {
        // This is the first session for the user. Unlock and mount the filesystems.
        if (!err.value)
            err = zfscrypt_context_drop_privs(&context);
        if (!err.value)
            err = zfscrypt_context_restore_token(&context, &token);
        if (!err.value)
            err = zfscrypt_dataset_unlock_all(&context, token);
        if (context.privs.is_dropped)
            (void) zfscrypt_context_regain_privs(&context);
    }
    (void) zfscrypt_context_clear_token(&context);
    return zfscrypt_context_end(&context, err);
}

/*
 * Counts active sessions, executes zfs umount and zfs unload-key, drops logsystem caches
 *
 * Here we destroy the environment we have created above.
 */
extern int pam_sm_close_session(pam_handle_t* handle, int flags, int argc, char const** argv) {
    zfscrypt_context_t context;
    zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
    int counter = 0;
    if (!err.value) {
        err = zfscrypt_context_log_err(
            &context,
            zfscrypt_session_counter_update(&counter, context.runtime_dir, context.user, -1));
    }
    if (counter == 0) {
	/* The last session has been closed. Unmount and lock the filesystems. */
        if (!err.value)
            err = zfscrypt_context_drop_privs(&context);
        if (!err.value)
            err = zfscrypt_dataset_lock_all(&context);
        if (context.privs.is_dropped)
            (void) zfscrypt_context_regain_privs(&context);
        (void) drop_filesystem_cache();
    }
    return zfscrypt_context_end(&context, err);
}

/*
 * Reads authentication token from pam data, executes zfs change-key
 *
 * This function is called to change the authentication token. Here we should,
 * for example, change the user password with the new password.
 */
extern int pam_sm_chauthtok(pam_handle_t* handle, int flags, int argc, char const** argv) {
    if (flags & PAM_PRELIM_CHECK) {
        // Should return PAM_TRY_AGAIN if not all pre requirements for changing the password are met
        return PAM_SUCCESS;
    }
    if (flags & PAM_UPDATE_AUTHTOK) {
        zfscrypt_context_t context;
        zfscrypt_err_t err = zfscrypt_context_begin(&context, handle, flags, argc, argv);
        const char* old_token = NULL;
        const char* new_token = NULL;
        if (!err.value)
            err = zfscrypt_context_drop_privs(&context);
        if (!err.value)
            err = zfscrypt_context_get_tokens(&context, &old_token, &new_token);
        // FIXME passwd updates the login password even if this module fails intentionally here
        if (!err.value && strlen(new_token) < 8)
            err = zfscrypt_err_pam(PAM_AUTHTOK_ERR, "ZFS encryption requires a minimum password length of eight characters");
        if (!err.value)
            err = zfscrypt_dataset_update_all(&context, old_token, new_token);
        if (context.privs.is_dropped)
            (void) zfscrypt_context_regain_privs(&context);
        return zfscrypt_context_end(&context, err);
    }
    return PAM_IGNORE;
}
