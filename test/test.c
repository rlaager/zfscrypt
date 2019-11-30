#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_POOL "tank"
#define TEST_USER "tester"
#define TEST_PASSWORD "passw0rd"
#define TEST_NEW_PASSWORD "12345678"
#define TEST_BASE_DIR "/tmp/zfscrypt-test"

#define TEST_HOME_DIR TEST_BASE_DIR "/home"
#define TEST_MOUNTPOINT TEST_HOME_DIR "/" TEST_USER
#define TEST_DATASET_PARENT TEST_POOL "/zfscrypt-test"
#define TEST_DATASET TEST_DATASET_PARENT "/" TEST_USER
#define TEST_RUNTIME_DIR TEST_BASE_DIR "/run"
#define TEST_RUNTIME_FILE TEST_RUNTIME_DIR "/" TEST_USER

#define assert(expr) \
    if (!(expr)) { \
        printf("%s:%d:%s: assertion failed: %s\n", __FILE__, __LINE__, __func__, #expr); \
        exit(1); \
    }

#define pam_assert(expr) \
    do { \
        const int status = (expr); \
        if (status != PAM_SUCCESS) { \
            printf("%s:%d:%s: assertion failed: error: %s: %s\n", __FILE__, __LINE__, __func__, pam_strerror(NULL, status), #expr); \
            exit(1); \
        } \
    } while (0)

#define system_assert(command) \
    if (system_assert_impl((command)) != 0) { \
        printf("%s:%d:%s: assertion failed: %s\n", __FILE__, __LINE__, __func__, (command)); \
        exit(1); \
    }

#define system_assert_not(command) \
    if (system_assert_impl((command)) == 0) { \
        printf("%s:%d:%s: assertion failed: %s\n", __FILE__, __LINE__, __func__, (command)); \
        exit(1); \
    }

int system_run(const char* command) {
    printf("%s\n", command);
    return system(command);
}

void setup() {
    system_run("mkdir -p " TEST_HOME_DIR " " TEST_RUNTIME_DIR);
    system_run("zfs create -o mountpoint=" TEST_HOME_DIR " " TEST_DATASET_PARENT);
    system_run("echo " TEST_PASSWORD " | zfs create -o io.github.benkerry:zfscrypt_user=" TEST_USER " -o encryption=on -o keylocation=prompt -o keyformat=passphrase -o canmount=noauto " TEST_DATASET);
    system_run("zfs mount " TEST_DATASET_PARENT);
    system_run("zfs mount " TEST_DATASET);
    system_run("useradd --no-user-group --home-dir " TEST_MOUNTPOINT " --create-home " TEST_USER);
    system_run("zfs allow -u " TEST_USER " load-key,change-key,mount " TEST_DATASET);
    system_run("echo " TEST_USER ":" TEST_PASSWORD " | chpasswd");
}

void teardown() {
    system_run("zfs umount " TEST_DATASET);
    system_run("zfs unload-key " TEST_DATASET);
    system_run("zfs destroy " TEST_DATASET);
    system_run("zfs destroy " TEST_DATASET_PARENT);
    system_run("userdel " TEST_USER);
    system_run("rm -rf " TEST_BASE_DIR);
}

int system_assert_impl(const char* command) {
    const int rc = system_run(command);
    if (rc < 0) {
        printf("assertion failed: system error: %s\n", strerror(errno));
        return -1;
    } else if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    } else {
        printf("assertion failed: command did not exit correctly\n");
        return -1;
    }
}

char* message_style_to_str(const int style) {
    switch (style) {
    case PAM_PROMPT_ECHO_OFF:
        return "PAM_PROMPT_ECHO_OFF";
    case PAM_PROMPT_ECHO_ON:
        return "PAM_PROMPT_ECHO_ON";
    case PAM_TEXT_INFO:
        return "PAM_TEXT_INFO";
    case PAM_ERROR_MSG:
        return "PAM_ERROR_MSG";
    default:
        return "UNKNOWN";
    }
}

typedef struct test_data {
    const char* user;
    const char* token;
    const char* new_token;
} test_data_t;

int conversation_counter = 0;

static int pamtester_conv(const int num_messages, const struct pam_message** messages, struct pam_response** result, void* raw_data) {
    if (num_messages <= 0)
        return PAM_CONV_ERR;
    struct pam_response* responses = malloc(num_messages * sizeof(struct pam_response));
    if (result == NULL)
        return PAM_BUF_ERR;
    test_data_t* data = raw_data;
    for (int i = 0; i < num_messages; i++) {
        char* response = NULL;
        const char* message = messages[i]->msg;
        const int style = messages[i]->msg_style;
        switch (style) {
        case PAM_PROMPT_ECHO_ON:
            printf("conversation failed: unknown message '%s' of known style PAM_PROMPT_ECHO_ON\n", message);
            goto error;
        case PAM_PROMPT_ECHO_OFF:
            if (strcmp(message, "Password: ") == 0) {
                response = strdup(data->token);
            } else if (strcmp(message, "New password: ") == 0) {
                response = strdup(data->new_token);
            } else if (strcmp(message, "Retype new password: ") == 0) {
                response = strdup(data->new_token);
            } else {
                printf("conversation failed: unknown message '%s' with known style PAM_PROMPT_ECHO_OFF\n", message);
                goto error;
            }
            printf("conversation: replying to message '%s' (PAM_PROMPT_ECHO_OFF) with '%s'\n", message, response);
            break;
        case PAM_TEXT_INFO:
            printf("conversation: info: %s\n", message);
            break;
        case PAM_ERROR_MSG:
            printf("conversation: error: %s\n", message);
            break;
        default:
            printf("conversation failed: unknown message '%s' with unknown style %d\n", message, style);
            goto error;
        }
        responses[i].resp = response;
        responses[i].resp_retcode = 0;
    }
    *result = responses;
    return PAM_SUCCESS;
error:
    free(responses);
    return PAM_CONV_ERR;
}

int get_session_counter() {
    FILE* file = fopen(TEST_RUNTIME_FILE, "r");
    assert(file != NULL);
    int value = -1;
    assert(fscanf(file, "%d", &value) >= 0);
    assert(fclose(file) >= 0);
    assert(value >= 0);
    return value;
}

void test_session_handling(const test_data_t* data, const struct pam_conv* conv) {
    const int flags = 0;
    pam_handle_t* handle1 = NULL;
    pam_assert(pam_start("login", data->user, conv, &handle1));
    pam_assert(pam_authenticate(handle1, flags));
    pam_assert(pam_open_session(handle1, flags));
    assert(get_session_counter() == 1);
    system_assert("zfs mount | grep -q ^" TEST_DATASET);
    pam_handle_t* handle2 = NULL;
    pam_assert(pam_start("login", data->user, conv, &handle2));
    pam_assert(pam_authenticate(handle2, flags));
    pam_assert(pam_open_session(handle2, flags));
    assert(get_session_counter() == 2);
    system_assert("zfs mount | grep -q ^" TEST_DATASET);
    pam_assert(pam_close_session(handle1, flags));
    pam_assert(pam_end(handle1, PAM_SUCCESS));
    assert(get_session_counter() == 1);
    system_assert("zfs mount | grep -q ^" TEST_DATASET);
    pam_assert(pam_close_session(handle2, flags));
    pam_assert(pam_end(handle2, PAM_SUCCESS));
    assert(get_session_counter() == 0);
    system_assert_not("zfs mount | grep -q ^" TEST_DATASET);
}

void test_password_change(const test_data_t* data, const struct pam_conv* conv) {
    const int flags = 0;
    pam_handle_t* handle = NULL;
    pam_assert(pam_start("passwd", data->user, conv, &handle));
    pam_assert(pam_chauthtok(handle, flags));
    pam_assert(pam_end(handle, PAM_SUCCESS));
    system_run("zfs umount " TEST_DATASET);
    system_run("zfs unload-key " TEST_DATASET);
    system_assert("echo " TEST_NEW_PASSWORD " | zfs load-key " TEST_DATASET);
}

typedef void (*test_f)(const test_data_t* data, const struct pam_conv* conv);

void run_test(test_f test, const test_data_t* data, const struct pam_conv* conv) {
    teardown();
    setup();
    test(data, conv);
    teardown();
}

int main() {
    test_data_t data = {.user = TEST_USER, .token = TEST_PASSWORD, .new_token = TEST_NEW_PASSWORD};
    const struct pam_conv conv = {.conv = pamtester_conv, .appdata_ptr = &data};
    run_test(test_session_handling, &data, &conv);
    run_test(test_password_change, &data, &conv);
    printf("\033[32mAll tests passed!\033[0m\n");
    return 0;
}
