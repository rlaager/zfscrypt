#pragma once
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdio.h>

// public macros

#define defer(destructor) __attribute__((__cleanup__(destructor)))
#define unused __attribute__((unused))

// public functions

void free_ptr(void* data);
void close_file(FILE** file);
void close_fd(int const* fd);

bool streq(const char* a, const char* b);
bool strnq(const char* a, const char* b);

char* strfmt(const char* format, ...);

int make_private_dir(const char* path);

int open_exclusive(const char* path, const int flags);

// Instructs kernel to free reclaimable inodes and dentries. This has the effect of making encrypted datasets whose keys are not present no longer accessible. Requires root privileges.
int drop_filesystem_cache();

void* secure_dup(void const* const data);
void secure_cleanup(pam_handle_t* handle, void* data, int error_status);
