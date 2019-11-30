#pragma once
#include "zfscrypt_err.h"

// public functions

zfscrypt_err_t zfscrypt_session_counter_update(int* result, const char* base_dir, const char* file_name, const int delta);
