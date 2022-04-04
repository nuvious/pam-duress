#ifndef UTIL_H_
#define UTIL_H_

#include <openssl/sha.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "version.h"

unsigned long get_file_size(FILE *fp);

static const char *SIGNATURE_EXTENSION = ".sha256";

/* Directory in a users home directory that will contain local duress scripts and signatures. */
static const char *LOCAL_CONFIG_DIR_SUFFIX = "/.duress";

/* Directory that contains common duress codes and signature files. */
static const char *GLOBAL_CONFIG_DIR = "/etc/duress.d";

static char *SHELL_CMD = "/bin/sh";

char *get_full_path(const char *directory, const char *filename);

char *get_hash_filename(const char *filepath);

const char *get_filename_ext(const char *filename);

char *get_local_config_dir(const char *user_name);

void write_file_hash(const char *filepath, unsigned char *hash);

unsigned char *sha_256_sum(const char *payload, size_t payload_size, const unsigned char *salt, size_t salt_size);

#endif