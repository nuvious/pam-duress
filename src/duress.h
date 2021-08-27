#define DEBUG

#ifndef DURESS_H_
#define DURESS_H_
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include "util.h"
#include <dirent.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef DEBUG
#include <stdarg.h>
#endif /* DEBUG */

/*
 *Logging wrapper for syslog with DEBUG compile flag wrapper.
 */
void dbg_log(int priority, const char *fmt, ...);

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv);

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv);

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);

int is_valid_duress_file(const char *filepath, const char *pam_pass);

int process_dir(const char *directory, const char *pam_user, const char *pam_pass, const char *run_as_user);

int execute_duress_scripts(const char *pam_user, const char *pam_pass);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv);

pid_t run_shell_as(const char *pam_user, const char *run_as_user, char *script);

#endif /* DURESS_H_ */