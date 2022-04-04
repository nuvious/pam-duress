#include "duress.h"

/*
 *Logging wrapper for syslog with DEBUG compile flag wrapper.
 */
void dbg_log(int priority, const char *fmt, ...) {
#ifdef DEBUG
  va_list ap;
  va_start(ap, fmt);
  vsyslog(priority, fmt, ap);
  va_end(ap);
#endif /* DEBUG */
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  return (PAM_SUCCESS);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char **argv) {
  return (PAM_SUCCESS);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  return (PAM_SUCCESS);
}

int is_valid_duress_file(const char *filepath, const char *pam_pass) {
  if (access(filepath, R_OK) != 0) {
    dbg_log(LOG_INFO, "User does not have read access to %s.", filepath);
    return 0;
  }

  if (access(filepath, X_OK) != 0) {
    dbg_log(LOG_INFO, "User does not have execute access to %s.", filepath);
    return 0;
  }

  struct stat st;
  if (stat(filepath, &st) == -1) {
    dbg_log(LOG_ERR, "Error stating file %s.", filepath);
    return 0;
  }

  dbg_log(LOG_INFO, "REG: %d, SYM: %d, DIR: %d\n", S_ISREG(st.st_mode),
          S_ISLNK(st.st_mode), S_ISDIR(st.st_mode));

  /* Ensure it's a file */
  if (!(S_ISREG(st.st_mode))) {
    dbg_log(LOG_INFO, "Not a regular file or simlink.\n");
    return 0;
  }

  /* Ensure duress file has a signature file with the appended extension */
  const char *ext = get_filename_ext(filepath);
  if (!strcmp(ext, SIGNATURE_EXTENSION)) {
    dbg_log(LOG_INFO, "Is a signature file.\n");
    return 0;
  }

  /* Allowed permissions are 500, 540, and 550
     Ensure file is readable and executable by the user. */
  if ((st.st_mode & S_IRUSR) == 0) {
    dbg_log(LOG_INFO, "Improper permissions. USR R\n");
    return 0;
  }
  if ((st.st_mode & S_IXUSR) == 0) {

    dbg_log(LOG_INFO, "Improper permissions. USR X\n");

    return 0;
  }
  /* Ensure public permissions are not allowed and group can't write. */
  if (st.st_mode & S_IWGRP) {
    dbg_log(LOG_INFO, "Improper permissions. GRP W\n");
    return 0;
  }
  if (st.st_mode & S_IROTH) {
    dbg_log(LOG_INFO, "Improper permissions. PUB R\n");
    return 0;
  }
  if (st.st_mode & S_IWOTH) {
    dbg_log(LOG_INFO, "Improper permissions. PUB W\n");
    return 0;
  }
  if (st.st_mode & S_IXOTH) {
    dbg_log(LOG_INFO, "Improper permissions. PUB X\n");
    return 0;
  }

  /* Ensure a coresponding signature file exists */
  char *hash_file = get_hash_filename(filepath);
  struct stat st_hash;
  if (stat(hash_file, &st_hash) == -1) {
    dbg_log(LOG_ERR, "Error reading hash file, %s\n", strerror(errno));
    return 0;
  }

  /* Load the hash */

  dbg_log(LOG_INFO, "Loading hash file %s, %d...\n", hash_file,
          SHA256_DIGEST_LENGTH);

  unsigned char *hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
  FILE *hashfileptr;
  hashfileptr = fopen(hash_file, "rb");
  if (hashfileptr == NULL) {
    dbg_log(LOG_ERR, "Error reading %s, %d...\n", hash_file, st.st_size);
    free(hash);
    return 0;
  }
  fread(hash, 1, SHA256_DIGEST_LENGTH, hashfileptr);
  fclose(hashfileptr);
  free(hash_file);

  /* Load the duress executable */
  unsigned char *file_bytes = (unsigned char *)malloc(st.st_size);
  FILE *fileptr;
  fileptr = fopen(filepath, "rb");
  if (fileptr == NULL) {
    dbg_log(LOG_ERR, "Error reading %s, %d...\n", filepath, st.st_size);
    free(file_bytes);
    free(hash);
    return 0;
  }

  dbg_log(LOG_INFO, "Reading %s, %d...\n", filepath, st.st_size);

  fread(file_bytes, 1, st.st_size, fileptr);

  dbg_log(LOG_INFO, "Done\n");

  fclose(fileptr);

  /* compute the hash and compare it to the stored hash. */

  dbg_log(LOG_INFO, "Computing duress hash...");

  unsigned char *duress_hash =
      sha_256_sum(pam_pass, strlen(pam_pass), file_bytes, st.st_size);

  int result = 1;
  if (memcmp(hash, duress_hash, SHA256_DIGEST_LENGTH)) {
    dbg_log(LOG_INFO, "Hash mismatch\n");
    free(hash);
    free(file_bytes);
    return 0;
  }

  free(hash);
  free(file_bytes);

  return result;
}

int process_dir(const char *directory, const char *pam_user,
                const char *pam_pass, const char *run_as_user) {
  int ret = 0;
  struct dirent *de;

  DIR *dr = opendir(directory);

  dbg_log(LOG_INFO, "Processing %s.\n", directory);

  if (dr == NULL) {
    dbg_log(LOG_ERR, "Could not open directory %s, %s.\n", directory, strerror(errno));
    return ret;
  }

  while ((de = readdir(dr)) != NULL) {
    char *fpath = get_full_path(directory, de->d_name);

    dbg_log(LOG_INFO, "Processing file %s...\n", fpath);

    if (is_valid_duress_file(fpath, pam_pass)) {

      dbg_log(LOG_INFO, "File is valid.\n");

      if (run_as_user != NULL) {
        run_shell_as(pam_user, run_as_user, fpath);
      } else {
        run_shell_as(pam_user, "root", fpath);
      }
      ret = 1;
    }
    free(fpath);
  }

  closedir(dr);
  return ret;
}

int execute_duress_scripts(const char *pam_user, const char *pam_pass) {
  // Run user level first
  int local_duress_run = 0;
  char *local_config_dir = get_local_config_dir(pam_user);
  if (local_config_dir != NULL)
    local_duress_run = process_dir(local_config_dir, pam_user, pam_pass, pam_user);

  /* 
   * Run global next; allows a duress script to be generated to uninstall
   * pam-duress
   */
  int global_duress_run =
      process_dir(GLOBAL_CONFIG_DIR, pam_user, pam_pass, NULL);

  if (global_duress_run || local_duress_run)
    return PAM_SUCCESS;
  else
    return PAM_IGNORE;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  const char *pam_user;
  const char *pam_pass;
  int pam_err;

  pam_err = pam_get_user(pamh, &pam_user, 0);
  dbg_log(LOG_ERR, "PAM ERROR: %d\n", pam_err);
  if (pam_err != PAM_SUCCESS)
    return PAM_IGNORE;
  pam_err = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pam_pass);
  dbg_log(LOG_ERR, "PAM ERROR: %d\n", pam_err);
  if (pam_err != PAM_SUCCESS)
    return PAM_IGNORE;

  return execute_duress_scripts(pam_user, pam_pass);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return (PAM_SUCCESS);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  return (PAM_SUCCESS);
}

pid_t run_shell_as(const char *pam_user, const char *run_as_user, char *script) {
    if (pam_user == NULL)
      return -1;

    pid_t pid = fork();
    char *script_args[] = {};

    switch (pid) {
        case 0: {
#ifndef DEBUG
            /* Redirect sderr and sdout to /dev/null */
            int fd = open("/dev/null", O_WRONLY | O_CREAT, 0666);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
#endif //DEBUG

            /* get user information struct */
            struct passwd *run_as_pw = getpwnam(run_as_user);

            /* set PAMUSER environment variable for use in /etc/duress.d scripts */
            if (setenv(PAM_USER_ENV_VAR_NAME, pam_user, 1)) {
                dbg_log(LOG_ERR, "Could not set environment for PAMUSER to %s, %s.\n", pam_user, strerror(errno));
                goto child_failed;
            }

            if (!run_as_pw) {
                dbg_log(LOG_ERR, "Could not getpwnam %s, %s.\n", run_as_user, strerror(errno));
                goto child_failed;
            }

            /* set the group first; calls to setuid lock out the ability to call setgid */
            if (setgid(run_as_pw->pw_gid)) {
                dbg_log(LOG_ERR, "Could not setgid, %s.\n", strerror(errno)); 
                goto child_failed;
            }
            /* call setuid */
            if (setuid(run_as_pw->pw_uid)) {
                dbg_log(LOG_ERR, "Could not setuid, %s.\n", strerror(errno)); 
                goto child_failed;
            }

            /* execute the command */
            dbg_log(LOG_DEBUG, "Executing %s.", script);
            execv(script, script_args);

        child_failed:
            dbg_log(LOG_ERR, "Could not run script %s, %s.\n", script, strerror(errno));
            exit(1);
            break;
        }
        case -1:
            dbg_log(LOG_ERR, "Could not fork for script %s, %s\n", script, strerror(errno));
            break;
        default:
            break;
    }
    return pid;
}
