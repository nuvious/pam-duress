#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
//#define DEBUG

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <openssl/sha.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <dirent.h>
#include <syslog.h>
#include "util.h"

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
      return (PAM_SUCCESS);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
      return (PAM_SUCCESS);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
      return (PAM_SUCCESS);
}

int is_valid_duress_file(const char *filepath, const char *pam_pass)
{
      if (access(filepath, R_OK) != 0)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "User does not have read access to %s.", filepath);
#endif //DEBUG
            return 0;
      }

      if (access(filepath, X_OK) != 0)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "User does not have execute access to %s.", filepath);
#endif //DEBUG
            return 0;
      }

      struct stat st;
      if (stat(filepath, &st) == -1)
      {
            syslog(LOG_ERR, "Error stating file %s.", filepath);
            return 0;
      }

#ifdef DEBUG
      syslog(LOG_INFO, "REG: %d, SYM: %d, DIR: %d\n", S_ISREG(st.st_mode), S_ISLNK(st.st_mode), S_ISDIR(st.st_mode));
#endif //DEBUG

      // Ensure it's a file
      if (!(S_ISREG(st.st_mode)))
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Not a regular file or simlink.\n");
#endif //DEBUG
            return 0;
      }

      //Ensure duress file has a signature file with the appended extension
      const char *ext = get_filename_ext(filepath);
      if (!strcmp(ext, SIGNATURE_EXTENSION))
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Is a signature file.\n");
#endif //DEBUG
            return 0;
      }

      // Allowed permisions are 500, 700, 540, 550 and 770
      // Ensure file is readable and executable by the user.
      if (st.st_mode & S_IRUSR == 0)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. USR R\n");
#endif //DEBUG
            return 0;
      }
      if (st.st_mode & S_IWUSR)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. USR W\n");
#endif //DEBUG
            return 0;
      }
      if (st.st_mode & S_IXUSR == 0)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. USR X\n");
#endif //DEBUG
            return 0;
      }

      // Ensure public permissions are not allowed and group can't write.
      if (st.st_mode & S_IWGRP)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. GRP W\n");
#endif //DEBUG
            return 0;
      }
      if (st.st_mode & S_IROTH)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. PUB R\n");
#endif //DEBUG
            return 0;
      }
      if (st.st_mode & S_IWOTH)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. PUB W\n");
#endif //DEBUG
            return 0;
      }
      if (st.st_mode & S_IXOTH)
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Improper permissions. PUB X\n");
#endif //DEBUG
            return 0;
      }

      //Ensure a coresponding signature file exists
      char *hash_file = get_hash_filename(filepath);
      struct stat st_hash;
      if (stat(hash_file, &st_hash) == -1)
      {
            syslog(LOG_ERR, "Error reading hash file.\n");
            return 0;
      }

      //Load the hash
#ifdef DEBUG
      syslog(LOG_INFO, "Loading hash file %s, %d...\n", hash_file, SHA256_DIGEST_LENGTH);
#endif //DEBUG
      unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
      FILE *hashfileptr;
      hashfileptr = fopen(hash_file, "rb");
      if (hashfileptr == NULL)
      {
#ifdef DEBUG
            syslog(LOG_ERR, "Error reading %s, %d...\n", hash_file, st.st_size);
#endif //DEBUG
            return 0;
      }
      fread(hash, 1, SHA256_DIGEST_LENGTH, hashfileptr);
      fclose(hashfileptr);
      free(hash_file);
      // Output the hash

      //Load the durress executable
      unsigned char *file_bytes = malloc(st.st_size);
      FILE *fileptr;
      fileptr = fopen(filepath, "rb");
      if (fileptr == NULL)
      {
#ifdef DEBUG
            syslog(LOG_ERR, "Error reading %s, %d...\n", filepath, st.st_size);
#endif //DEBUG
            return 0;
      }
#ifdef DEBUG
      syslog(LOG_INFO, "Reading %s, %d...\n", filepath, st.st_size);
#endif //DEBUG
      fread(file_bytes, 1, st.st_size, fileptr);
#ifdef DEBUG
      syslog(LOG_INFO, "Done\n");
#endif //DEBUG
      fclose(fileptr);

      //compute the hash and compare it to the stored hash.
#ifdef DEBUG
      syslog(LOG_INFO, "Computing durress hash...");
#endif //DEBUG
      unsigned char *duress_hash = sha_256_sum(pam_pass, strlen(pam_pass), file_bytes, st.st_size);

#ifdef DEBUG
      syslog(LOG_INFO, "Loaded Hash: ");
      for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
      {
            syslog(LOG_INFO, "%02X", hash[i]);
      }
      syslog(LOG_INFO, "\n");
      // Output the hash
      syslog(LOG_INFO, "Computed Hash: ");
      for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
      {
            syslog(LOG_INFO, "%02X", duress_hash[i]);
      }
      syslog(LOG_INFO, "\n");
#endif //DEBUG

      int result = 1;
      if (memcmp(hash, duress_hash, SHA256_DIGEST_LENGTH))
      {
#ifdef DEBUG
            syslog(LOG_INFO, "Hash mismatch\n");
#endif
            return 0;
      }

      free(hash);
      free(file_bytes);

      return result;
}

int process_dir(const char *directory, const char *pam_user, const char *pam_pass)
{
      int ret = 0;
      struct dirent *de;

      DIR *dr = opendir(directory);
#ifdef DEBUG
      syslog(LOG_INFO, "Processing %s.\n", directory);
#endif //DEBUG

      if (dr == NULL)
      {
            syslog(LOG_ERR, "Could not open directory %s, %d.\n", directory, errno);
            return ret;
      }

      while ((de = readdir(dr)) != NULL)
      {
            char *fpath = get_full_path(directory, de->d_name);
#ifdef DEBUG
            syslog(LOG_INFO, "Processing file %s...\n", fpath);
#endif //DEBUG
            if (is_valid_duress_file(fpath, pam_pass))
            {
                  syslog(LOG_INFO, "File is valid.\n");
                  char *cmd = malloc(strlen(pam_user) + strlen(SHELL_CMD) + strlen(fpath) + 21);
                  if (sprintf(cmd, "export PAMUSER=%s; %s %s", pam_user, SHELL_CMD, fpath) < 0)
                  {
                        syslog(LOG_ERR, "Failed to format command. %s %s\n", SHELL_CMD, fpath);
                  }
                  else
                  {
#ifdef DEBUG
                        syslog(LOG_INFO, "Running command %s\n", cmd);
#endif //DEBUG
                        int status = system(cmd);
                        ret = 1;
                  }
                  free(cmd);
            }
            free(fpath);
      }

      closedir(dr);
      return ret;
}

int execute_duress_scripts(const char *pam_user, const char *pam_pass)
{
      int ret = PAM_IGNORE;

      int global_duress_run = process_dir(GLOBAL_CONFIG_DIR, pam_user, pam_pass);
      int local_duress_run = process_dir(get_local_config_dir(pam_user), pam_user, pam_pass);

      if (global_duress_run || local_duress_run)
            return PAM_SUCCESS;
      else
            return PAM_IGNORE;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
      const char *pam_user;
      const char *pam_pass;
      const char *pam_service;
      int pam_err;

      pam_err = pam_get_user(pamh, &pam_user, 0);
      syslog(LOG_ERR, "PAM ERROR: %d\n", pam_err);
      if (pam_err != PAM_SUCCESS)
            return PAM_IGNORE;
      pam_err = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pam_pass);
      syslog(LOG_ERR, "PAM ERROR: %d\n", pam_err);
      if (pam_err != PAM_SUCCESS)
            return PAM_IGNORE;

      return execute_duress_scripts(pam_user, pam_pass);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
      return (PAM_SUCCESS);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
      return (PAM_SUCCESS);
}