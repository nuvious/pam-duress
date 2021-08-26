#include "util.h"

unsigned long get_file_size(FILE *fp)
{
    unsigned long ret = 0;
    rewind(fp);
    fseek(fp, 0L, SEEK_END);
    ret = ftell(fp);
    rewind(fp);
    return ret;
}

char *get_hash_filename(const char *filepath)
{
    size_t hash_filename_len = strlen(filepath) + strlen(SIGNATURE_EXTENSION);
    char *hash_filename = malloc(hash_filename_len + 1);
    memcpy(hash_filename, filepath, strlen(filepath));
    memcpy(hash_filename + strlen(filepath), SIGNATURE_EXTENSION, strlen(SIGNATURE_EXTENSION));
    hash_filename[hash_filename_len] = 0;
    return hash_filename;
}

const char *get_filename_ext(const char *filename)
{
    const char *ret = filename;
    const char *dot;
    do
    {
        dot = strrchr(ret, '.');
        if (dot == ret || dot == NULL)
            break;
        ret = dot;
    } while (dot);
    return ret + 1;
}

void write_file_hash(const char *filepath, unsigned char *hash)
{
    FILE *fileptr;
    char *hash_filename = get_hash_filename(filepath);
    fileptr = fopen(hash_filename, "wb");
    if (fileptr == NULL)
    {
        printf("ERROR WRITING HASH FILE %s!", hash_filename);
        free(hash_filename);
        exit(-1);
    }
    fwrite(hash, 1, SHA256_DIGEST_LENGTH, fileptr);
    fclose(fileptr);
    free(hash_filename);
}

char *get_full_path(const char *directory, const char *filename)
{
    size_t len = strlen(directory) + strlen(filename) + 2;
    char *fp = malloc(len);
    memcpy(fp, directory, strlen(directory));
    fp[strlen(directory)] = '/';
    memcpy(fp + strlen(directory) + 1, filename, strlen(filename));
    fp[len - 1] = 0;
    return fp;
}

char *get_local_config_dir(const char *user_name)
{
    struct passwd *pwd = (struct passwd *) calloc(1, sizeof(struct passwd));
    if (pwd == NULL)
    {
        syslog(LOG_INFO, "Failed to allocate struct passwd for getpwnam_r.\n");
        exit(1);
    }
    size_t buffer_len = sysconf(_SC_GETPW_R_SIZE_MAX) * sizeof(char);
    char *buffer = malloc(buffer_len);
    if (buffer == NULL)
    {
        syslog(LOG_INFO, "Failed to allocate buffer for getpwnam_r.\n");
        exit(2);
    }
    getpwnam_r(user_name, pwd, buffer, buffer_len, &pwd);
    if (pwd == NULL)
    {
        syslog(LOG_INFO, "getpwnam_r failed to find requested entry.\n");
        exit(3);
    }

    free(buffer);
    const char *home_dir = pwd->pw_dir;
    size_t final_path_len = strlen(home_dir) + strlen(LOCAL_CONFIG_DIR_SUFFIX) + 1;
    char *config_dir = malloc(final_path_len); // + 2 for null at the end and additonal / character.
    memcpy(config_dir, home_dir, strlen(home_dir));
    memcpy(config_dir + strlen(home_dir), LOCAL_CONFIG_DIR_SUFFIX, strlen(LOCAL_CONFIG_DIR_SUFFIX));
    config_dir[final_path_len - 1] = 0;

    return config_dir;
}

unsigned char *sha_256_sum(const char *payload, size_t payload_size, const char *salt, size_t salt_size)
{
    unsigned char salt_hash[SHA256_DIGEST_LENGTH];
    SHA256(salt, salt_size, salt_hash);
    unsigned char *payload_hash = malloc(SHA256_DIGEST_LENGTH);
    char *salted_pass = malloc(SHA256_DIGEST_LENGTH + payload_size);
    memcpy(salted_pass, salt_hash, SHA256_DIGEST_LENGTH);
    memcpy(salted_pass + SHA256_DIGEST_LENGTH, payload, payload_size);
    SHA256(salted_pass, SHA256_DIGEST_LENGTH + payload_size, payload_hash);
    free(salted_pass);
    return payload_hash;
}
