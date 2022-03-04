#include "util.h"

int main(int argc, const char *argv[])
{
    if (argc != 2)
    {
        printf("Usage:\n\tduress_sign [FILENAME]\n");
        return EINVAL;
    }
    else
    {
        /* Get the password and copy it to a separate buffer.
           get_pass uses a single buffer so calling it twice
           in a row will just return the same buffer which will then
           hold the second password entered in the confirmation,
           resulting in the strcmp always returning 0 */
        char *p = getpass("Password: ");
        char *password = malloc(strlen(p) + 1);
        memccpy(password, p, 1, strlen(p) + 1);

        /* Confirm the password */
        char *confirm = getpass("Confirm: ");

        /* Compare the password */
        if (strcmp(password, confirm) != 0)
        {
            printf("Password did not match. Aborting.\n");
            return EINVAL;
        }
        else
        {
            /* Read in the file to be signed */
            struct stat st;
            if (stat(argv[1], &st) == -1)
                return EINVAL;
            unsigned char *file_bytes = malloc(st.st_size);
            FILE *fileptr;
            fileptr = fopen(argv[1], "rb");
            if (fileptr == NULL)
            {
                printf("Error opening file %s.", argv[1]);
                free(file_bytes);
                return EINVAL;
            }
            printf("Reading %s, %ld...\n", argv[1], st.st_size);
            fread(file_bytes, 1, st.st_size, fileptr);
            printf("Done\n");
            fclose(fileptr);

            /* Use the file as the salt for the password hash */
            unsigned char *hash = sha_256_sum(password, strlen(password), file_bytes, st.st_size);

            /* Don't need the file bytes anymore so clean those up */
            free(file_bytes);

            /* Output the hash */
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            {
                printf("%02X", hash[i]);
            }
            printf("\n");

            /* Write the hash to [FILE].sha256 */
            write_file_hash(argv[1], hash);

            /* Free up the hash allocation */
            free(hash);
        }

        /* Free up the password allocation */
        free(password);
        return 0;
    }
}
