#include <security/pam_appl.h>

/* macOS uses openpam. https://stackoverflow.com/a/66853251 */
#ifdef   OPENPAM
#include <security/openpam.h>
#define  USE_CONV_FUNC  openpam_ttyconv
#else
#include <security/pam_misc.h>
#define  USE_CONV_FUNC  misc_conv
#endif

#include <stdlib.h>
#include <stdio.h>
#include "version.h"

const struct pam_conv conv = {
	USE_CONV_FUNC,
	NULL};

int main(int argc, char *argv[])
{
	pam_handle_t *pamh = NULL;
	int retval;
	const char *user = "nobody";

	if (argc != 2)
	{
		printf("Usage: app [username]\n");
		exit(1);
	}

	user = argv[1];

	retval = pam_start("check_user", user, &conv, &pamh);

	/* Are the credentials correct? */
	if (retval == PAM_SUCCESS)
	{
		printf("Credentials accepted.\n");
		retval = pam_authenticate(pamh, 0);
	}

	/* Can the account be used at this time? */
	if (retval == PAM_SUCCESS)
	{
		printf("Account is valid.\n");
		retval = pam_acct_mgmt(pamh, 0);
	}

	/* Did everything work? */
	if (retval == PAM_SUCCESS)
	{
		printf("Authenticated\n");
	}
	else
	{
		printf("Not Authenticated\n");
	}

	/* close PAM (end session) */
	if (pam_end(pamh, retval) != PAM_SUCCESS)
	{
		pamh = NULL;
		printf("check_user: failed to release authenticator\n");
		exit(1);
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}
