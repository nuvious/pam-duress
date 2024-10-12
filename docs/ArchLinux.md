# Pam Duress on Arch

This is a guide on how to use pam duress on Arch linux in support of
[Issue 29](https://github.com/nuvious/pam-duress/issues/29) on GitHub
submitted by [Dusan Lesan](https://github.com/DusanLesan).

## Installation 

### Dependencies

For the dependencies arch packages the development libraries with openssl
so your dependencies look more like the below:

```bash
sudo pacman -Su
sudo pacman --needed -S base-devel openssl
```

### Build and Install

The build and installation steps remain the same.

```bash
make
sudo make install
make clean
```

## Configuration

Much of the pam configurations all eventually point to /etc/system-auth
which has many more entries than say a Debian distribution. To employ
pam-duress you'll need to modify the configuration as follows:


### /etc/pam.d/system-auth

Change system-auth from this:

```bash
...
-auth      [success=3 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
...
```

To this:

```bash
...
-auth      [success=3 default=ignore]  pam_systemd_home.so
auth       [success=2 default=ignore]  pam_unix.so          try_first_pass nullok
auth	   [success=1 default=bad]     pam_duress.so
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
...
```

What's going on under the hood is after `pam_unix` fails in the default
configuration it passess off to `pam_faillock` which keeps track of the number
of failed logins to lock out accounts. By switching `pam_unix` to default to
ignore and putting `pam_duress` after with the default action of bad.

Per [PAM's documentation](http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html)
the definition of 'bad' in this instance is:

```
bad
	this action indicates that the return code should be thought of as indicative
of the module failing. If this module is the first in the stack to fail, its status
value will be used for that of the whole stack.
```

This is in contrast to ignore:

```
ignore
	when used with a stack of modules, the module's return status will not
contribute to the return code the application obtains.
```

With Arch's initial intent to be a return of bad on a bad password we want
that behavior to carry forward but we do not want `pam_unix` to make the whole
stack fail and rather handle `pam_duress` and defer failures to it. This
preserves the desired behavior of dropping the person entering the duress
password into a normal authenticated shell without recording any failed
password entries in `pam_faillock`.

## NOTE: Use ssh instead of pam_test

Though `pam_test` is a part of this repo it doesn't seem to be effective on
on Arch system; see [Issue 29](https://github.com/nuvious/pam-duress/issues/29).

Instead of using `pam_test` use `ssh USER@localhost`. This will simulate a
remote login and should trigger the full duress chain.

## Remaining Configuration

All further configurations regarding creation, signing and permissions for
duress scripts are the same, so continue in the
[configuration section of the README](../README.md#configuration) to continue
setting up duress scripts.

