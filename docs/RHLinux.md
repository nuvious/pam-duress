# Pam Duress on Red Hat variants

This is a guide on how to use pam duress on Red Hat linux in support of
[Issue 51](https://github.com/nuvious/pam-duress/issues/51) on GitHub
submitted by [radioaddition](https://github.com/radioaddition).

## Installation 

### Dependencies

For the dependencies arch packages the development libraries with openssl
so your dependencies look more like the below:

```bash
# Redhat family dependencies
sudo dnf group install development-tools -y
sudo dnf install pam-devel -y
```

### Build and Install

As noted in [Issue 51](https://github.com/nuvious/pam-duress/issues/51), the
location of PAM so libraries is in `/usr/lib64/security` in Red Hat variants so
we simply need to set that in the installation command:

```bash
make
sudo make install PAM_DIR=/usr/lib64/security
make clean
```

## Configuration

Much of the pam configurations all eventually point to /etc/system-auth
which has many more entries than say a Debian distribution. Below was taken
from a Fedora Live 41 instance as an example, but your specific RedHat variant
may be different. In this example, you'll need to modify the configuration as
follows:

### /etc/pam.d/system-auth

Change system-auth from this:

```bash
...
auth       required                    pam_env.so
auth       required                    pam_faildelay.so delay=2000000
auth       sufficient                  pam_unix.so nullok
auth       required                    pam_deny.so
...
```

To this:

```bash
...
auth       required                    pam_env.so
auth       required                    pam_faildelay.so delay=2000000
auth       sufficient                  pam_unix.so nullok
auth       sufficient                  pam_duress.so
auth       required                    pam_deny.so
...
```

## Testing

The `pam_test` doesn't work the same in Red Hat variants as it does in debian
so to test the configuration you'll simply need to run the following:

```
sudo su # Drop into a root shell
login [USERNAME WITH CONFIGURED DURESS]
```

After login with a configured duress password, you should see the effects of
your test applied. 

## Remaining Configuration

All further configurations regarding creation, signing and permissions for
duress scripts are the same, so continue in the
[configuration section of the README](../README.md#configuration) to continue
setting up duress scripts.
