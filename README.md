# zfscrypt

zfscrypt implements a [Linux Pluggable Authentication Module](https://github.com/linux-pam/linux-pam) that encrypts users home directories with their login password leveraging [ZFS](https://github.com/zfsonlinux/zfs) native encryption. The concept was heavily inspired by Google's [fscrypt](https://github.com/google/fscrypt).

> **Warning:** This is my first project written in C. It might contain severe security issues.

## Setup

Check that ZFS v0.8.0 or later is installed.

~~~ sh
zfs -V
~~~

Build and install the PAM module.

~~~ sh
make
make install
~~~

Unfortunately PAM configuration is a bit of a mess, beacuse every distribution configures PAM differently. So chances are high that you have to adapt the follwing example to your distribution.

> **Note:** Tested on Arch Linux with pam v1.3.1 and zfs v0.8.2.

Append the following line to the `auth` section in `/etc/pam.d/system-login`:

~~~ pam
auth optional pam_zfscrypt.so
~~~

And append this two lines to the `session` section:

~~~ pam
session [success=1 default=ignore] pam_succeed_if.so service = systemd-user quiet
session optional pam_zfscrypt.so
~~~

The first line is needed to work around some quirks in systemd (more info [here](https://wiki.archlinux.org/index.php/Pam_mount)).

Finally append the next line to `etc/pam.d/passwd`:

~~~ pam
password optional pam_zfscrypt.so
~~~

Having problems with PAM? Maybe one of this Arch Wiki pages can help you: [pam](https://wiki.archlinux.org/index.php/PAM), [fscrypt](https://wiki.archlinux.org/index.php/Fscrypt)

## Usage

All datasets with the following properties will be automatically unlocked when the corresponding user logs in (and locked after logout).

| Property                           | Value        |
|------------------------------------|--------------|
| `io.github.benkerry:zfscrypt_user` | user name    |
| `encryption`                       | not `off`    |
| `keyformat`                        | `passphrase` |
| `keylocation`                      | `prompt`     |
| `canmount`                         | not `off`    |

### Create a new user with zfscrypt

The encryption key and the login password must be the same, otherwise automatic unlocking won't work. Future password changes will update the encryption key automatically.

~~~ sh
zfs create -o mountpoint=/home tank/home
zfs create -o io.github.benkerry:zfscrypt_user=ben -o encryption=on -o keyformat=passphrase -o keylocation=prompt -o canmount=noauto tank/home/ben
zfs mount tank/home
zfs mount tank/home/ben
useradd --create-home ben
zfs allow -u ben load-key,change-key,mount tank/home/ben 
passwd ben
~~~

### Migrate an existing user to zfscrypt

~~~ sh
mv /home/ben /home/_ben
zfs create -o io.github.benkerry:zfscrypt_user=ben -o encryption=on -o keyformat=passphrase -o keylocation=prompt -o canmount=noauto -o mountpoint=/home/ben tank/home/ben
zfs allow -u ben load-key,change-key,mount tank/home/ben
zfs mount tank/home/ben
chown ben:ben /home/ben
chmod 0700 /home/ben
cp -ar /home/_ben/. /home/ben/
rm -rf /home/_ben
~~~
