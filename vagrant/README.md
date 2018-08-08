# Vagrant Box for TREES 

This vagrant box is meant for testing. Do not use in production.

It will provision a working postfix, dovecot, TREES setup, 
including some pre-defined users (see below). 

## What does it do?

This box creates a test environment for TREES. Therefore it executes the following 
steps:

- initialize the system
- setup [mariadb](https://mariadb.org/) with a predefined database, which includes test users 
- setup [postfix](http://www.postfix.org/) 
	- with domain trees.testing 
- setup [dovecot](https://www.dovecot.org/)
	- add ARGON2 support for dovecot 2.2.* via [dovecot-libsodium-plugin](https://github.com/LuckyFellow/dovecot-libsodium-plugin/) 
- setup TREES
	- add TREES support for dovecot 
	- install ruby environment and ruby gems, which are required for 
	  using the trees-create script

## Requirements

To use this box you need the following software:

- [Ansible](https://www.ansible.com/) (>= 2.4)
- [VirtualBox](https://www.virtualbox.org/) 
- [Vagrant](https://www.vagrantup.com/)

## Usage

Initial Setup:

```
git clone https://0xacab.org/riseuplabs/trees
cd trees/vagrant
vagrant up
```

Reprovisioning:

```
cd trees/vagrant
vagrant provision
```

## Pre-defined values

The database is populated with two pre-defined users:

```
user: admin@trees.testing
password: PASSWORD
trees_enabled: False
```

```
user: treesenabled@trees.testing
password: PASSWORD
trees_enabled: True
```

### Using your own values

The pre-defined values in the database, can be created inside the box. 
For populating the database with your own values, you have to run the 
following commands. Replace those values in the database scheme and reset the 
database. Database can be reset by setting `reset_db: True` in `playbook.yml` and
running `vagrant provision`. 

**Note:** The password you choose when creating a user, must be the same password
that you use, when you run `trees-create` for that user!

#### Change a users password:

The user password is a hashed string in the databse table `virtual_users` 
in the column `password`. You can create your own values by executing:

  ```
	vagrant@trees:~$ doveadm pw -s argon2
    Enter new password: 
    Retype new password: 
    {ARGON2}$argon2i$v=19$m=32768,t=4,p=1$VPxyrzkhN0JuCXbnNpFlFw$mpbQ0QqdQZA/v+M9znnQwMd3DX3WDYM5utPeTOcX39U
 
    
    # do not copy "{ARGON2}"
  ```

#### Change a users TREES values:

The TREES values are defined in the table `virtual_storage_keys`. You can 
generate your custom values, by running the following commands and inserting the
output into the database

  ```
    vagrant@trees:~$ cd /opt/local/sources/trees/bin/
    vagrant@trees:/opt/local/sources/trees/bin$ ./trees-create --password PASSWORD
    
    {
      "public_key": "b7b151873bb7c14de89ffcf34e1e4a7af2843f9becce9da0f7738a93480ae63f",
      "locked_secretbox": "869ddac34b3afab6e138d7a82b4b93b13aec046f340e4a78d5b44644ad86cf11179473de16a9080bf5261ec406f82889",
      "sk_nonce": "634c29520f376fff514d68b372d497d0eb5b62c14fb84b68",
      "pwhash_opslimit": "4",
      "pwhash_memlimit": "33554432",
      "pwhash_salt": "5c13b1144ad120d6ca275e01b43c61d9"
    }

  ``` 

# Playbook Variables:

The playbook is executed with the following variables:

```
- hosts: all
  become: true
  vars:
    extra_packages:
      - mailutils
    # trees.testing
    dovecot_mail_name: "{{ inventory_hostname }}"
    dovecot_libsodium_plugin:
      repo:
        url: https://github.com/LuckyFellow/dovecot-libsodium-plugin/
        path: /opt/local/sources/dovecot-libsodium-plugin
    mysql:
      database: mailserver
      user: mailserver
      user_password: treesftw
      reset_db: False
    # trees.testing
    postfix_mail_name: "{{ inventory_hostname }}"
    postfix_mynetwork: "{{ ansible_default_ipv4.network }}/24"
    trees:
      repo:
        url: https://0xacab.org/riseuplabs/trees
        path: /opt/local/sources/trees/
        # specify latest release, e.g. v2.1.0
        # or use the commit hash sum to clone specific commit
        release: "HEAD"
      pwhash_algo: 0
      # pwhash_algo:
      # 0 for libsodium <= 1.0.14 (Debian Stretch Package)
      #  - install libsodium from normal debian repos (current version 1.0.12)
      #  - uses ARGON2
  roles:
    - init
    - mariadb
    - postfix
    - dovecot
    - trees
```

## Testing the setup

Does it really work? Run the following commands, to see if TREES is running 
correctly:

```
	# After provisioning
	user@laptop:~$ vagrant ssh
	
	# become root
	vagrant@trees:~$ sudo -i
	
	# send testmail
	root@trees:~# echo "That's a trees encryption test" | mail -s "A trees test" treesenabled@trees.testing

	# check if you can read this plain text mail
	root@trees:~# sudo less /var/vmail/trees.testing/treesenabled/Maildir/new/1531471288.M934119P25665.trees\,S\=870\,W\=447 
	"/var/vmail/trees.testing/treesenabled/Maildir/new/1531471288.M934119P25665.trees,S\=870,W\=447" may be a binary file.  See it anyway? 

	# login via IMAP
	root@trees:~# telnet localhost 143

	# login as treesenabled via IMAP command
	a login "treesenabled@trees.testing" "PASSWORD"
	
	# Select your INBOX via IMAP command
	1 SELECT INBOX
	
	# Read Mail via IMAP command
	2 FETCH 1 BODY[TEXT]
	
	# Command output with decrypted mail
    * 1 FETCH (FLAGS (\Seen \Recent) BODY[TEXT] {32}
    That's a trees encryption test
    )
    2 OK Fetch completed (0.004 + 0.000 + 0.003 secs).

```

## Current limitations 

  * this box does not work with pwhash_algo 1 (libsodium > 1.0.15) yet 
    (will be implemented in the future)
  * dovecot indexes won't be disabled yet
  * users are hardcoded in the database, should be moved to a script

  