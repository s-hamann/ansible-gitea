Gitea
=====

This role sets up and configures a [Gitea](https://gitea.io/) instance.
It supports official binaries from https://gitea.io/ or distribution-provided packages.
Local user accounts can be created on deployment.
It is also possible to configure external authentication sources.

Requirements
------------

Gitea versions older than 1.18.0 are not (fully) supported.
Depending on the exact configuration, they may or may not work.

If TLS encryption (i.e. HTTPS) is desired, the target system needs to have a suitable X.509 certificate.
This roles does not handle deploying certificates.

Gitea needs a database server, unless it is configured to use SQLite.
This role does not handle database configuration.

Gitea's (optional) email system requires a SMTP server or a working `sendmail` program.
This is not set up by this role either.

This role requires the `community.general` Ansible collection.

Role Variables
--------------

* `gitea_use_pkg`  
  Whether to prefer the distribution's package of Gitea.
  Defaults to `true` but is set to `false` if the distribution is not known provide a package.
* `gitea_version`  
  What version of Gitea to install from <https://gitea.io/>.
  If left unset, the latest version (not including release candidates) is chosen.
  This setting is ignored when using a distribution package (cf. `gitea_use_pkg`).
* `gitea_bind_address`  
  The IP address to bind to.
  Set to `0.0.0.0` to listen on all IP addresses.
  Defaults to `127.0.0.1`.
* `gitea_port`  
  The TCP port to listen on.
  Defaults to `443` if `gitea_tls_cert` is set and `80` if it is not.
* `gitea_tls_cert`  
  Path to a PEM-encoded X.509 certificate for Gitea to use.
  The file needs to exist and be readable by the Gitea user.
  Default is unset, which disables TLS support.
* `gitea_tls_cert_key`  
  Path to the PEM-encoded private key file for the certificate.
  The file needs to exist and be readable by the Gitea user.
  Default is unset.
* `gitea_user`, `gitea_group`  
  The system user account and system group to run Gitea as.
  `gitea_user` defaults to `git`; `gitea_group` defaults to the user name.
  When using a distribution package (cf. `gitea_use_pkg`), these settings are ignored.
* `gitea_data_path`  
  The path where repositories, user avatars and similar data is stored.
  Defaults to `/var/lib/gitea`.
* `gitea_log_path`  
  The directory where Gitea's log files are stored.
  Gitea creates a number of log files for different purposes.
  Defaults to `/var/log/gitea`.
* `gitea_loglevel`  
  The log level Gitea's various loggers.
  Valid values are `Trace`, `Debug`, `Info`, `Warn`, `Error`, `Critical`, `Fatal` and `None` in decreasing order of verbosity.
  Fine tuning individual loggers is possible using `gitea_extra_options`.
  Defaults to `Info`.
* `gitea_custom_path`  
  The path where custom files can be placed.
  These files allow [customizing Gitea](https://docs.gitea.io/en-us/customizing-gitea/).
  `gitea_custom_files` can be used to deploy files to this path.
  Note: For security reasons, setting this to a directory within `gitea_data_path` is not recommended.
  Defaults to `/etc/gitea/custom`.
* `gitea_custom_files`  
  Path to a directory on the Ansible controller that contains files that should be deployed to `gitea_custom_path`.
  Refer to the [Gitea documentation](https://docs.gitea.io/en-us/customizing-gitea/) for details.
  Optional.
* `gitea_database_type`  
  The type of database that Gitea should use to store user information, repository metadata, issues, etc.
  Valid values are `mysql`, `postgres`, `mssql` and `sqlite3`.
  Note that this role does not set up a database for Gitea.
  This should be done by another role, unless using SQLite, which does not need any setup.
  Mandatory.
* `gitea_database_host`  
  The host name (and optionally port) of the database system.
  This can also be an absolute path to a UNIX socket, if the database runs on the same system as Gitea.
  Mandatory, unless `gitea_database_type` is `sqlite3`.
* `gitea_database_name`  
  The name of the database to use.
  When using SQLite, this is the path to the database file.
  If not set, Gitea's internal default value is used.
* `gitea_database_user`  
  User account to use when connecting to the database.
  Mandatory, unless `gitea_database_type` is `sqlite3`.
* `gitea_database_password`  
  The password for `gitea_database_user`.
  Omit, if the database does not require a password.
* `gitea_enable_mailer`  
  Whether to enable the mailer (for password resets, etc.) and email notifications.
  Requires are working SMTP server, somewhere.
  Setting up an SMTP server is outside the scope of this role.
  Defaults to `false` unless `gitea_mailer_host` is set.
* `gitea_mailer_host`  
  The host name (and optionally port) of a SMTP server to use for sending email.
  If the mailer is enabled without setting this option, the system's `sendmail` command is used.
  Optional.
* `gitea_mailer_from`  
  The sender address for mail generated by Gitea in RFC 5322 format.
  Mandatory if the mailer is enabled.
* `gitea_mailer_user`  
  User account to use when connecting to the SMTP server.
  Optional.
* `gitea_mailer_password`  
  The password of `gitea_mailer_user`.
  Optional.
* `gitea_enable_indexer`  
  Whether to enable the repository indexer.
  The indexer provides code search, but is known to use a fairly large amount of disk space.
  Defaults to `true`.
* `gitea_enable_lfs`  
  Whether to enable git-lfs support for storing large file more efficiently.
  Defaults to `false`.
* `gitea_enable_signing`  
  Whether to enable automatic singing of commits that are created via the web interface (e.g. on merges or repository initialisation).
  For this purpose a PGP key is generated and stored on the remote system.
  Note that a key is generated only once, and not regenerated, e.g. when the configured identity or other key parameters are changed.
  The exact conditions on when a signature is made can be fine tuned using `gitea_extra_options`.
  Defaults to `true`.
* `gitea_signing_key_type`  
  The type of PGP key to generate.
  Valid values depend on the capabilities of the `gpg` program on the remote system.
  Defaults to `RSA`.
* `gitea_signing_key_length`  
  Length of the PGP key in bits.
  Defaults to `4096`.
* `gitea_committer_name`  
  If `gitea_enable_signing` is `true`, this is the name in the signing PGP key.
  The value may be used elsewhere as well.
  Defaults to `Gitea Bot`.
* `gitea_committer_email`  
  If `gitea_enable_signing` is `true`, this is the email address in the signing PGP key.
  The value may be used elsewhere as well.
  The email address does not need to exist.
  Defaults to `invalid`.
  Another generically useful value might be `{{ gitea_user }}@{{ ansible_facts['hostname'] }}`.
* `gitea_users`  
  A list of local user account to set up within Gitea.
  Note that this only allows creating users, but not modifying existing users.
  Each list item is in turn a dictionary with the following keys:
    * `name`  
      The user's name.
      Needs to be unique within the Gitea installation.
      Mandatory.
    * `email`  
      The user's email address.
      Needs to be unique within the Gitea installation.
      Mandatory.
    * `password`  
      The user's password.
      Mandatory.
    * `admin`  
      Whether to assign administrative privileges to the user.
      Defaults to `false`.  
  Note: `gitea_users` only works on Gitea 1.14.0 or newer.
* `gitea_auth_providers`  
  A list of [external authentication](https://docs.gitea.io/en-us/authentication/) sources to set up within Gitea.
  Each list item is in turn a dictionary with the following keys:
    * `name`
      The name of the authentication source.
      Needs to be unique within the Gitea installation.
      Mandatory.
    * `type`  
      The type of external authentication source to configure.
      Valid values are `oauth`, `ldap` and `ldap-simple`.
      Mandatory.  
  If `type` is `oauth`, the following keys are used:
    * `provider`  
      The name of the OAuth2 provider.
      Valid values are the names of providers supported by Gitea, such as `github`, `gitlab` or `twitter`.
      Mandatory.
    * `client_id`  
      The client ID for use with the OAuth2 provider.
      Mandatory.
    * `client_secret`  
      The client secret for use with the OAuth2 provider.
      Mandatory.
    * `auto_discover_url`  
      The OpenID auto discovery URL.
      Optional.
    * `use_custom_urls`  
      Whether to use custom URLs if `provider` is `github`, `gitlab` or `gitea`.
      Defaults to `false`.
    * `custom_tenant_id`  
      A custom Tenant ID for OAuth2 endpoint (cf. `use_custom_urls`).
      Optional.
      Only works on Gitea 1.19.0 an newer.
    * `custom_auth_url`  
      A custom Authorization URL (cf. `use_custom_urls`).
      Optional.
    * `custom_email_url`  
      A custom Email URL (cf. `use_custom_urls`).
      Optional.
    * `custom_profile_url`  
      A custom Profile URL (cf. `use_custom_urls`).
      Optional.
    * `custom_token_url`  
      A custom Token URL (cf. `use_custom_urls`).
      Optional.  
  If `type` is `ldap` or `ldap-simple`, the following keys are used:
    * `host`  
      The host name of the LDAP server to connect to.
      Mandatory.
    * `port`  
      The TCP port the LDAP service runs on.
      Defaults to `389` or, if `encryption` is `ldaps`, to `636`.
    * `encryption`  
      How connections to the LDAP server should be encrypted.
      Valid values are `disable`, `starttls` and `ldaps`.
      Mandatory.
    * `bind_dn`  
      If `type` is `ldap`: The DN to bind to the LDAP server with when searching for the user. Omit to perform an anonymous search.
      If `type` is `ldap-simple`: A template to use as the user's DN. `%s` is substituted with the login name given on sign-in form.
      Mandatory if `type` is `ldap-simple`.
    * `bind_password`  
      The password for the user in `bind_dn`.
      Only used when `type` is `ldap`.
    * `user_search_base`  
      The LDAP base at which user accounts will be searched for.
      Mandatory if `type` is `ldap`.
    * `user_filter`  
      An LDAP filter declaring when a user should be allowed to log in.
      `%s` is substituted with login name given on sign-in form.
      Mandatory.
    * `admin_filter`  
      An LDAP filter specifying if a user should be given administrator privileges.
      If a user account passes the filter, the user will be privileged as an administrator.
      Optional.
    * `username_attribute`  
      The attribute of the user's LDAP record containing the user name.
      The attribute value will be used for new Gitea accounts' user name after the first successful sign-in.
      Leave empty to use the login name given on sign-in form.
      This is useful when the supplied login name is matched against multiple attributes, but only a single specific attribute should be used for the Gitea account name.
      Optional.
    * `email_attribute`  
      The attribute of the user's LDAP record containing the user's email address.
      Defaults to `mail`.
    * `firstname_attribute`  
      The attribute of the user's LDAP record containing the user's first name.
      Optional.
    * `surname_attribute`  
      The attribute of the user's LDAP record containing the user's surname.
      Optional.
    * `sshkey_attribute`  
      The attribute of the user's LDAP record containing the user's public SSH key.
      Optional.
    * `sync_users`  
      This option enables a periodic task that synchronizes the Gitea users with the LDAP server.
      Defaults to `false`.  
  Note: `gitea_auth_providers` only works on Gitea 1.12.0 or newer.
* `gitea_extra_options`  
  Additional configuration options for Gitea.
  This variable is a dictionary where the keys are section names in `app.ini`.
  The values are in turn dictionaries where keys are Gitea configuration options for the appropriate section and values are the corresponding configuration values.
  Refer to the [Gitea documentation](https://docs.gitea.io/en-us/config-cheat-sheet/) for options and their meaning.
  Optional.
* `gitea_extra_groups`  
  A list of groups that the Gitea system user is added to.
  This allows granting access to additional resources, such as the private key file.
  All groups need to exist on the target system; this role does not create them.
  Empty by default.
* `gitea_inaccessible_paths`  
  If the target system uses systemd, this option takes a list of paths, that should not be accessible at all for Gitea.
  Regardless of this option, home directories are made inaccessible.
  Optional.

Dependencies
------------

This role does not set up TLS certificates and therefore depends on a role that generates and deploys them, if TLS support is desired.

It also depends on a role to set up a MySQL/MariaDB, PostgreSQL or Microsoft SQL Server, respectively (possibly on a different system), if using a "full" DBMS is desired.
Alternatively, SQLite can be used, which does not require any further setup.

Example Configuration
---------------------

The following is a short example for some of the configuration options this role provides:

```yaml
gitea_bind_address: '0.0.0.0'
gitea_database_type: 'mysql'
gitea_database_host: '/run/mysqld/mysqld.sock'
gitea_database_name: 'gitea'
gitea_database_user: 'git'
gitea_inaccessible_paths:
  - '/var/lib/mysql'
gitea_enable_mailer: true
gitea_mailer_from: "{{ gitea_user }}@{{ ansible_facts['fqdn'] }}"
gitea_extra_options:
  server:
    LANDING_PAGE: 'explore'
  service:
    DISABLE_REGISTRATION: true
gitea_users:
  - name: 'admin user'
    email: 'admin@my.domain'
    password: 'admin_password'
    admin: true
  - name: 'ordinary user'
    email: 'user@my.domain'
    password: 'user_password'
gitea_auth_providers:
  - name: 'OpenLDAP'
    type: 'ldap'
    host: 'localhost'
    encryption: 'disable'
    bind_dn: 'cn=gitea,ou=machines,dc=my,dc=domain'
    bind_password: 'some_password'
    user_search_base: 'ou=people,dc=my,dc=domain'
    user_filter: '(&(objectClass=posixAccount)(uid=%s))'
    admin_filter: '(memberOf=cn=Gitea Admins,ou=groups,dc=my,dc=domain)'
    username_attribute: 'uid'
    email_attribute: 'mail'
    sshkey_attribute: 'sshPublicKey'
    sync_users: true
```

License
-------

MIT
