#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Sebastian Hamann
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: gitea_auth

short_description: Manage external authentication sources in Gitea

version_added: none

description:
    - "The `gitea_auth` module allows adding, updating and removing external
      authentication sources in an instance of Gitea."

requirements:
    - Gitea >= 1.12.0

notes:
    - Many options are required when adding new authentication sources. If the authentication source named as in I(name) already exists, the required options can be omitted.
    - If I(state) is C(present), this module always reports a changed result, since Gitea does not currently provide full information about configured authentication sources.

options:
    admin_filter:
        description:
            - An LDAP filter specifying if a user should be given administrator privileges. If a user account passes the filter, the user will be privileged as an administrator.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: str
        required: False
    auto_discover_url:
        description:
            - OpenID Connect auto discovery URL
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: str
        required: False
    bind_dn:
        description:
            - If I(type) is C(ldap): The DN to bind to the LDAP server with when searching for the user. Omit to perform an anonymous search.
            - If I(type) is C(ldap-simple): A template to use as the user's DN. The %s matching parameter will be substituted with the login name given on sign-in form.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
            - Required if I(type) is C(ldap-simple) and I(state) is C(present).
        type: str
        required: False
    bind_password:
        description:
            - The password for the Bind DN specified above, if any.
            - Note: The password is stored in plaintext on the server. As such, ensure that the Bind DN has as few privileges as possible.
            - Only used if I(type) is C(ldap) and I(state) is C(present).
        type: str
        required: False
    client_id:
        description:
            - OAuth2 Client ID
            - Only used if I(type) is C(oauth) and I(state) is C(present).
            - Required in this case.
        type: str
        required: False
    client_secret:
        description:
            - OAuth2 Client secret
            - Only used if I(type) is C(oauth) and I(state) is C(present).
            - Required in this case.
        type: str
        required: False
    config:
        description:
            - Path to the Gitea config file (C(app.ini)).
            - The config file must contain the C(RUN_USER) setting.
        type: str
        required: False
        default: /etc/gitea/app.ini
    custom_tenant_id:
        description:
            - Use custom Tenant ID for OAuth endpoints
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: str
        required: False
    custom_auth_url:
        description:
            - Use a custom Authorization URL (option for GitLab/GitHub).
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: str
        required: False
    custom_email_url:
        description:
            - Use a custom Email URL (option for GitHub).
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: str
        required: False
    custom_profile_url:
        description:
            - Use a custom Profile URL (option for GitLab/GitHub).
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: str
        required: False
    custom_token_url:
        description:
            - Use a custom Token URL (option for GitLab/GitHub).
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: str
        required: False
    email_attribute:
        description:
            - The attribute of the user's LDAP record containing the user's email address.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: str
        required: False
    encryption:
        description:
            - Whether and how to use TLS when connecting to the LDAP server.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
            - Required in this case.
        type: str
        required: False
        choices: ['disable', 'starttls', 'ldaps']
    firstname_attribute:
        description:
            - The attribute of the user's LDAP record containing the user's first name.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: str
        required: False
    host:
        description:
            - The host name of the LDAP server.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
            - Required in this case.
        type: str
        required: False
    name:
        description:
            - The name of the external authentication source.
            - The name needs to be unique in the Gitea installation.
        type: str
        required: True
    port:
        description:
            - The port to use when connecting to the server.
            - Default is 636 if I(encryption) is C(ldaps) and otherwise 389.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: int
        required: False
    provider:
        description:
            - The name of an OAuth2 provider supported by Gitea. Valid names include "github", "gitlab" or "twitter", for instance.
            - Only used if I(type) is C(oauth) and I(state) is C(present).
            - Required in this case.
        type: str
        required: False
    sshkey_attribute:
        description:
            - The attribute of the user's LDAP record containing the user's public SSH key.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: str
        required: False
    state:
        description:
            - Whether the authentication source should exist or not, taking action if the state is different from what is stated.
        type: str
        required: False
        default: 'present'
        choices: ['present', 'absent']
    surname_attribute:
        description:
            - The attribute of the user's LDAP record containing the user's surname.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: str
        required: False
    sync_users:
        description:
            - This option enables a periodic task that synchronizes the Gitea users with the LDAP server.
            - Only used if I(type) is C(ldap) and I(state) is C(present).
        type: bool
        required: False
        default: False
    type:
        description:
            - The type of external authentication provider to set up.
            - Only used if I(state) is C(present).
        type: str
        required: False
        choices: ['oauth', 'ldap', 'ldap-simple']
    use_custom_urls:
        description:
            - Whether to use custom URLs for GitLab/GitHub OAuth endpoints.
            - Only used if I(type) is C(oauth) and I(state) is C(present).
        type: bool
        required: False
    user_filter:
        description:
            - An LDAP filter declaring when a user should be allowed to log in. The %s matching parameter will be substituted with login name given on sign-in form.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
            - Required in this case.
        type: str
        required: False
    user_search_base:
        description:
            - The LDAP base at which user accounts will be searched for.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
            - Required if I(type) is C(ldap) and I(state) is C(present).
        type: str
        required: False
    username_attribute:
        description:
            - The attribute of the user's LDAP record containing the user name. The attribute value will be used for new Gitea accounts' user name after the first successful sign-in. Leave empty to use the login name given on sign-in form.
            - This is useful when the supplied login name is matched against multiple attributes, but only a single specific attribute should be used for the Gitea account name.
            - Only used if I(type) is C(ldap) or C(ldap-simple) and I(state) is C(present).
        type: str
        required: False

author:
    - Sebastian Hamann (@s-hamann)
'''

EXAMPLES = '''
# Create an OAuth2 authentication source
- name: Enable login with GitHub
  gitea_auth:
    name: GitHub
    type: oauth
    provider: github
    client_id: gitea
    client_secret: some_token

# Create an LDAP authentication source
- name: Enable LDAP login
  gitea_auth:
    name: OpenLDAP
    type: ldap
    host: ldap.my.domain
    encryption: starttls
    bind_dn: uid=gitea,ou=machines,dc=my,dc=domain
    bind_password: some_password
    user_search_base: ou=people,dc=my,dc=domain
    user_filter: '(&(objectClass=posixAccount)(uid=%s)(memberOf=cn=Gitea Users,ou=groups,dc=my,dc=domain))'
    admin_filter: '(memberOf=cn=Gitea Admins,ou=groups,dc=my,dc=domain)'
    username_attribute: uid
    firstname_attribute: givenName
    surname_attribute: sn
    email_attribute: mail
    sshkey_attribute: sshPublicKey
    sync_users: true

# Create an LDAP authentication source
- name: Enable Active Directory login
  gitea_auth:
    name: Active Directory
    type: ldap
    host: dc.my.domain
    encryption: ldaps
    bind_dn: uid=gitea,ou=machines,dc=my,dc=domain
    bind_password: some_password
    user_search_base: ou=people,dc=my,dc=domain
    user_filter: '(&(objectCategory=Person)(memberOf=cn=Gitea Users,ou=groups,dc=my,dc=domain)(sAMAccountName=%s)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
    admin_filter: '(memberOf=cn=Gitea Admins,ou=groups,dc=my,dc=domain)'
    username_attribute: sAMAccountName
    firstname_attribute: givenName
    surname_attribute: sn
    email_attribute: mail
    sync_users: true

# Delete an authentication source
- name: Remove login with GitHub
  gitea_auth:
    name: GitHub
    state: absent
'''

RETURN = '''
'''

import os
import pwd
import subprocess

from ansible.module_utils.basic import AnsibleModule
from collections import namedtuple


AuthSrc = namedtuple('AuthSrc', ['id', 'name', 'type', 'enabled'])
CommandResult = namedtuple('CommandResult', ['stdout', 'stderr', 'returncode'])


def gitea_cmd(command, app_ini_path):
    """Run the given Gitea auth command and return the output.

    :command: The auth command to run, as a list (e.g. ['delete', '--id', '1'])
    :app_ini_path: The absolute path to the configuration file (app.ini)
    :returns: The output and return code of the given command as a named tuple
              (stdout, stderr, returncode)

    """

    def become_gitea(uid, gid):
        """Return a function that changes the uid and gid to the given
        user and group."""
        def result():
            os.setgroups([gid])
            os.setgid(gid)
            os.setuid(uid)
        return result

    import configparser
    app_ini = configparser.ConfigParser()
    app_ini.read(app_ini_path)
    user = app_ini['DEFAULT']['RUN_USER']

    userinfo = pwd.getpwnam(user)
    uid = userinfo.pw_uid
    gid = userinfo.pw_gid
    home = userinfo.pw_dir

    env = os.environ.copy()
    env['HOME'] = home

    cmd = subprocess.Popen(['gitea', '--config', app_ini_path, 'admin', 'auth'] + command,
                           preexec_fn=become_gitea(uid, gid), cwd=home, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = cmd.communicate()
    return CommandResult(stdout, stderr, cmd.returncode)


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        admin_filter=dict(type='str'),
        auto_discover_url=dict(type='str'),
        bind_dn=dict(type='str'),
        bind_password=dict(type='str', no_log=True),
        client_id=dict(type='str'),
        client_secret=dict(type='str', no_log=True),
        config=dict(type='str', default='/etc/gitea/app.ini'),
        custom_tenant_id=dict(type='str'),
        custom_auth_url=dict(type='str'),
        custom_email_url=dict(type='str'),
        custom_profile_url=dict(type='str'),
        custom_token_url=dict(type='str'),
        email_attribute=dict(type='str'),
        encryption=dict(type='str', choices=['disable', 'starttls', 'ldaps']),
        firstname_attribute=dict(type='str'),
        host=dict(type='str'),
        name=dict(type='str', required=True),
        port=dict(type='int'),
        provider=dict(type='str'),
        sshkey_attribute=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        surname_attribute=dict(type='str'),
        sync_users=dict(type='bool', default=False),
        type=dict(type='str', choices=['oauth', 'ldap', 'ldap-simple']),
        use_custom_urls=dict(type='bool'),
        user_filter=dict(type='str'),
        user_search_base=dict(type='str'),
        username_attribute=dict(type='str')
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    auth_providers = []

    # Get the currently configured authentication sources.
    header_pos = {}
    for line in gitea_cmd(['list'], module.params['config'])[0].splitlines():
        # Gitea may print random cruft before the actual information, i.e. the
        # header may not be in the first line. Search it.
        line = line.decode().split()
        if not header_pos:
            if line[0] == 'ID':
                header_pos['id'] = line.index('ID')
                header_pos['name'] = line.index('Name')
                header_pos['type'] = line.index('Type')
                header_pos['enabled'] = line.index('Enabled')
            continue
        else:
            a = AuthSrc(id=int(line[header_pos['id']]),
                        name=line[header_pos['name']],
                        type=line[header_pos['type']],
                        enabled=line[header_pos['enabled']].lower() == 'true'
                        )
            auth_providers.append(a)

    # Set `id` to the ID of the authentication source with the given name, if any.
    for p in auth_providers:
        if p.name == module.params['name']:
            id = p.id
            break
    else:
        id = None

    # Sanity checks on the parameters.
    if module.params['state'] == 'present' and not module.params['type']:
        module.fail_json(rc=256, msg='type is required with state=present')
    if module.params['state'] == 'present' and id is None:
        if module.params['type'] == 'oauth':
            required_params = ['provider', 'client_id', 'client_secret']
        elif module.params['type'] == 'ldap':
            required_params = ['host', 'encryption', 'user_filter', 'user_search_base']
        elif module.params['type'] == 'ldap-simple':
            required_params = ['host', 'encryption', 'user_filter', 'bind_dn']
        missing_params = []
        for p in required_params:
            if module.params[p] is None:
                missing_params.append(p)
        if missing_params:
            msg = ('The following parameters are required: {lst}'.
                   format(lst=', '.join(missing_params)))
            module.fail_json(rc=256, msg=msg)

    if module.params['state'] == 'absent' and id is not None:
        # Delete an authentication source.
        if not module.check_mode:
            retval = gitea_cmd(['delete', '--id', str(id)], module.params['config'])
            if retval.returncode > 0:
                msg = ('Could not delete authentication source {name}'.
                       format(name=module.params['name']))
                module.fail_json(msg=msg, stdout=retval.stdout, rc=retval.returncode, **result)
        result['changed'] = True

    elif module.params['state'] == 'present':
        # Add/update an authentication source.
        if module.params['type'] == 'oauth':
            if id is None:
                cmd = ['add-oauth']
            else:
                cmd = ['update-oauth', '--id', str(id)]
            cmd += ['--name', module.params['name']]
            if module.params['provider']:
                cmd += ['--provider', module.params['provider']]
            if module.params['client_id']:
                cmd += ['--key', module.params['client_id']]
            if module.params['client_secret']:
                cmd += ['--secret', module.params['client_secret']]
            if module.params['auto_discover_url']:
                cmd += ['--auto-discover-url', module.params['auto_discover_url']]
            if module.params['use_custom_urls']:
                cmd += ['--use-custom-urls', str(module.params['use_custom_urls'])]
            if module.params['custom_tenant_id']:
                cmd += ['--custom-tenant-id', module.params['custom_tenant_id']]
            if module.params['custom_auth_url']:
                cmd += ['--custom-auth-url', module.params['custom_auth_url']]
            if module.params['custom_token_url']:
                cmd += ['--custom-token-url', module.params['custom_token_url']]
            if module.params['custom_profile_url']:
                cmd += ['--custom-profile-url', module.params['custom_profile_url']]
            if module.params['custom_email_url']:
                cmd += ['--custom-email-url', module.params['custom_email_url']]

        elif module.params['type'] == 'ldap' or module.params['type'] == 'ldap-simple':
            if module.params['type'] == 'ldap':
                if id is None:
                    cmd = ['add-ldap']
                else:
                    cmd = ['update-ldap', '--id', str(id)]
                if module.params['bind_dn']:
                    cmd += ['--bind-dn', module.params['bind_dn']]
                    cmd += ['--attributes-in-bind']
                if module.params['bind_password']:
                    cmd += ['--bind-password', module.params['bind_password']]
                if module.params['sync_users']:
                    cmd += ['--synchronize-users']

            elif module.params['type'] == 'ldap-simple':
                if id is None:
                    cmd = ['add-ldap-simple']
                else:
                    cmd = ['update-ldap-simple', '--id', str(id)]
                if module.params['bind_dn']:
                    cmd += ['--user-dn', module.params['bind_dn']]

            cmd += ['--name', module.params['name']]
            if module.params['host']:
                cmd += ['--host', module.params['host']]
            if module.params['port']:
                cmd += ['--port', module.params['port']]
            elif id is None:
                if module.params['encryption'] == 'ldaps':
                    port = '636'
                else:
                    port = '389'
                cmd += ['--port', port]
            if module.params['encryption']:
                if module.params['encryption'] == 'disable':
                    encryption = 'unencrypted'
                elif module.params['encryption'] == 'starttls':
                    encryption = 'StartTLS'
                elif module.params['encryption'] == 'ldaps':
                    encryption = 'LDAPS'
                cmd += ['--security-protocol', encryption]
            if module.params['user_search_base']:
                cmd += ['--user-search-base', module.params['user_search_base']]
            if module.params['user_filter']:
                cmd += ['--user-filter', module.params['user_filter']]
            if module.params['admin_filter']:
                cmd += ['--admin-filter', module.params['admin_filter']]
            if module.params['username_attribute']:
                cmd += ['--username-attribute', module.params['username_attribute']]
            if module.params['firstname_attribute']:
                cmd += ['--firstname-attribute', module.params['firstname_attribute']]
            if module.params['surname_attribute']:
                cmd += ['--surname-attribute', module.params['surname_attribute']]
            if module.params['email_attribute'] or id is None:
                email_attribute = module.params['email_attribute']
                if not email_attribute:
                    email_attribute = 'mail'
                cmd += ['--email-attribute', email_attribute]
            if module.params['sshkey_attribute']:
                cmd += ['--public-ssh-key-attribute', module.params['sshkey_attribute']]

        if not module.check_mode:
            retval = gitea_cmd(cmd, module.params['config'])
            if retval.returncode > 0:
                if id is None:
                    verb = 'add'
                else:
                    verb = 'update'
                msg = ('Could not {verb} authentication source {name}'.
                       format(verb=verb, name=module.params['name']))
                module.fail_json(msg=msg, stdout=retval.stdout, rc=retval.returncode, **result)

        # We can not know if anything was changed, since we can not get the
        # full configuration of an authentication source out of Gitea.
        result['changed'] = True

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
