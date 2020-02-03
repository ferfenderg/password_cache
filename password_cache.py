#!/usr/bin/python
__author__ = "ferfenderg"

import getpass3
import keyutils
import pexpect
import sys
import re
import argparse

import logging
if sys.stdout.isatty():
    log = logging.getLogger()
    log.setLevel(logging.WARNING)
    shandler = logging.StreamHandler()
    shandler.setFormatter(
            logging.Formatter(
                    "%(levelname)-8s %(asctime)s %(filename)16s:%(funcName)s:%(lineno)-4d  %(message)s")
    )
    log.addHandler(shandler)

# noinspection PyPep8,PyBroadException
try:
    # This is only used in pycharm - it has stubs for this for python 2.7
    # noinspection PyUnresolvedReferences
    from typing import List, Optional, Dict, DefaultDict, Any, Union, Pattern, Match, Iterator, Tuple, Callable
except Exception as does_not_matter_just_for_pycharm:
    pass

HELP_DESC = '''
password_cache caches a password for a username that you input for a specified period of time. 
If this script is imported, it can pop out the required password for any script.
'''
SET_EPILOGUE = '''
This script uses keyctl to temporarily cache a password. This isn't a replacement for a password management system nor 
an effective replacement for sudo escalation.
It's good practice to use the name of the code as the key prefix. This would make it easier for you to code around it 
'''
LOGIN = getpass.getuser()

class AuthenticationFailure(Exception):
    """ password check failed """
    pass


def password_initiator(username, keyring_prefix, do_not_save_password, timeout=3600, active_directory=None, skip_test=True):
    """
    This is intended to act as a black box, where you give it a namespace with a username in it and it'll perform it's
    magic and it'll spit out the vetted password.
    It will only check Active Directory users to prevent you from locking yourself out.

    :param username: User Credential. expected format: Acive directory user- user@wetafx.co.nz, local user - user
    :type username: str
    :param keyring_prefix: Prefix that'll help create a unique identifer for the key that'll go on your
    kernel keyring
    :type keyring_prefix: str
    :param do_not_save_password: True if you don't want to save the password to the kernel
    :type do_not_save_password: bool
    :param timeout: number of seconds before the key expires
    :type timeout: int
    :param active_directory: The active directory domain
    :type active_directory: str
    :param skip_test: A boolean to skip local authentication
    :type skip_test: bool

    :return: User password
    :rtype: str
    """

    if active_directory:
        username = str(username + "@" + active_directory)
        log.debug('active_directory = True. Username changed to {}\n'.format(username))

    keyname = str(keyring_prefix + "_" + username)
    key = KernelKeyring(key_name=keyname, username=username)
    if do_not_save_password:
        log.debug('do_not_save_password = True.\n')
        return password_check(username=username, keyname=keyname, active_directory=active_directory, skip_test=skip_test)

    else:
        log.debug('do_not_save_password = False.\n')
        return key.get_user_password_through_keyctl(timeout=timeout, active_directory=active_directory,
                                                    skip_test=skip_test)


def password_check(username, keyname, active_directory, skip_test):
    """
    This checks if the password is valid

    It uses a while loop to give you multiple tries to

    :param username: Username for the password
    :type username: str
    :param keyname: The name of the key. so it's properly
    :type keyname: str
    :param active_directory: The active directory domain
    :type active_directory: str
    :param skip_test: A boolean to skip local authentication
    :type skip_test: bool

    :return: User password
    :rtype: str
    """
    counter = 0
    password_ok = False
    log = logging.getLogger('Password')
    while counter < 3 and not password_ok:
        try:
            password_i = Password(key_name=keyname)
        except KeyboardInterrupt:
            sys.stderr.write("\nkeyboard interrupt received\n")
            raise KeyboardInterrupt

        if skip_test:
            log.debug('Auth test skipped.\n')
            counter = 5
            password_ok = True

        else:
            # this is to test the account so you don't accidentally lock yourself out
            if active_directory is None:
                i_username = username

            else:
                i_username = username.strip().split('@')[0]

            try:
                log.debug('Password attept {}\n'.format(counter))
                password_ok = password_i.test_password(user=i_username)

            except AuthenticationFailure:
                if counter >= 2:
                    log.critical('Authentication failed too many times.\n exiting.\n')
                    exit(401)

            except Exception as err:
                log.error('Test failed. reason: {}\n'.format(err))

        counter = counter + 1

    return password_i.password


class Password(object):

    def __init__(self, key_name=None):
        self.key_name = key_name
        self.password_prompt = ''
        if self.key_name:
            self.password_prompt = '[%s] ' % self.key_name
        self.password_prompt += 'Password: '
        self.password = getpass3.getpass(self.password_prompt)
        self.log = logging.getLogger('Password')

    def test_password(self, username):
        '''
        This does an su locally to test that your account works fine.

        :param username:
        :return: whether the password authenticated correctly
        :rtype: bool
        '''

        expect_re = r'(?P<auth_failure>Authentication failure)' \
                    r'|(?P<good_auth>good password)'
        auth_test_cmd = "su {} -c 'echo good password'".format(username)

        child = pexpect.spawn(auth_test_cmd, echo=False)
        child.expect('Password:')
        child.sendline(self.password)
        i = child.expect(
            [
                pexpect.EOF,
                pexpect.TIMEOUT,
                expect_re],
            timeout=10)

        error_info = "cmd: {} received: '{}{}'".format(auth_test_cmd, child.before, child.after )

        if i == 0:
            self.log.error("Got EOF before finishing checking password with  {} ".format(error_info))
            raise EOFError

        elif i == 1:
            self.log.error("Got timeout waiting to match {} -  {}".format(expect_re, error_info))
            raise pexpect.exceptions.TIMEOUT

        elif i == 2:
            m = child.match  # type: Match

            if m.groupdict().get('auth_failure') is not None:
                self.log.critical(
                    "Authentication failure got this back from '{}' - {}{}".format(auth_test_cmd, child.before, child.after))
                raise AuthenticationFailure("Authentication Failure")

            elif m.groupdict().get('good_auth') is not None:
                self.log.debug("Got good authentication\n")
                return True

            else:
                self.log.critical("Programming error - a regex was matched which was not in a group - regex was {}"
                                  .format(expect_re))
                raise RuntimeError("Programming error")


class KernelKeyring(object):
    """
    The kernel keyring
    """
    def __init__(self, key_name='keyctl', username=None):
        self.key_name = key_name
        self.username = username

    def clear_keyctl_password(self):
        '''
        This is to delete the key for whatever reason. A good reason is if you accidentally cache a password.
        :return:
        '''
        keyctl_keyring_name = 'keyutils did not import so unknown'

        ring = keyutils.KEY_SPEC_SESSION_KEYRING
        keyctl_keyring_name = '@s'
        key_id = keyutils.request_key(self.key_name, ring)

        if key_id:
            keyutils.unlink(key_id, ring)
            log.debug('key deleted')

    def get_user_password_through_keyctl(self, timeout, active_directory, skip_test, keyring=None,
                                         raise_on_error=True):
        '''

        :param timeout:
        :param active_directory:
        :param skip_test:
        :param keyring:
        :param raise_on_error:
        :return:
        '''
        password = None

        try:
            if keyring is None: # if keyring doesn't exist, generate a new keyring
                keyring = keyutils.KEY_SPEC_SESSION_KEYRING
                log.debug('KEY_SPEC_SESSION_KEYRING generated\n')
            elif keyring is 'user':
                keyring == keyutils.KEY_SPEC_USER_SESSION_KEYRING
                log.debug('KEY_SPEC_USER_SESSION_KEYRING generated\n')

            if keyring == keyutils.KEY_SPEC_SESSION_KEYRING:
                keyctl_keyring_name = '@s'

            elif keyring == keyutils.KEY_SPEC_USER_SESSION_KEYRING:
                keyctl_keyring_name = '@us'

            else:
                sys.exit('update this code to add the un translated keyring type {}\n'.format(keyring))

            key_id = keyutils.request_key(self.key_name, keyring)

            if key_id:
                log.debug('Key {} exists on {}. Pulling from keyring\n'.format(self.key_name, keyring))
                password = keyutils.read_key(key_id)

            else:
                log.debug('Key {} does not exist on {}. creating new key\n'.format(self.key_name, keyring))
                password = password_check(username=self.username, keyname=self.key_name,
                                          active_directory=active_directory, skip_test=skip_test)

            key_id = keyutils.add_key(self.key_name, password, keyring)  # for keyctl(1) the 'type' is 'user'
            keyutils.set_timeout(key_id, timeout)  # Reset it each time it's accessed

        except Exception as e:
            if raise_on_error:
                raise Exception("Failed to get key from keyutils using keyring {} - exception was {}"
                                .format(keyctl_keyring_name, e))
        return password


def main():

    prs = argparse.ArgumentParser(description=HELP_DESC, formatter_class=RawTextHelpFormatter, epilog=SET_EPILOGUE)
    prs.add_argument('--debug', default=False, dest='print_debug', action='store_true',
                     help='Output debug data')
    prs.add_argument('-u', '--username', default=LOGIN, dest='username',
                     help="Log in with a specific user default user is: {}.".format(LOGIN))
    prs.add_argument('--do-not-save-password', default=False, action='store_true', dest='do_not_save_password',
                     help="Don't save the password")
    prs.add_argument('--keyring-prefix', default='pass_cache', help='prefix to use when creating/using the keyring')
    prs.add_argument('--timeout', type=int, help='Timeout before the password expires. default is 60min')
    prs.add_argument('-AD''--active-directory', help='Active directory domain name [Optional]')
    prs.add_argument('--skip-test', action=store_true, help='Used to skip the local auth test. su is done locally.'
                                                            'best used when the password is for a remote system with a'
                                                            ' local user')
    args = prs.parse_args()

    password = password_initiator(username=args.username, keyring_prefix=args.keyring_prefix,
                                  do_not_save_password=args.do_not_save_password, timeout=args.timeout,
                                  active_directory=args.active_directory, skip_test=skip_test)
    if sys.stdout.isatty():
        sys.stdout.write('Key added to kernel keyring\n')

    else:
        sys.stdout.write(password)


if __name__ == "__main__":
    main()
