#!/usr/bin/env python3

'''Cliente de prueba para RestFS'''

import os
import cmd
import sys
import glob
import fnmatch
import getpass
import logging
import os.path
import argparse
from io import StringIO

from restfs_common.errors import NO_ERROR, CMDCLI_ERROR, CONNECTION_ERROR, UNAUTHORIZED,\
    Unauthorized, ObjectNotFound
from restfs_common.constants import ADMIN

import restfs_client
import restfs_client.auth
from restfs_client.uitools import ask_login_process, ask_string, ask_choice
from restfs_client.filesystem import RestFS


__version__ = '1.0'

_COMMENT_TAG_ = '#'


class RestFSShell(cmd.Cmd):
    '''Shell para probar los servicios de RestFS'''
    prompt = ''
    interactive = True

    auth = None
    blob = None
    dirs = None
    user = None

    lpath = os.path.abspath(os.getcwd())

    mount = None

    blob_selection = []

    def out(self, *args, **kwargs):
        '''Send to output'''
        print(*args, **kwargs)
        logging.debug(*args, **kwargs)

    def error_out(self, *args, **kwargs):
        '''Send to output'''
        logging.error(*args, **kwargs)

    def preloop(self) -> None:
        '''Setup prompt before start the shell'''
        self._compute_prompt_()
        return super().preloop()

    def precmd(self, line: str) -> str:
        '''Setup prompt before execute a command'''
        self._compute_prompt_()
        if line.strip().startswith(_COMMENT_TAG_):
            return ''
        logging.debug(f'Running: {line}')
        return super().precmd(line)

    def postcmd(self, stop: bool, line: str) -> bool:
        '''Setup prompt after execute a command'''
        self._compute_prompt_()
        return super().postcmd(stop, line)

    def _compute_prompt_(self):
        if self.interactive:
            self.prompt = f'RestFS [{self._online_}{self._authenticated_}{self._remote_path_}]> '
        else:
            self.prompt = ''

    @property
    def _online_(self):
        if (self.auth is None) and (self.blob is None) and (self.dirs is None):
            return 'off-line'
        elif (self.auth is not None) and (self.blob is not None) and (self.dirs is not None):
            return 'on-line'
        else:
            return '*on-line'

    @property
    def _authenticated_(self):
        if self.user is None:
            return '(anonymous)'
        else:
            return f'({self.user.user})'

    @property
    def _remote_path_(self):
        if self.mount is None:
            return ''
        else:
            return f'[{self.mount.current_path}]'
    @property
    def _is_admin_(self):
        return isinstance(self.user, restfs_client.auth.Administrator)

    def default(self, line):
        '''Command handler for unknown commands'''
        self.error_out(f'Unknown command: {line}')
        return None

    def emptyline(self) -> bool:
        '''Action in case of empty line'''
        return None

    def do_EOF(self, line):
        '''Quit'''
        return self.do_quit(line)

    def do_quit(self, line):
        '''Disconnect from services and exit'''
        return True

    def do_status(self, line):
        '''Show client status'''
        self.out(f'Local path: {self.lpath}')
        if self.auth is None:
            self.out('Not connected to an authentication service')
        else:
            self.out(f'Authentication service: {self.auth.base_url}')
        if self.blob is None:
            self.out('Not connected to a blob service')
        else:
            self.out(f'Blob service: {self.blob.base_url}')
        if self.dirs is None:
            self.out('Not connected to a directory service')
        else:
            self.out(f'Directory service: {self.auth.base_url}')
        if self.user is None:
            self.out('Not authenticated')
        else:
            if self._is_admin_:
                self.out('Authenticated as administrator')
            else:
                self.out(f'Authenticated as {self.user.user}')
                self.out(f'Current token: {self.user.token}')
        if not self.blob_selection:
            self.out('No blobs selected')
        else:
            self.out(f'{len(self.blob_selection)} blob(s) selected')
        if self.mount is None:
            self.out('No folder mounted')
        else:
            self.out(f'Folder mounted: {self.mount.current_directory.identifier}')
            self.out(f'Remote path: {self.mount.current_path}')

    ### Local filesystem commands ###

    def do_lcd(self, line):
        '''Local change directory'''
        if line == '':
            self.out(f'Local path: {self.lpath}')
            return
        new_path = os.path.abspath(os.path.join(self.lpath, line))
        if not os.path.isdir(new_path):
            self.error_out(f'Cannot change to {new_path}: local directory not found')
        self.lpath = new_path

    def do_lls(self, line):
        '''Local "ls"'''
        if line == '':
            line = '*'
        entries = glob.glob(os.path.join(self.lpath, line))
        directories = []
        files = []
        for entry in entries:
            if os.path.isdir(entry):
                directories.append(entry)
            else:
                files.append(entry)
        if directories:
            self.out('Local directories:')
            for dirname in directories:
                self.out(f'\t{os.path.basename(dirname)}')
        if files:
            self.out('Local files:')
            for filename in files:
                self.out(f'\t{os.path.basename(filename)}')

    ### Authentication service ###

    def do_connect_auth(self, line):
        '''Connect to a given authentication service'''
        if self.auth is not None:
            self.error_out('Already connected, disconnect first')
            return
        url = ask_string('Authentication service URL: ', line, interactive=self.interactive)
        self.auth = restfs_client.get_AuthService(url)

    def do_disconnect_auth(self, line):
        '''Disconnect from a given authentication service'''
        if self.auth is None:
            self.error_out('Already disconnected, connect first')
            return
        if self.user is not None:
            self.error_out('Already logged, logout first')
            return
        self.auth = None

    def do_login(self, line):
        '''Do a login'''
        if self.user is not None:
            self.error_out('Already logged, logout first')
            return
        if self.auth is None:
            self.error_out('Cannot login because not connected to an authentication service')
            return
        username, password = ask_login_process(line, interactive=self.interactive)
        if username == ADMIN:
            self.user = restfs_client.new_Administrator(admin_token=password, attached_service=self.auth)
        else:
            self.user = restfs_client.new_User(username=username, password=password, attached_service=self.auth)
        return

    def do_refresh_token(self, line):
        '''Refresh the user token'''
        if self._is_admin_:
            self.error_out('Administrator token cannot be refreshed')
            return
        if self.user is None:
            self.error_out('Not logged, login first')
            return
        try:
            self.user.refresh_token()
            self.out('Token refreshed')
        except Exception as error:
            self.error_out(f'Cannot refresh token: {error}')
        return

    def do_logout(self, line):
        '''Do logout'''
        if self.user is None:
            self.error_out('Already logged out')
            return
        if self.mount is not None:
            self.error_out('User mounts a directory, unmount first')
            return
        self.user = None
        self.blob_selection = []

    def do_new_user(self, line):
        '''Create new user'''
        if not self._is_admin_:
            self.error_out('This command requires administrative access')
            return
        username, password = ask_login_process(
            line, confirm_password=True, interactive=self.interactive
        )
        try:
            new_user = self.user.new_user(username, password)
            self.out(f'User "{new_user.user}" created')
        except Exception as error:
            self.error_out(f'Cannot create user: {error}')

    def do_remove_user(self, line):
        '''Delete a user'''
        if not self._is_admin_:
            self.error_out('This command requires administrative access')
            return
        username = ask_string('User to remove: ', line, interactive=self.interactive)
        try:
            self.user.remove_user(username)
            self.out(f'User "{username} removed')
        except Exception as error:
            self.error_out(f'Cannot remove user: {error}')

    def do_set_password(self, line):
        '''Set password for the current user'''
        if self._is_admin_:
            self.error_out('Administrator does not have a password access')
            return
        if self.user is None:
            self.error_out('Not logged, login first')
            return
        password = ask_string('New password: ', line, False, interactive=self.interactive)
        try:
            self.user.set_new_password(password)
            self.out(f'Password changed')
        except Exception as error:
            self.error_out(f'Cannot change password: {error}')

    def do_whois(self, line):
        '''Who is the owner of the token'''
        if self.auth is None:
            self.error_out('Cannot execute command because not connected to an authentication service')
            return
        token = ask_string('Which token: ', line, interactive=self.interactive)
        try:
            user = self.auth.user_of_token(token)
            self.out(f'Owner: {user}')
        except Unauthorized:
            self.out('Invalid token')

    def do_user_exists(self, line):
        '''Check if user exists or not'''
        if self.auth is None:
            self.error_out('Cannot execute command because not connected to an authentication service')
            return
        user = ask_string('Which user: ', line, interactive=self.interactive)
        if self.auth.exists_user(user):
            self.out('User exists')
        else:
            self.out('User not found')

    ### Blob service ###

    def do_connect_blob(self, line):
        '''Connect to a given blob service'''
        if self.blob is not None:
            self.error_out('Already connected, disconnect first')
            return
        url = ask_string('Blob service URL: ', line, interactive=self.interactive)
        self.blob = restfs_client.get_BlobService(url)

    def do_disconnect_blob(self, line):
        '''Disconnect from a given blob service'''
        if self.blob is None:
            self.error_out('Already disconnected, connect first')
            return
        self.blob = None

    def do_upload_blobs(self, line):
        '''Upload files to the blob service'''
        if self.blob is None:
            self.error_out('Cannot upload files because not connected to a blob service')
            return
        if self.user is None:
            self.error_out('Anonymous users cannot upload files')
            return
        if line == '':
            self.error_out('Files to upload is mandatory')
            return
        files = line.split()
        files_to_upload = []
        for filename in files:
            for item in glob.glob(os.path.join(self.lpath, filename)):
                if os.path.isfile(item):
                    self.out(f'Select file {os.path.basename(item)} for upload')
                    files_to_upload.append(item)
                else:
                    self.out(f'Skipping "{os.path.basename(item)}" (not a regular file)')
        blob_count = 0
        for filename in files_to_upload:
            self.out(f'Uploading {os.path.basename(filename)}...')
            try:
                self.blob_selection.append(self.blob.new_blob(filename, self.user))
                blob_count += 1
            except Exception as error:
                self.error_out(f'Failed to upload: {error}')
                break
        self.out(f'{blob_count} blob(s) created')

    def do_blob_selection(self, line):
        '''Handle blob selection'''
        if not self.blob_selection:
            self.out('No blobs selected')
            return
        if line in ['', 'show', 'ls', 'list']:
            count = 1
            for blob in self.blob_selection:
                self.out(f'Blob #{count}: {blob.url}')
                count += 1
            return
        if line in ['clear', 'reset']:
            self.blob_selection = []
            self.out('Blob selection cleared')
            return

    def do_remove_selected_blob(self, line):
        '''Remove blob from service'''
        if self.blob is None:
            self.error_out('Cannot remove blobs because not connected to a blob service')
            return
        if self.user is None:
            self.error_out('Anonymous users cannot remove blobs')
            return
        if not self.blob_selection:
            self.error_out('No blobs selected')
            return
        target_blob = ask_choice(self.blob_selection, line, self.interactive, self.out)
        self.blob_selection.remove(target_blob)
        try:
            self.blob.remove_blob(target_blob)
            self.out('Blob removed')
        except ObjectNotFound as error:
            self.error_out(f'Cannot download blob: {error}')
        except Unauthorized as error:
            self.error_out(f'Aunauthorized: {error}')

    def do_download_selected_blob(self, line):
        '''Download blob from service'''
        if self.blob is None:
            self.error_out('Cannot download blobs because not connected to a blob service')
            return
        if self.user is None:
            self.error_out('Anonymous users cannot download blobs')
            return
        if not self.blob_selection:
            self.error_out('No blobs selected')
            return

        line = line.split()
        try:
            pre_input = line[0]
        except IndexError:
            pre_input = None
        target_filename = ask_string('Destination filename: ', pre_input, interactive=self.interactive)
        target_filename = os.path.abspath(os.path.join(self.lpath, target_filename))
        target_blob = ask_choice(self.blob_selection, line, self.interactive, self.out)
        try:
            target_blob.dump_to(target_filename)
            self.out(f'Blob downloaded to {os.path.basename(target_filename)}')
        except ObjectNotFound as error:
            self.error_out(f'Cannot download blob: {error}')
        except Unauthorized as error:
            self.error_out(f'Aunauthorized: {error}')

    def do_replace_selected_blob(self, line):
        '''Replace blob from the given file'''
        if self.blob is None:
            self.error_out('Cannot replace blobs because not connected to a blob service')
            return
        if self.user is None:
            self.error_out('Anonymous users cannot replace blobs')
            return
        if not self.blob_selection:
            self.error_out('No blobs selected')
            return

        line = line.split()
        try:
            source_filename = line[0]
        except IndexError:
            source_filename = None
        try:
            target_blob = line[1]
        except IndexError:
            target_blob = None
        source_filename = ask_string('Source filename: ', source_filename, interactive=self.interactive)
        source_filename = os.path.abspath(os.path.join(self.lpath, source_filename))
        target_blob = ask_choice(self.blob_selection, target_blob, self.interactive, self.out)
        try:
            target_blob.refresh_from(source_filename)
            self.out(f'Blob updated using {os.path.basename(source_filename)}')
        except ObjectNotFound as error:
            self.error_out(f'Cannot download blob: {error}')
        except Unauthorized as error:
            self.error_out(f'Aunauthorized: {error}')

    def do_select_blob(self, line):
        '''Select a blob'''
        if self.blob is None:
            self.error_out('Cannot select blobs because not connected to a blob service')
            return
        if self.user is None:
            self.error_out('Anonymous users cannot select blobs')
            return
        blob_id = ask_string('Enter blob identifier: ', line, interactive=self.interactive)
        try:
            blob = self.blob.get_blob(blob_id, self.user)
            self.blob_selection.append(blob)
            self.out(f'Added blob to selection')
        except ObjectNotFound as error:
            self.error_out(f'Cannot download blob: {error}')
        except Unauthorized as error:
            self.error_out(f'Aunauthorized: {error}')

    def do_unselect_blob(self, line):
        '''Unselect a blob from selection'''
        if self.blob is None:
            self.error_out('Cannot unselect blobs because not connected to a blob service')
            return
        if not self.blob_selection:
            self.error_out('Blobs selection in empty')
            return
        blob = ask_choice(self.blob_selection, line, self.interactive, self.out)
        self.out(f'Remove blob #{blob.identifier} from the selection')
        self.blob_selection.remove(blob)

    ### Directory service ###

    def do_connect_dirs(self, line):
        '''Connect to a given directory service'''
        if self.dirs is not None:
            self.error_out('Already connected, disconnect first')
            return
        url = ask_string('Directory service URL: ', line, interactive=self.interactive)
        self.dirs = restfs_client.get_DirectoryService(url)

    def do_disconnect_dirs(self, line):
        '''Disconnect from the current directory service'''
        if self.mount is not None:
            self.error_out('Directory is mounted, unmount first')
            return
        if self.dirs is None:
            self.error_out('Already disconnected, connect first')
            return
        self.dirs = None

    def do_mount_rfs(self, line):
        '''Get a root directory from the directory service'''
        if self.mount is not None:
            self.error_out('Already mounted, unmount first')
            return
        if self.dirs is None:
            self.error_out('Cannot mount directory without directory service connection')
            return
        if self.user is None:
            self.error_out('Anonymous cannot mount root dir')
            return
        self.mount = RestFS(self.auth.base_url, self.blob.base_url, self.dirs.base_url, self.user)

    def do_umount_rfs(self, line):
        '''Release a remote directory'''
        if self.mount is None:
            self.error_out('Not mounted, mount first')
            return
        self.mount = None

    def do_rls(self, line):
        '''Remote "ls"'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        if line == '':
            line = '*'
        directories = fnmatch.filter(self.mount.directories, line)
        files = fnmatch.filter(self.mount.files, line)
        if directories:
            self.out('Local directories:')
            for dirname in directories:
                    self.out(f'\t{os.path.basename(dirname)}')
        if files:
            self.out('Local files:')
            for filename in files:
                self.out(f'\t{os.path.basename(filename)}')

    def do_rcd(self, line):
        '''Remote change directory'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        if line == '':
            self.out(f'Remote path: {self.mount.current_path}')
            return
        new_path = os.path.abspath(os.path.join(self.mount.current_path, line))
        try:
            self.mount.change_directory(new_path)
        except KeyError:
            self.error_out('Target directory not found')
            return

    def do_rmkdir(self, line):
        '''Remote create directory'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        directory = ask_string('New directory name: ', line, interactive=self.interactive)
        try:
            self.mount.create_directory(directory)
        except Exception as error:
            self.error_out(f'Cannot create directory: {error}')
            return
        self.out('Directory created')

    def do_rrmdir(self, line):
        '''Remove remote directory'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        directory = ask_choice(self.mount.directories, line, self.interactive, self.out)
        try:
            self.mount.remove_directory(directory)
        except Exception as error:
            self.error_out(f'Cannot remove directory: {error}')
            return
        self.out('Directory removed')

    def do_mkfile(self, line):
        '''Remote create file from blob'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        if self.blob is None:
            self.error_out('Not connected to a blob service')
            return
        if not self.blob_selection:
            self.error_out('No blobs in the selection')
            return
        line = line.split()
        try:
            pre_input = line[0]
        except IndexError:
            pre_input = None
        target_filename = ask_string('Destination filename: ', pre_input, interactive=self.interactive)
        try:
            pre_input = line[1]
        except IndexError:
            pre_input = None
        source_blob = ask_choice(self.blob_selection, pre_input, self.interactive, self.out)
        try:
            self.mount.current_directory.new_file(target_filename, source_blob.url)
        except Exception as error:
            self.error_out(
                f'Cannot create file "{target_filename}" from blob {source_blob.identifier}: {error}')
            return
        self.error_out('File created')

    def do_unlink_file(self, line):
        '''Remove remote file (not the blob)'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        filename = ask_choice(self.mount.files, line, self.interactive, self.out)
        try:
            self.mount.current_directory.remove_file(filename)
        except Exception as error:
            self.error_out(f'Cannot remove the file "{filename}": {error}')
            return
        self.out('File removed')

    def do_rrmfile(self, line):
        '''Remove remote file (including the blob)'''
        if self.mount is None:
            self.error_out('Not mounted')
            return
        filename = ask_choice(self.mount.files, line, self.interactive, self.out)
        try:
            self.mount.remove_file(filename)
        except Exception as error:
            self.error_out(f'Cannot remove the file "{filename}": {error}')
            return
        self.error_out('File removed')

    def do_upload(self, line):
        '''Upload file from local filesystem to RestFS'''
        if self.mount is None:
            self.error_out('Not mounted')

        line = line.split()
        try:
            sourcefile = line[0]
        except IndexError:
            sourcefile = None
        sourcefile = ask_string('Source filename: ', sourcefile, interactive=self.interactive)
        try:
            destinationfile = line[1]
        except IndexError:
            destinationfile = None
        try:
            self.mount.upload_file(sourcefile, destinationfile)
            self.out('File uploaded')
        except Exception as error:
            self.error_out(f'Cannot upload file: {error}')

    def do_download(self, line):
        '''Upload file from local filesystem to RestFS'''
        if self.mount is None:
            self.error_out('Not mounted')

        line = line.split()
        try:
            sourcefile = line[0]
        except IndexError:
            sourcefile = None
        sourcefile = ask_choice(self.mount.files, sourcefile, self.interactive, self.out)
        try:
            destinationfile = line[1]
        except IndexError:
            destinationfile = None
        try:
            self.mount.download_file(sourcefile, destinationfile)
            self.out('File uploaded')
        except Exception as error:
            self.error_out(f'Cannot upload file: {error}')

    ### Help messages ###

    def help_quit(self):
        self.out('''Usage:
\tquit
Disconnect from services and quit.''')

    def help_status(self):
        self.out('''Usage:
\tstatus
Show the status of the client.''')

    def help_lcd(self):
        self.out('''Usage:
\tlcd [path]
Change the local directory. If path is omited, show the current path.''')

    def help_lls(self):
        self.out('''Usage:
\tlls [pattern]
Show files and directories that match pattern. If pattern is omited, all file will be shown.''')

    def help_connect_auth(self):
        self.out('''Usage:
\tconnect_auth <URL>
Connect to a given authentication service using the provided URL.''')

    def help_disconnect_auth(self):
        self.out('''Usage:
\tdisconnect_auth
Disconnect from the current authentication service.''')

    def help_login(self):
        self.out('''Usage:
\tlogin [user [password]]
Login into the authentication service.''')

    def help_logout(self):
        self.out('''Usage:
\tlogout
Logout the current user.''')

    def help_new_user(self):
        self.out('''Usage:
\tnew_user [user [password]]
Create new user with the given password.''')

    def help_remove_user(self):
        self.out('''Usage:
\tremove_user [user]
Remove user from the authentication service.''')

    def help_set_password(self):
        self.out('''Usage:
\tset_password [password]
Change new password for the user.''')

    def help_whois(self):
        self.out('''Usage:
\twhois [token]
Get the owner of the given token or error if token is invalid.''')

    def help_user_exists(self):
        self.out('''Usage:
\tuser_exists [user]
Check if given user exists on the service.''')

    def help_connect_blob(self):
        self.out('''Usage:
\tconnect_blob <URL>
Connect to a given blob service using the provided URL.''')

    def help_disconnect_blob(self):
        self.out('''Usage:
\tdisconnect_blob
Disconnect from the current blob service.''')

    def help_upload_blobs(self):
        self.out('''Usage:
\tupload_blob <file_pattern0> [<file_pattern1> [<file_patternN>]]
Upload a set of files given by a list of shell expressions.''')

    def help_blob_selection(self):
        self.out('''Usage:
\tblob_selection [ls|clear]
With "ls" shows the current blob selection. With "clear" resets the selection.''')

    def help_remove_selected_blob(self):
        self.out('''Usage:
\tremove_selected_blob [selection]
Remove selected blob from the server.''')

    def help_download_selected_blob(self):
        self.out('''Usage:
\tdownload_selected_blob [selection [destination_filename]]
Download selected blob from the server to a local filename.''')

    def help_replace_selected_blob(self):
        self.out('''Usage:
\treplace_selected_blob [selection [source_filename]]
Upload local filename and replace the blob on the server.''')

    def help_select_blob(self):
        self.out('''Usage:
\tselect_blob [blob_id]
Select a single blob.''')

    def help_unselect_blob(self):
        self.out('''Usage:
\tunselect_blob [selection]
Unselect a single blob.''')

    def help_connect_dirs(self):
        self.out('''Usage:
\tconnect_dirs <URL>
Connect to a given directory service using the provided URL.''')

    def help_disconnect_dirs(self):
        self.out('''Usage:
\tdisconnect_dirs
Disconnect from the current directory service.''')

    def help_rls(self):
        self.out('''Usage:
\trls [pattern]
Show files and directories of the current remote folder that match pattern. If pattern is omited, all file will be shown.''')

    def help_rcd(self):
        self.out('''Usage:
\trcd <folder>
Change the remote current folder.''')

    def help_rmkdir(self):
        self.out('''Usage:
\trmkdir [folder]
Create new subfolder in the current directory.''')

    def help_rrmdir(self):
        self.out('''Usage:
\trrmdir [folder]
Remove given subfolder of the current folder.''')

    def help_mkfile(self):
        self.out('''Usage:
\tmkfile [filename [selection]]
Create a new file on the current folder using the given selected blob.''')

    def help_unlink_file(self):
        self.out('''Usage:
\tunlink_file [filename]
Remove a previously created file on the current folder but keeps the source blob.''')


def main():
    '''Entry point'''
    # Bootstrap
    user_options = parse_commandline()
    if not user_options:
        return CMDCLI_ERROR

    log_level = logging.DEBUG if user_options.debug else logging.INFO
    if user_options.log_file:
        logging.basicConfig(filename=user_options.log_file, level=log_level)
    else:
        logging.basicConfig(level=log_level)
    logging.debug('Starting RestFS client...')

    exit_code = NO_ERROR

    auth_service = restfs_client.get_AuthService(user_options.auth_url) if user_options.auth_url else None
    blob_service = restfs_client.get_BlobService(user_options.blob_url) if user_options.blob_url else None
    dirs_service = restfs_client.get_DirectoryService(user_options.dirs_url) if user_options.dirs_url else None
    token = user_options.token
    if user_options.force_admin:
        if token is None:
            token = raw_input('Please, enter administrative token: ')
        try:
            user = restfs_client.new_Administrator(admin_token=token, attached_service=auth_service)
        except restfs_client.errors.ConnectionError as error:
            logging.error(f'Cannot connect to the authorization service: {error}')
            return CONNECTION_ERROR
        except restfs_client.errors.Unauthorized as error:
            logging.error(f'Cannot login as administrator: {error}')
            return UNAUTHORIZED
    elif user_options.user:
        if token is None:
            token = getpass.getpass(f'Enter password for {user_options.user}: ')
        try:
            user = restfs_client.new_User(user_options.user, token, attached_service=auth_service)
        except restfs_client.errors.ConnectionError as error:
            logging.error(f'Cannot connect to the authorization service: {error}')
            return CONNECTION_ERROR
        except restfs_client.errors.Unauthorized as error:
            logging.error(f'Cannot login as the given user: {error}')
            return UNAUTHORIZED
    else:
        user = None

    if auth_service and blob_service and dirs_service and user:
        logging.debug('Automount root folder...')
        mount = RestFS(auth_service.base_url, blob_service.base_url, dirs_service.base_url, user)
    else:
        mount = None

    # Prepare input
    script_files = []
    if len(user_options.SCRIPT) == 0:
        logging.debug('Enable interactive shell')
        script_files.append(sys.stdin)
    else:
        logging.debug('Script execution mode')
        for filename in user_options.SCRIPT:
            script_files.append(open(filename, 'r'))

    # Start execution
    output = StringIO()
    interactive = False
    raw_input = False

    for input_file in script_files:
        if input_file is sys.stdin:
            raw_input = True
            if sys.stdin.isatty():
                interactive = True
                output = sys.stdout
        shell = RestFSShell(stdin=input_file, stdout=output)
        shell.auth = auth_service
        shell.blob = blob_service
        shell.dirs = dirs_service
        shell.user = user
        shell.mount = mount

        shell.use_rawinput = raw_input
        shell.interactive = interactive
        shell.cmdloop()

    # Close and exit
    for file_descriptor in script_files:
        if file_descriptor is sys.stdin:
            continue
        file_descriptor.close()
    return exit_code


def parse_commandline():
    '''Parse and check commandline'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('SCRIPT', nargs='*', help='RestFS scripts to run. Interactive shell if omited.')
    parser.add_argument('--version', action='version', version=__version__)

    user = parser.add_argument_group('User options')
    user.add_argument('-A', '--admin', default=False, action='store_true', dest='force_admin', help='Force admin mode.')
    user.add_argument('-u', '--user', default=None, action='store', dest='user', help='Use given user.')
    user.add_argument('-t', '--token', default=None, action='store', dest='token', help='Use given admin token or password.')

    auth = parser.add_argument_group('Authentication service')
    auth.add_argument('-a', '--auth-url', default=None, dest='auth_url', help='Use given authentication service.')

    blob = parser.add_argument_group('Blob service')
    blob.add_argument('-b', '--blob-url', default=None, dest='blob_url', help='Use given blob service.')

    dirs = parser.add_argument_group('Directory service')
    dirs.add_argument('-d', '--dirs-url', default=None, dest='dirs_url', help='Use given directory service.')

    log = parser.add_argument_group('Logging settings')
    log.add_argument('--debug', default=False, action='store_true', dest='debug', help='Increase verbose.')
    log.add_argument('-l', '--log-file', default=None, dest='log_file', help='Dump log into a given file.')

    args = parser.parse_args()
    if args.force_admin and (args.user not in [None, 'admin']):
        logging.error('Cannot force admin mode and user')
        return
    if args.user == 'admin':
        args.force_admin = True

    return args


if __name__ == '__main__':
    sys.exit(main())