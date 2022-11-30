#!/usr/bin/env python

'''
    Rest FS: filesystem view
'''

import os.path


from restfs_client import get_AuthService, get_BlobService, get_DirectoryService


class RestFS:
    '''Filesystem implementation os RestFS'''
    def __init__(self, auth: str, blob: str, dirs: str, user):
        self._auth_ = get_AuthService(auth)
        self._blob_ = get_BlobService(blob)
        self._dirs_ = get_DirectoryService(dirs)

        self._user_ = user

        self._cwd_ = self._dirs_.get_root(self._user_)
        self._path_ = '/'

    @property
    def current_path(self):
        '''Return current path'''
        return self._path_

    @property
    def current_directory(self):
        '''Return CWD'''
        return self._cwd_

    @property
    def directories(self):
        '''List of subdirectories of the CWD'''
        return self._cwd_.list_directories()

    def change_directory(self, abspath):
        '''Change the CWD to a given path'''
        self._cwd_ = self._dirs_.walk(abspath, self._user_)
        self._path_ = abspath

    def create_directory(self, directory_name):
        '''Create new directory in the CWD'''
        self._cwd_.new_directory(directory_name)

    def remove_directory(self, directory_name):
        '''Remove directory from the CWD'''
        self._cwd_.remove_directory(directory_name)

    def upload_file(self, local_filename, remote_name=None):
        '''Create a new remote file in the CWD uploading the given local file'''
        blob = self._blob_.new_blob(local_filename, self._user_)
        if remote_name is None:
            remote_name = os.path.basename(local_filename)
        self._cwd_.new_file(remote_name, blob.url)
        return blob

    def download_file(self, remote_filename, local_filename=None):
        '''Create a new local file using a remote filename from CWD'''
        if local_filename is None:
            local_filename = os.path.basename(remote_filename)
        blob_url = self._cwd_.get_file(remote_filename)
        self._blob_.download_blob(blob_url, self._user_, local_filename)

    def remove_file(self, filename):
        '''Remove a file from the CWD'''
        blob_url = self._cwd_.get_file(filename)
        self._cwd_.remove_file(filename)
        self._blob_.remove_blob(blob_url, self._user_)

    @property
    def files(self):
        '''List of files of the CWD'''
        return self._cwd_.list_files()
