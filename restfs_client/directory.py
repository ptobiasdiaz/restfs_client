'''
    Interfaces para el acceso al servicio de directorio
'''

import json
import logging

import requests

from restfs_common.errors import NotAttached, Unauthorized, ConnectionError, ObjectNotFound, UnexpectedError
from restfs_common.constants import ROOT, DEFAULT_ENCODING, DIR_CHILDS, DIR_PARENT_ID, DIR_IDENTIFIER, FILES

import restfs_client
from restfs_client.auth import header_name


class DirectoryService:
    '''Cliente de acceso al servicio de directorio'''
    def __init__(self, uri):
        self._uri_ = uri[:-1] if uri.endswith('/') else uri

    @property
    def base_url(self):
        '''Return the base of the service'''
        return self._uri_

    def get(self, resource, headers=None, data=None):
        try:
            return requests.get(f'{self.base_url}/v1{resource}', headers=headers, data=data)
        except requests.exceptions.ConnectionError as error:
            logging.error(f'Failed to execute GET request: {error}')
            raise ConnectionError() from error

    def post(self, resource, headers=None, data=None):
        try:
            return requests.post(f'{self.base_url}/v1{resource}', headers=headers, data=data)
        except requests.exceptions.ConnectionError as error:
            logging.error(f'Failed to execute POST request: {error}')
            raise ConnectionError() from error

    def put(self, resource, headers=None, data=None):
        try:
            return requests.put(f'{self.base_url}/v1{resource}', headers=headers, data=data)
        except requests.exceptions.ConnectionError as error:
            logging.error(f'Failed to execute PUT request: {error}')
            raise ConnectionError() from error

    def delete(self, resource, headers=None, data=None):
        try:
            return requests.delete(f'{self.base_url}/v1{resource}', headers=headers, data=data)
        except requests.exceptions.ConnectionError as error:
            logging.error(f'Failed to execute DELETE request: {error}')
            raise ConnectionError() from error

    def get_root(self, user):
        '''Obtiene el directorio raiz'''
        return self.get_directory(ROOT, user)

    def get_directory(self, dir_id, user):
        '''Obtiene un directorio'''
        if not isinstance(user, (restfs_client.Administrator, restfs_client.User)):
            raise ValueError('user must be a User() or Administrator() instance')
        return Directory(dir_id, user, attached_service=self)

    def walk(self, abspath, user):
        '''Obtiene un directorio por su path'''
        if not isinstance(user, (restfs_client.Administrator, restfs_client.User)):
            raise ValueError('user must be a User() or Administrator() instance')
        steps = abspath.split('/')
        steps = list(filter(lambda x : x not in ['', '.'], steps))

        current_dir = self.get_root(user)
        for current_step in steps:
            if current_step == '..':
                next_dir_id = current_dir.parent
            else:
                next_dir_id = current_dir.directory_id(current_step)
            if next_dir_id == None:
                # "/.." --> "/"
                continue
            current_dir = self.get_directory(next_dir_id, user)
        return current_dir


class Directory:
    '''Cliente de acceso a un directorio'''
    def __init__(self, dir_id, owner=None, attached_service=None):
        self._identifier_ = dir_id
        self._owner_ = owner
        self._service_ = attached_service

        self._dir_info_ = None
        self._parent_ = None

    @property
    def identifier(self):
        return self._identifier_

    def _assert_is_attached_(self):
        if self._service_ is None:
            raise NotAttached()

    @property
    def dir_info(self):
        if self._dir_info_ is None:
            self._assert_is_attached_()
            headers = {header_name(self._owner_): self._owner_.token}
            result = self._service_.get(f'/directory/{self.identifier}', headers=headers)
            if result.status_code == 401:
                raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
            if result.status_code not in [200]:
                raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))
            try:
                result = json.loads(result.content.decode(DEFAULT_ENCODING))
            except Exception as error:
                raise UnexpectedError(str(error)) from error
            if (DIR_CHILDS not in result) or (DIR_PARENT_ID not in result):
                raise UnexpectedError('Missing mandatory key from service response')
            self._dir_info_ = result
        self._parent_ = self._dir_info_[DIR_PARENT_ID]
        return self._dir_info_

    @property
    def parent(self):
        if self._parent_ is None:
            self._parent_ = self.dir_info[DIR_PARENT_ID]
        return self._parent_

    def list_directories(self):
        '''Obtiene una lista de todos los subdirectorios del directorio'''
        self._assert_is_attached_()
        self._dir_info_ = None
        return list(self.dir_info[DIR_CHILDS].keys())

    def directory_id(self, directory_name):
        '''Obtiene el dir_id de un subdirectorio dado'''
        self._assert_is_attached_()
        self._dir_info_ = None
        if directory_name not in self.dir_info[DIR_CHILDS]:
            raise KeyError()
        return self.dir_info[DIR_CHILDS][directory_name]

    def new_directory(self, directory_name):
        '''Crea un nuevo subdirectorio en el directorio'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}

        result = self._service_.put(f'/directory/{self.identifier}/{directory_name}', headers=headers)

        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        elif result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        elif result.status_code not in [200]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

        try:
            result = json.loads(result.content.decode(DEFAULT_ENCODING))
        except Exception as error:
            raise UnexpectedError(str(error)) from error
        if DIR_IDENTIFIER not in result:
            raise UnexpectedError('Missing mandatory key from service')
        self._dir_info_[DIR_CHILDS][directory_name] = result[DIR_IDENTIFIER]
        return result[DIR_IDENTIFIER]

    def remove_directory(self, directory_name):
        '''Elimina un subdirectorio del directorio'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}

        result = self._service_.delete(f'/directory/{self.identifier}/{directory_name}', headers=headers)
        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        elif result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        elif result.status_code not in [204]:
            raise ObjectNotFound(result.content.decode(DEFAULT_ENCODING))

    def list_files(self):
        '''Obtiene una lista de ficheros del directorio'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}

        result = self._service_.get(f'/files/{self.identifier}', headers=headers)
        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        elif result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        elif result.status_code not in [200]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

        try:
            result = json.loads(result.content.decode(DEFAULT_ENCODING))
        except Exception as error:
            raise UnexpectedError(str(error)) from error
        if (FILES not in result):
            raise UnexpectedError('Missing mandatory key from service response')
        return result[FILES]

    def new_file(self, filename, blob_url):
        '''Crea un nuevo fichero y lo asocia a un blob'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token, 'content-type': 'application/json'}
        request = json.dumps({'URL': blob_url})
        result = self._service_.put(f'/files/{self.identifier}/{filename}', headers=headers, data=request)

        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        elif result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        elif result.status_code not in [200, 201]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def get_file(self, filename):
        '''Obtiene la url de un fichero'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token, 'content-type': 'application/json'}
        result = self._service_.get(f'/files/{self.identifier}/{filename}', headers=headers)

        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        elif result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        elif result.status_code not in [200, 201]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))
        return result.content.decode(DEFAULT_ENCODING)

    def remove_file(self, filename):
        '''Elimina un fichero del directorio'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token, 'content-type': 'application/json'}
        result = self._service_.delete(f'/files/{self.identifier}/{filename}', headers=headers)

        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        elif result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        elif result.status_code not in [200, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def add_read_permission_to(self, user):
        '''Permite al usuario dado leer el directorio'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}
        result = self._service_.put(f'/directory/{self.identifier}/readable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def revoke_read_permission_to(self, user):
        '''Elimina al usuario dado de la lista de permiso de lectura'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}
        result = self._service_.delete(f'/directory/{self.identifier}/readable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def add_write_permission_to(self, user):
        '''Permite al usuario dado escribir en el directorio'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}
        result = self._service_.put(f'/directory/{self.identifier}/writable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Directory {self.identifier} not found')
        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def revoke_write_permission_to(self, user):
        '''Elimina al usuario dado de la lista de permiso de escritura'''
        self._assert_is_attached_()
        headers = {header_name(self._owner_): self._owner_.token}
        result = self._service_.delete(f'/directory/{self.identifier}/writable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Blob #{self.identifier}')
        if result.status_code == 401:
            raise Unauthorized(self._owner_.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))
