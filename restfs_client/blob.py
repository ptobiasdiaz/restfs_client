'''
    Interfaces para el acceso a la API rest del servicio de blobs
'''

import uuid
import shutil
import logging
import os.path

import requests
import validators

from requests_toolbelt import MultipartEncoder

from restfs_common.errors import NotAttached, Unauthorized, ConnectionError, ObjectNotFound,\
    UnexpectedError
from restfs_common.constants import DEFAULT_ENCODING

import restfs_client
from restfs_client.auth import header_name


class BlobService:
    '''Cliente de acceso al servicio de blobbing'''
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

    def new_blob(self, local_filename, user):
        '''Crea un nuevo blob usando el usuario establecido'''
        blob_id = str(uuid.uuid4())
        headers = {header_name(user): user.token}
        mp = MultipartEncoder(
            fields={
                blob_id: (os.path.basename(local_filename), open(local_filename, 'rb'), 'application/octet-stream')
            }
        )
        headers['content-type'] = mp.content_type
        result = self.put(f'/blob/{blob_id}', headers=headers, data=mp)
        if result.status_code not in [200, 201, 204]:
            raise Unauthorized(user.user, reason=result.content.decode(DEFAULT_ENCODING))
        return Blob(blob_id, owner=user, attached_service=self)

    def get_blob(self, blob_id, user):
        '''Obtiene un blob usando el usuario indicado'''
        if not isinstance(user, (restfs_client.Administrator, restfs_client.User)):
            raise ValueError('user must be a User() or Administrator() instance')
        return Blob(blob_id, owner=user, attached_service=self)

    def remove_blob(self, blob_id, user=None):
        '''Intenta eliminar un blob usando el usuario dado'''
        if isinstance(blob_id, Blob):
            request_url = f'/blob/{blob_id.identifier}'
            if not user:
                user = blob_id.owner
        elif isinstance(blob_id, str):
            if user is None:
                raise ValueError('User cannot be None is blob is a string instance')
            if validators.url(blob_id):
                request_url = blob_id
            else:
                request_url = f'/blob/{blob_id}'
        else:
            raise ValueError(f'Unsupported value type for blob_id ({type(blob_id)})')
        headers = {header_name(user): user.token}
        result = self.delete(request_url, headers=headers)
        if result.status_code == 404:
            raise Unauthorized(user.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 204]:
            raise ObjectNotFound(f'Blob #{blob_id}')

    def download_blob(self, blob_url, user, local_filename):
        '''Descarga un blob a un fichero local'''
        headers = {header_name(user.user): user.token}

        with requests.get(blob_url, stream=True, headers=headers) as conn:
            if conn.status_code == 404:
                raise ObjectNotFound(f'Blob #{self.identifier}')
            if conn.status_code == 401:
                raise Unauthorized(self.owner.user, conn.content.decode(DEFAULT_ENCODING))
            if conn.status_code not in [200]:
                raise UnexpectedError(conn.content.decode(DEFAULT_ENCODING))
            with open(local_filename, 'wb') as fd:
                shutil.copyfileobj(conn.raw, fd)

class Blob:
    '''Cliente para controlar un blob'''
    def __init__(self, blob_id, owner=None, attached_service=None):
        self._identifier_ = blob_id
        self._owner_ = owner
        self._service_ = attached_service

    @property
    def identifier(self):
        '''Retorna el identificador del blob'''
        return self._identifier_

    @property
    def owner(self):
        '''Retorna el usuario del blob'''
        return self._owner_

    @property
    def url(self):
        '''Retorna la URL de descarga'''
        self._assert_is_attached_()
        return f'{self._service_.base_url}/v1/blob/{self.identifier}'

    @property
    def is_online(self):
        '''Comprueba si el blob existe'''
        self._assert_is_attached_()
        try:
            result = self._service_.get(f'/blob/stats/{self.identifier}')
        except Exception as error:
            logging.error(f'Cannot check blob: {error}')
            return False
        return result.status_code in [200, 204]

    def _assert_is_attached_(self):
        if self._service_ is None:
            raise NotAttached()

    def dump_to(self, local_filename):
        '''Vuelca los datos del blob en un archivo local'''
        self._assert_is_attached_()
        self._service_.download_blob(self.url, self.owner, local_filename)

    def refresh_from(self, local_filename):
        '''Reemplaza el blob por el contenido del fichero local'''
        self._assert_is_attached_()
        headers = {header_name(self.owner): self.owner.token}
        mp = MultipartEncoder(
            fields={
                self.identifier: (os.path.basename(local_filename), open(local_filename, 'rb'), 'application/octet-stream')
            }
        )
        headers['content-type'] = mp.content_type
        result = self._service_.post(f'/blob/{self.identifier}', headers=headers, data=mp)
        if result.status_code == 404:
            raise ObjectNotFound(f'Blob #{self.identifier}')
        if result.status_code == 401:
            raise Unauthorized(self.owner.user, reason=result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def add_read_permission_to(self, user):
        '''Permite al usuario dado leer el blob'''
        self._assert_is_attached_()
        headers = {header_name(self.owner): self.owner.token}
        result = self._service_.put(f'/blob/{self.identifier}/readable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Blob #{self.identifier}')
        if result.status_code == 401:
            raise Unauthorized(self.owner.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def revoke_read_permission_to(self, user):
        '''Elimina al usuario dado de la lista de permiso de lectura'''
        self._assert_is_attached_()
        headers = {header_name(self.owner): self.owner.token}
        result = self._service_.delete(f'/blob/{self.identifier}/readable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Blob #{self.identifier}')
        if result.status_code == 401:
            raise Unauthorized(self.owner.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def add_write_permission_to(self, user):
        '''Permite al usuario dado escribir el blob'''
        self._assert_is_attached_()
        headers = {header_name(self.owner): self.owner.token}
        result = self._service_.put(f'/blob/{self.identifier}/writable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Blob #{self.identifier}')
        if result.status_code == 401:
            raise Unauthorized(self.owner.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def revoke_write_permission_to(self, user):
        '''Elimina al usuario dado de la lista de permiso de escritura'''
        self._assert_is_attached_()
        headers = {header_name(self.owner): self.owner.token}
        result = self._service_.delete(f'/blob/{self.identifier}/writable_by/{user}', headers=headers)
        if result.status_code == 404:
            raise ObjectNotFound(f'Blob #{self.identifier}')
        if result.status_code == 401:
            raise Unauthorized(self.owner.user, result.content.decode(DEFAULT_ENCODING))
        if result.status_code not in [200, 201, 204]:
            raise UnexpectedError(result.content.decode(DEFAULT_ENCODING))

    def __str__(self) -> str:
        return f'Blob #{self.identifier}'