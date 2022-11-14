'''
    Interfaces para el acceso a la API rest del servicio de autenticacion
'''

import json
import hashlib
import logging
import requests

from restfs_common.errors import NotAttached, Unauthorized, ConnectionError, ObjectAlreadyExists
from restfs_common.constants import ADMIN, ADMIN_TOKEN, USER_TOKEN, DEFAULT_ENCODING,\
    HASH_PASS, USER, TOKEN


def _compute_password_hash_(password):
    '''Compute SHA256 of the given password'''
    hasher = hashlib.sha256()
    hasher.update(password.encode(DEFAULT_ENCODING))
    return hasher.hexdigest()


def header_name(user):
    '''Get proper header name or raise an error'''
    if isinstance(user, Administrator):
        return ADMIN_TOKEN
    elif isinstance(user, User):
        return USER_TOKEN
    raise ValueError('user must be a User() or Administrator() instance')


class Administrator:
    '''Cliente de autenticacion como administrador'''

    def __init__(self, token, auth_service=None):
        self._token_ = token
        self._service_ = auth_service

    @property
    def user(self):
        return ADMIN

    @property
    def token(self):
        '''Retorna el token del administrador'''
        return self._token_

    def new_user(self, user, password=None):
        '''Crea un nuevo usuario'''
        if isinstance(user, User):
            password = user.password_hash
            user = user.user
        else:
            if password is None:
                raise ValueError('If user is a string value, the password is mandatory')
            password = _compute_password_hash_(password)
        if user == ADMIN:
            raise ObjectAlreadyExists(f'User "{ADMIN}"')
        if self._service_ is None:
            raise NotAttached()
        headers = {ADMIN_TOKEN: self.token, 'content-type': 'application/json'}
        request = json.dumps({HASH_PASS: password})
        result = self._service_.put(f'/user/{user}', headers=headers, data=request)
        if result.status_code not in [200, 201, 204]:
            raise Unauthorized(ADMIN, result.content.decode())
        return User(user, password, auth_service=self)

    def remove_user(self, username):
        '''Elimina un usuario'''
        user = user.user if isinstance(username, User) else username
        if self._service_ is None:
            raise NotAttached()
        if user == ADMIN:
            raise Unauthorized(ADMIN, 'Administrator user is mandatory')
        headers = {ADMIN_TOKEN: self.token}
        result = self._service_.delete(f'/user/{user}', headers=headers)
        if result.status_code not in [200, 204]:
            raise Unauthorized(ADMIN, result.content.decode())


class User:
    '''Cliente de autenticacion como usuario'''

    def __init__(self, user, password, token=None, auth_service=None):
        self._user_ = user
        self._pass_ = password
        self._token_ = token
        self._service_ = auth_service

    @property
    def user(self):
        return self._user_

    @property
    def password_hash(self):
        return _compute_password_hash_(self._pass_)

    def set_new_password(self, new_password):
        '''Cambia la contraseña del usuario'''
        if self._service_ is None:
            raise NotAttached()
        headers = {USER_TOKEN: self.token, 'content-type': 'application/json'}
        request = json.dumps({HASH_PASS: _compute_password_hash_(new_password)})
        result = self._service_.post(f'/user/{self._user_}', headers=headers, data=request)
        if result.status_code in [200, 204]:
            self._pass_ = new_password
            return
        raise Unauthorized(user=self._user_, reason=result.content.decode(DEFAULT_ENCODING))

    @property
    def token(self):
        '''Retorna el token del usuario'''
        if (self._token_ is None) and (self._service_ is None):
            raise NotAttached()
        if (self._token_ is None) and isinstance(self._service_, AuthService):
            dummy_user = self._service_.user_login(self._user_, self._pass_)
            self._token_ = dummy_user.token
        return self._token_

    def refresh_token(self):
        '''Solicita un nuevo token'''
        self._token_ = None
        return self.token


class AuthService:
    '''Cliente de acceso al servicio de autenticacion'''
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

    def user_of_token(self, token):
        '''Return username of the given token or error'''
        if token is None:
            raise Unauthorized(reason='no token')
        result = self.get(f'/token/{token}')
        if result.status_code == 404:
            raise Unauthorized(reason='wrong token')
        return json.loads(result.content.decode())[USER]

    def is_admin(self, token):
        '''Return is token is a valid administrator token'''
        try:
            self.administrator_login(token)
            return True
        except Unauthorized:
            return False

    def exists_user(self, username):
        '''Return if given user exists or not'''
        result = self.get(f'/user/{username}')
        return result.status_code in [200, 204]

    def administrator_login(self, token):
        '''Return Adminitrator() object or error'''
        headers = {ADMIN_TOKEN: token, 'content-type': 'application/json'}
        result = self.get('/user/admin', headers=headers)
        if result.status_code not in [200, 201, 204]:
            raise Unauthorized(ADMIN, 'invalid administrator token')
        return Administrator(token=token, auth_service=self)

    def user_login(self, username, password):
        '''Return User() object or error'''
        headers = {'content-type': 'application/json'}
        request = json.dumps({USER: username, HASH_PASS: _compute_password_hash_(password)})
        result = self.post('/user/login', headers=headers, data=request)
        if result.status_code not in [200, 201, 204]:
            raise Unauthorized(username, 'invalid user/password')
        token = json.loads(result.content.decode())[TOKEN]
        return User(user=username, password=password, token=token, auth_service=self)
