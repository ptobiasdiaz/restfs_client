#!/usr/bin/env python3

'''
    Factories for restfs client classes
'''

from typing import Union

from restfs_client.auth import AuthService, Administrator, User
from restfs_client.blob import BlobService, Blob
from restfs_client.directory import DirectoryService, Directory


## Service access factory ##

def get_AuthService(uri:str) -> AuthService:
    '''Given a URI to the API REST (for instance, "http://127.0.0.1:5000/"), get instance of an AuthService()'''
    return AuthService(uri)


def get_BlobService(uri:str) -> BlobService:
    '''Given a URI to the API REST (for instance, "http://127.0.0.1:5000/"), get instance of a BlobService()'''
    return BlobService(uri)


def get_DirectoryService(uri:str) -> DirectoryService:
    '''Given a URI to the API REST (for instance, "http://127.0.0.1:5000/"), get instance of a DirectoryService()'''
    return DirectoryService(uri)


## Auth service items ##

def new_Administrator(admin_token:str, attached_service:Union[None, AuthService]) -> Administrator:
    '''Given an administrator token and AuthService() instance (optional), get instance of an Administrator()'''
    if attached_service is None:
        return Administrator(token=admin_token)
    return attached_service.administrator_login(admin_token)


def new_User(username:str, password:Union[None, str], attached_service:Union[None, AuthService]) -> User:
    '''Given an user name, password (optional) and AuthService() instance (optional), get instance of an User()'''
    if attached_service is None:
        return User(username, password)
    return attached_service.user_login(username, password)

## Blob service items ##

def new_Blob(blob_id:str, user:Union[None, Administrator, User], attached_service:Union[None, BlobService]) -> Blob:
    '''Given a blob identifier, a BlobService instance and the user, get intance of a Blob()'''
    if attached_service is None:
        return Blob(blob_id, owner=user)
    return attached_service.get_blob(blob_id, user)

## Directory service items ##

def new_Directory(directory_id:str, user:Union[None, Administrator, User], attached_service:DirectoryService) -> Directory:
    '''Given a directory identifier and a DirectoryService instance, get intance of a Directory()'''
    if attached_service is None:
        return Directory(directory_id, owner=user)
    return attached_service.get_directory(directory_id, user)
