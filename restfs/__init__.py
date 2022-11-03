#!/usr/bin/env python3

'''
    Factories for restfs client classes
'''

from typing import Union
from restfs.auth import AuthService, Administrator, User
from restfs.blob import BlobService, Blob
from restfs.directory import DirectoryService, Directory


## Service access factory ##

def get_AuthService(uri:str) -> AuthService:
    '''Given a URI to the API REST (for instance, "http://127.0.0.1:5000/v1"), get instance of an AuthService()'''
    raise NotImplementedError()


def get_BlobService(uri:str) -> BlobService:
    '''Given a URI to the API REST (for instance, "http://127.0.0.1:5000/v1"), get instance of a BlobService()'''
    raise NotImplementedError()


def get_DirectoryService(uri:str) -> DirectoryService:
    '''Given a URI to the API REST (for instance, "http://127.0.0.1:5000/v1"), get instance of a DirectoryService()'''
    raise NotImplementedError()


## Auth service items ##

def new_Administrator(admin_token:str, attached_service:Union[None, AuthService]) -> Administrator:
    '''Given an administrator token and AuthService() instance (optional), get instance of an Administrator()'''
    raise NotImplementedError()


def new_User(username:str, password:Union[None, str], attached_service:Union[None, AuthService]) -> User:
    '''Given an user name, password (optional) and AuthService() instance (optional), get instance of an User()'''
    raise NotImplementedError()


## Blob service items ##

def new_Blob(blob_id:str, attached_service:BlobService, user:str) -> Blob:
    '''Given a blob identifier, a BlobService instance and the user, get intance of a Blob()'''
    raise NotImplementedError()


## Directory service items ##

def new_Directory(directory_id, attached_service:DirectoryService) -> Directory:
    '''Given a directory identifier and a DirectoryService instance, get intance of a Directory()'''
    raise NotImplementedError()
