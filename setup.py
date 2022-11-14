#!/usr/bin/env python3

'''Libreria de clientes para el proyecto RestFS'''

from setuptools import setup

setup(
    name='restfs-client',
    version='0.1',
    description=__doc__,
    packages=['restfs_client'],
    entry_points={
        'console_scripts': [
            'restfs_client=restfs_client.main:main'
        ]
    }
)
