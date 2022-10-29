'''
    Interfaces para el acceso a la API rest del servicio de blobs
'''

class BlobService:
    '''Cliente de acceso al servicio de blobbing'''

    def new_blob(self, local_filename, user):
        '''Crea un nuevo blob usando el usuario establecido'''
        raise NotImplementedError()

    def get_blob(self, blob_id, user):
        '''Obtiene un blob usando el usuario indicado'''
        raise NotImplementedError()

    def remove_blob(self, blob_id, user):
        '''Intenta eliminar un blob usando el usuario dado'''
        raise NotImplementedError()


class Blob:
    '''Cliente para controlar un blob'''

    @property
    def is_online(self):
        '''Comprueba si el blob existe'''
        raise NotImplementedError()

    def dump_to(self, local_filename):
        '''Vuelca los datos del blob en un archivo local'''
        raise NotImplementedError()

    def refresh_from(self, local_filename):
        '''Reemplaza el blob por el contenido del fichero local'''
        raise NotImplementedError()

    def add_read_permission_to(self, user):
        '''Permite al usuario dado leer el blob'''
        raise NotImplementedError()

    def revoke_read_permission_to(self, user):
        '''Elimina al usuario dado de la lista de permiso de lectura'''
        raise NotImplementedError()

    def add_write_permission_to(self, user):
        '''Permite al usuario dado escribir el blob'''
        raise NotImplementedError()

    def revoke_write_permission_to(self, user):
        '''Elimina al usuario dado de la lista de permiso de escritura'''
        raise NotImplementedError()
