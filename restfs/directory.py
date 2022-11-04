'''
    Interfaces para el acceso al servicio de directorio
'''

class DirectoryService:
    '''Cliente de acceso al servicio de directorio'''

    def get_root(self, user):
        '''Obtiene el directorio raiz'''
        raise NotImplementedError()


class Directory:
    '''Cliente de acceso a un directorio'''

    def list_directories(self):
        '''Obtiene una lista de todos los subdirectorios del directorio'''
        raise NotImplementedError()

    def new_directory(self, directory_name):
        '''Crea un nuevo subdirectorio en el directorio'''
        raise NotImplementedError()

    def remove_directory(self, directory_name):
        '''Elimina un subdirectorio del directorio'''
        raise NotImplementedError()

    def list_files(self):
        '''Obtiene una lista de ficheros del directorio'''
        raise NotImplementedError()

    def new_file(self, filename, file_url):
        '''Crea un nuevo fichero a partir de la URL de un blob'''
        raise NotImplementedError()

    def remove_file(self, filename):
        '''Elimina un fichero del directorio'''
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
