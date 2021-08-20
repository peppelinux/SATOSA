class SatosaOidcStorage(object):

    def get_client_by_id(self, client_id:str, expired:bool = True):
        raise NotImplementedError()
