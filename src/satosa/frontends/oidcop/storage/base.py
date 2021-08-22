class SatosaOidcStorage(object):

    def get_client_by_id(self, client_id:str, expired:bool = True):
        raise NotImplementedError()

    def store_session_to_db(self, ses_man_dump:dict, **kwargs):
        raise NotImplementedError()

    def load_session_from_db(self, req_args, http_headers, session_manager, **kwargs):
        raise NotImplementedError()
