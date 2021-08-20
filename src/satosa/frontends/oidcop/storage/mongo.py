import pymongo

from . base import SatosaOidcStorage


class Mongodb(SatosaOidcStorage):

    def __init__(self, storage_conf:dict, url:str, connection_params: dict = None):
        self.storage_conf = storage_conf
        self.url = url
        self.connection_params = connection_params
        self.client = None
        self._connect()

        self.db = getattr(self.client, storage_conf['db_name'])
        self.client_db = self.db[storage_conf['collections']['client']]
        self.session_db = self.db[storage_conf['collections']['session']]

    def _connect(self):
        if not self.client or not self.client.server_info():
            self.client = pymongo.MongoClient(
                self.url, **self.connection_params)

    def get_client_by_id(self, client_id):
        self._connect()
        res = self.client_db.find(
            {'client_id': client_id}
        )

        # improvement: unique index on client_id in client collection
        if res.count():
            # it returns the first one
            return res.next()
