from ..indexer.base_db import BaseDB


class SolanaSignatures(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'solana_transaction_signatures')

    def add_signature(self, signature, slot):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO solana_transaction_signatures
                (slot, signature)
                VALUES(%s, %s) ON CONFLICT DO NOTHING''',
                (slot, signature))

    def remove_signature(self, signature):
        with self._conn.cursor() as cursor:
            cursor.execute(f'DELETE FROM solana_transaction_signatures WHERE signature = %s', (signature,))

    def get_minimal_tx(self):
        with self._conn.cursor() as cursor:
            cursor.execute(f'SELECT slot, signature FROM solana_transaction_signatures ORDER BY slot LIMIT 1')
            row = cursor.fetchone()
            if row is not None:
                return row[1]
            return None
