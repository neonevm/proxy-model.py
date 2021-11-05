import psycopg
import os

POSTGRES_DB = os.environ.get("POSTGRES_DB", "neon-db")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "neon-proxy")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "neon-proxy")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")

try:
    from cPickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL
except ImportError:
    from pickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL


def encode(obj):
    """Serialize an object using pickle to a binary format accepted by SQLite."""
    return psycopg.Binary(dumps(obj, protocol=PICKLE_PROTOCOL))


def decode(obj):
    """Deserialize objects retrieved from SQLite."""
    return loads(bytes(obj))


class SQLDict(dict):
    def __init__(self, tablename='table', dbname=POSTGRES_DB, user=POSTGRES_USER, password=POSTGRES_PASSWORD, host=POSTGRES_HOST, encode=encode, decode=decode):
        self.encode = encode
        self.decode = decode
        self.tablename = tablename
        self.conn = psycopg.connect(dbname, user, password, host)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS
        {} (
            key TEXT UNIQUE,
            value BLOB
        )""".format(self.tablename))

    def close(self):
        self.conn.commit()
        self.conn.close()

    def __len__(self):
        REQUEST = 'SELECT COUNT(*) FROM {}'.format(self.tablename)
        rows = self.conn.execute(REQUEST).fetchone()[0]
        return rows if rows is not None else 0

    def iterkeys(self):
        REQUEST = 'SELECT key FROM {}'.format(self.tablename)
        c = self.conn.cursor()
        for key in c.execute(REQUEST):
            yield key[0]

    def itervalues(self):
        REQUEST = 'SELECT value FROM {}'.format(self.tablename)
        c = self.conn.cursor()
        for value in c.execute(REQUEST):
            yield self.decode(value[0])

    def iteritems(self):
        REQUEST = 'SELECT key, value FROM {}'.format(self.tablename)
        c = self.conn.cursor()
        for key, value in c.execute(REQUEST):
            yield key, self.decode(value)

    def keys(self):
        return list(self.iterkeys())

    def values(self):
        return list(self.itervalues())

    def items(self):
        return list(self.iteritems())

    def __contains__(self, key):
        REQUEST = 'SELECT 1 FROM {} WHERE key = ?'.format(self.tablename)
        return self.conn.execute(REQUEST, (key,)).fetchone() is not None

    def __getitem__(self, key):
        REQUEST = 'SELECT value FROM {} WHERE key = ?'.format(self.tablename)
        item = self.conn.execute(REQUEST, (key,)).fetchone()
        if item is None:
            raise KeyError(key)
        return self.decode(item[0])

    def __setitem__(self, key, value):
        REQUEST = 'REPLACE INTO {} (key, value) VALUES (?,?)'.format(self.tablename)
        self.conn.execute(REQUEST, (key, self.encode(value)))

    def __delitem__(self, key):
        REQUEST = 'DELETE FROM {} WHERE key = ?'.format(self.tablename)
        if key not in self:
            raise KeyError(key)
        self.conn.execute(REQUEST, (key,))

    def __iter__(self):
        return self.iterkeys()
