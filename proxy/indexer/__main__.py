from . import IndexerApp

if __name__ == '__main__':
    indexer_app = IndexerApp()
    exit_code = indexer_app.run()
    exit(exit_code)
