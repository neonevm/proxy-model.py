from logged_groups import logged_group

from ..environment import SOLANA_URL, EVM_LOADER_ID
from ..common_neon import NeonApp, INeonAppImpl

from .indexer import Indexer


@logged_group("neon.Indexer")
class IndexerApp(NeonApp, INeonAppImpl):

    def __init__(self):

        self.info(f"""Running indexer with params:
                  solana_url: {SOLANA_URL},
                  evm_loader_id: {EVM_LOADER_ID}""")

        self.indexer = Indexer(SOLANA_URL)

    def run_impl(self):
        self.indexer.run()


