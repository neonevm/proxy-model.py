from proxy.indexer.solana_receipts_update import run_indexer, IndexerEvent, NewTokenAccountEvent
from multiprocessing import Process, Queue
import requests, os, signal
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class StopAirdropperEvent:
    pass

class Airdropper:
    def __init__(self, faucet_addr, faucet_port, airdrop_amount, event_queue):
        self.event_queue = event_queue
        self.faucet_request_url = f'http://{faucet_addr}:{faucet_port}/request_eth_token'
        self.airdrop_amount = airdrop_amount
        self.indexer = Process(target=run_indexer, args=(self.event_queue,))

    def should_process_address(self, address):
        return True

    def run(self):
        self.indexer.start()
        while (True):
            event = self.event_queue.get()
            if isinstance(event, NewTokenAccountEvent) and self.should_process_address(event.address):
                data = f'{{"wallet": "{event.address}", "amount": {self.airdrop_amount}}}'
                r = requests.post(self.faucet_request_url, data=data)
                if not r.ok:
                    logger.warning('Faucet response:', r.status_code)
            elif isinstance(event, StopAirdropperEvent):
                break

def run_airdropper(faucet_addr, faucet_port, airdrop_amount, event_queue):
    airdropper = Airdropper(faucet_addr, faucet_port, airdrop_amount, event_queue)
    airdropper.run()

if __name__ == "__main__":
    try:
        faucet_addr = os.environ['AIRDROP_FAUCET_ADDR']
        faucet_port = os.environ['AIRDROP_FAUCET_PORT']
        airdrop_amount = os.environ['AIRDROP_AMOUNT']
        event_queue = Queue()

        def stop_airdropper():
            event_queue.put(StopAirdropperEvent)

        signal.signal(signal.SIGINT, stop_airdropper)
        signal.signal(signal.SIGTERM, stop_airdropper)
        signal.signal(signal.SIGKILL, stop_airdropper)

        p = Process(target=run_airdropper, args=(faucet_addr, faucet_port, airdrop_amount, event_queue))
        p.start()
        p.join()
    except Exception as err:
        logger.error(f"Failed to start Airdropper: {err}")
