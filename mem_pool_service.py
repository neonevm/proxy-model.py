from proxy.mempool.mempool_service import MemPoolService

mempool_service = MemPoolService()

mempool_service.start()
mempool_service.wait()


