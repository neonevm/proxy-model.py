class EthereumError(Exception):
    def __init__(self, message: str, code=-32000, data=None):
        self.code = code
        self.message = message
        self.data = data

    def get_error(self):
        error = {'code': self.code, 'message': self.message}
        if self.data:
            error['data'] = self.data
        return error


class InvalidParamError(EthereumError):
    def __init__(self, message, data=None):
        EthereumError.__init__(self, message=message, code=-32602, data=data)


class ALTError(RuntimeError):
    pass


class BadResourceError(Exception):
    pass


class BlockedAccountsError(Exception):
    pass


class NodeBehindError(Exception):
    def __int__(self):
        super().__init__('The Solana node is not synchronized with a Solana cluster.')


class SolanaUnavailableError(Exception):
    def __int__(self):
        super().__init__('The Solana node is unavailable.')


class NonceTooLowError(Exception):
    pass


class NoMoreRetriesError(Exception):
    def __int__(self):
        super().__init__('The transaction is too complicated. No more retries to complete the Neon transaction.')


class CUBudgetExceededError(Exception):
    def __int__(self):
        super().__init__('The transaction is too complicated. Solana`s computing budget is exceeded.')


class InvalidIxDataError(Exception):
    def __int__(self):
        super().__init__('Wrong instruction data.')


class RequireResizeIterError(Exception):
    def __int__(self):
        super().__init__('Transaction requires resize iterations.')
