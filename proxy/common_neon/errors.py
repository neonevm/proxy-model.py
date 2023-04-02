from __future__ import annotations

from typing import Dict, Any


class EthereumError(BaseException):
    def __init__(self, message: str, code=-32000, data=None):
        super().__init__(message, code, data)
        self._code = code
        self._msg = message
        self._data = data

    def get_error(self) -> Dict[str, Any]:
        error = {'code': self._code, 'message': self._msg}
        if self._data:
            error['data'] = self._data
        return error

    def __str__(self) -> str:
        return self._msg


class InvalidParamError(EthereumError):
    def __init__(self, message: str, code=-32602, data=None):
        EthereumError.__init__(self, message=message, code=code, data=data)


class ALTError(BaseException):
    pass


class RescheduleError(BaseException):
    pass


class BadResourceError(RescheduleError):
    pass


class BlockedAccountsError(RescheduleError):
    pass

    def __str__(self) -> str:
        return 'Blocked accounts error'


class NodeBehindError(RescheduleError):
    def __init__(self, slots_behind: int):
        super().__init__(slots_behind)
        self._slots_behind = slots_behind

    def __str__(self) -> str:
        return f'The Solana node is behind by {self._slots_behind} from the Solana cluster'


class SolanaUnavailableError(RescheduleError):
    pass


class NoMoreRetriesError(RescheduleError):
    def __str__(self) -> str:
        return 'The Neon transaction is too complicated. No more retries to complete the Neon transaction'


class BlockHashNotFound(RescheduleError):
    def __str__(self) -> str:
        return 'Blockhash not found'


class CommitLevelError(RescheduleError):
    def __init__(self, base_level: str, level: str):
        super().__init__(base_level, level)
        self._base_level = base_level
        self._level = level

    def __str__(self) -> str:
        return f"Current level '{self._level}' is less than '{self._base_level}'"


class NonceTooLowError(BaseException):
    _empty_sender = '?'

    def __init__(self, sender: str, tx_nonce: int, state_tx_cnt: int):
        super().__init__(sender, tx_nonce, state_tx_cnt)
        self._sender = sender
        self._tx_nonce = tx_nonce
        self._state_tx_cnt = state_tx_cnt

    @staticmethod
    def init_no_sender(tx_nonce: int, state_tx_cnt: int):
        return NonceTooLowError(NonceTooLowError._empty_sender, tx_nonce, state_tx_cnt)

    def has_sender(self) -> bool:
        return self._sender != self._empty_sender

    def init_sender(self, sender: str) -> NonceTooLowError:
        return NonceTooLowError(sender, self._tx_nonce, self._state_tx_cnt)

    def __str__(self) -> str:
        return f'nonce too low: address {self._sender}, tx: {self._tx_nonce} state: {self._state_tx_cnt}'


class NonceTooHighError(BaseException):
    def __str__(self) -> str:
        return 'tx nonce is too high for execution'


class BigTxError(BaseException):
    def __str__(self) -> str:
        return 'transaction is too big for execution'


class WrongStrategyError(BaseException):
    def __str__(self) -> str:
        return 'execution strategy is unsuitable'


class CUBudgetExceededError(WrongStrategyError):
    def __str__(self) -> str:
        return 'The Neon transaction is too complicated. Solana`s computing budget is exceeded'


class InvalidIxDataError(WrongStrategyError):
    def __str__(self) -> str:
        return 'Wrong instruction data'


class RequireResizeIterError(WrongStrategyError):
    def __str__(self) -> str:
        return 'Transaction requires resize iterations'
