from typing import Iterator, Optional, List, Type

from ..common_neon.utils import NeonTxInfo
from ..common_neon.constants import SYS_PROGRAM_ID

from ..indexer.neon_ix_decoder import DummyIxDecoder
from ..indexer.indexed_objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonAccountInfo


class WriteIxDecoder(DummyIxDecoder):
    _name = 'Write'
    _ix_code = 0x00
    _is_deprecated = True

    def _decode_data_chunk(self) -> NeonIndexedHolderInfo.DataChunk:
        ix_data = self.state.sol_neon_ix.ix_data
        # No enough bytes to get length of chunk
        if len(ix_data) < 17:
            return NeonIndexedHolderInfo.DataChunk.init_empty()

        return NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix_data[4:8], 'little'),
            length=int.from_bytes(ix_data[8:16], 'little'),
            data=ix_data[16:],
        )

    def execute(self) -> bool:
        chunk = self._decode_data_chunk()
        if not chunk.is_valid():
            return self._decoding_skip(f'bad data chunk {chunk}')

        ix = self.state.sol_neon_ix
        if ix.account_cnt < 1:
            return self._decoding_skip(f'no enough accounts {ix.account_cnt}')

        account = ix.get_account(0)
        block = self.state.neon_block
        holder = block.find_neon_holder(account, ix) or block.add_neon_holder(account, ix)

        # Write the received chunk into the holder account buffer
        holder.add_data_chunk(chunk)
        return self._decoding_success(holder, f'add Neon tx data chunk {chunk}')


class WriteWithHolderIxDecoder(WriteIxDecoder):
    _name = 'WriteWithHolder'
    _ix_code = 0x12
    _is_deprecated = True

    def _decode_data_chunk(self) -> NeonIndexedHolderInfo.DataChunk:
        # No enough bytes to get length of chunk
        ix = self.state.sol_neon_ix
        ix_data = ix.ix_data
        if len(ix_data) < 22:
            return NeonIndexedHolderInfo.DataChunk.init_empty()

        return NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix_data[9:13], 'little'),
            length=int.from_bytes(ix_data[13:21], 'little'),
            data=ix.ix_data[21:]
        )


class CreateAccountIxDecoder(DummyIxDecoder):
    _name = 'CreateAccount'
    _ix_code = 0x02
    _is_deprecated = True

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 41:
            return self._decoding_skip(f'not enough data to get the Neon account {len(ix.ix_data)}')

        neon_account = "0x" + ix.ix_data[8+8+4:][:20].hex()
        pda_account = ix.get_account(1)
        code_account = ix.get_account(3)
        if code_account == str(SYS_PROGRAM_ID) or code_account == '':
            code_account = None

        account_info = NeonAccountInfo(
            neon_account, pda_account, code_account,
            ix.block_slot, None, ix.sol_sig
        )

        self.state.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create Neon account')


class CallFromRawIxDecoder(DummyIxDecoder):
    _name = 'CallFromRaw'
    _ix_code = 0x05
    _is_deprecated = True

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 92:
            return self._decoding_skip('no enough data to get the Neon tx')

        rlp_sig = ix.ix_data[25:90]
        rlp_unsig_data = ix.ix_data[90:]

        neon_tx = NeonTxInfo.from_unsig_data(rlp_sig, rlp_unsig_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        key = NeonIndexedTxInfo.Key.from_ix(ix)
        tx = self.state.neon_block.add_neon_tx(key, neon_tx, ix)
        return self._decode_tx(tx, 'call raw Neon tx')


class OnResultIxDecoder(DummyIxDecoder):
    _name = 'OnResult'
    _ix_code = 0x06
    _is_deprecated = True

    def execute(self) -> bool:
        if not self.state.has_neon_tx():
            return self._decoding_skip('no Neon tx to add result')

        ix = self.state.sol_neon_ix
        tx = self.state.neon_tx
        log = ix.ix_data

        status = '0x1' if log[1] < 0xd0 else '0x0'
        gas_used = hex(int.from_bytes(log[2:10], 'little'))
        return_value = log[10:].hex()

        tx.neon_tx_res.fill_result(status=status, gas_used=gas_used, return_value=return_value)
        tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
        return self._decode_tx(tx, 'Neon tx result')


class OnEventIxDecoder(DummyIxDecoder):
    _name = 'OnEvent'
    _ix_code = 0x07
    _is_deprecated = True

    def execute(self) -> bool:
        if not self.state.has_neon_tx():
            return self._decoding_skip('no Neon tx to add events')

        ix = self.state.sol_neon_ix
        tx = self.state.neon_tx
        log = ix.ix_data

        address = log[1:21]
        topic_cnt = int().from_bytes(log[21:29], 'little')
        topic_list = []
        pos = 29
        for _ in range(topic_cnt):
            topic_bin = log[pos:pos + 32]
            topic_list.append('0x' + topic_bin.hex())
            pos += 32
        data = log[pos:]

        tx_log_idx = len(tx.neon_tx_res.log_list)
        rec = {
            'address': '0x' + address.hex(),
            'topics': topic_list,
            'data': '0x' + data.hex(),
            'transactionHash': tx.neon_tx.sig,
            'transactionLogIndex': hex(tx_log_idx),
            # 'logIndex': hex(tx_log_idx), # set when transaction found
            # 'transactionIndex': hex(ix.idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }

        tx.neon_tx_res.append_record(rec)
        return self._decode_tx(tx, 'Neon tx event')


class PartialCallIxDecoder(DummyIxDecoder):
    _name = 'PartialCallFromRawEthereumTX'
    _ix_code = 0x09
    _is_deprecated = True

    def execute(self) -> bool:
        first_blocked_account_idx = 7

        ix = self.state.sol_neon_ix
        if ix.account_cnt < first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')
        if len(ix.ix_data) < 100:
            return self._decoding_skip('no enough data to get arguments')

        rlp_sig = ix.ix_data[33:98]
        rlp_unsig_data = ix.ix_data[98:]

        neon_tx = NeonTxInfo.from_unsig_data(rlp_sig, rlp_unsig_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        block = self.state.neon_block

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(first_blocked_account_idx)

        key = NeonIndexedTxInfo.Key.from_storage_account(storage_account, iter_blocked_account)
        tx = block.find_neon_tx(key, ix)
        if (tx is not None) and (tx.neon_tx.sig != neon_tx.sig):
            self._decoding_fail(tx, f'Neon tx sign {neon_tx.sig} != {tx.neon_tx.sig}')
            tx = None

        if tx is None:
            tx = block.add_neon_tx(key, neon_tx, ix)

        neon_step_cnt = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(neon_step_cnt)
        return self._decode_tx(tx, 'partial Neon tx call')


class PartialCallV02IxDecoder(PartialCallIxDecoder):
    _name = 'PartialCallFromRawEthereumTXv02'
    _ix_code = 0x13
    _is_deprecated = True


class PartialCallOrContinueIxDecoder(PartialCallIxDecoder):
    _name = 'PartialCallOrContinueFromRawEthereumTX'
    _ix_code = 0x0d
    _is_deprecated = True


class ContinueIxDecoder(DummyIxDecoder):
    _name = 'Continue'
    _ix_code = 0x0a
    _is_deprecated = True
    _first_blocked_account_idx = 5

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')
        if len(ix.ix_data) < 14:
            return self._decoding_skip('no enough data to get arguments')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(self._first_blocked_account_idx)

        key = NeonIndexedTxInfo.Key.from_storage_account(storage_account, iter_blocked_account)
        tx = self.state.neon_block.find_neon_tx(key, ix)
        if not tx:
            return self._decode_skip(f'no transaction at the storage {storage_account}')

        neon_step_cnt = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(neon_step_cnt)
        return self.decode_tx(tx, 'continue Neon tx call')


class ContinueV02IxDecoder(ContinueIxDecoder):
    _name = 'ContinueV02'
    _ix_code = 0x14
    _is_deprecated = True
    _first_blocked_account_idx = 6


class ExecuteTrxFromAccountIxDecoder(DummyIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterative'
    _ix_code = 0x0b
    _is_deprecated = True
    _first_blocked_account_idx = 5

    def _init_neon_tx_from_holder(self, holder_account: str,
                                  storage_account: str,
                                  iter_blocked_account: Iterator[str]) -> Optional[NeonIndexedTxInfo]:
        block = self._state.neon_block
        ix = self._state.sol_neon_ix

        key = NeonIndexedTxInfo.Key.from_storage_account(storage_account, iter_blocked_account)
        tx = block.find_neon_tx(key, ix)
        if tx is not None:
            return tx

        holder = block.find_neon_holder(holder_account, ix)
        if holder is None:
            self._decoding_skip(f'no holder account {holder_account}')
            return None

        rlp_sig = holder.data[0:65]
        rlp_len = int.from_bytes(holder.data[65:73], 'little')
        rlp_endpos = 73 + rlp_len
        rlp_unsig_data = holder.data[73:rlp_endpos]

        neon_tx = NeonTxInfo.from_unsig_data(rlp_sig, rlp_unsig_data)
        if neon_tx.error:
            self.warning(f'Neon tx rlp error: {neon_tx.error}')
            return None

        tx = block.add_neon_tx(key, neon_tx, ix)
        tx.set_holder_account(holder)
        self._decoding_done(holder, f'init Neon tx {tx.neon_tx} from holder')
        return tx

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        holder_account = ix.get_account(0)
        storage_account = ix.get_account(1)
        iter_blocked_account = ix.iter_account(self._first_blocked_account_idx)

        tx = self._init_neon_tx_from_holder(holder_account, storage_account, iter_blocked_account)
        if not tx:
            return self._decoding_skip(f'fail to init storage {storage_account} from holder {holder_account}')

        neon_step_cnt = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(neon_step_cnt)
        return self._decode_tx(tx, 'execute/continue Neon tx from holder')


class ExecuteTrxFromAccountV02IxDecoder(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeV02'
    _ix_code = 0x16
    _is_deprecated = True
    _first_blocked_account_idx = 7


class ExecuteOrContinueIxDecoder(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeOrContinue'
    _ix_code = 0x0e
    _is_deprecated = True
    _first_blocked_account_idx = 7


class ExecuteOrContinueNoChainIdIxDecoder(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'
    _ix_code = 0x1b
    _is_deprecated = True
    _first_blocked_account_idx = 7


class CancelIxDecoder(DummyIxDecoder):
    _name = 'Cancel'
    _ix_code = 0x0c
    _is_deprecated = True

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        first_blocked_account_idx = 3
        if ix.account_cnt < first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(first_blocked_account_idx)

        key = NeonIndexedTxInfo.Key.from_storage_account(storage_account, iter_blocked_account)
        tx = self.state.neon_block.find_neon_tx(key, ix)
        if not tx:
            return self._decoding_skip(f'cannot find tx in the storage {storage_account}')

        tx.neon_tx_res.fill_result(status='0x0', gas_used='0x0', return_value='')
        tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
        return self._decode_tx(tx, 'cancel Neon tx')


class CancelV02IxDecoder(CancelIxDecoder):
    _name = 'CancelV02'
    _ix_code = 0x15
    _is_deprecated = True


class ERC20CreateTokenAccountIxDecoder(DummyIxDecoder):
    _name = 'ERC20CreateTokenAccount'
    _ix_code = 0x0f
    _is_deprecated = True


class FinalizeIxDecode(DummyIxDecoder):
    _name = 'Finalize'
    _ix_code = 0x01
    _is_deprecated = True


class CallIxDecoder(DummyIxDecoder):
    _name = 'Call'
    _ix_code = 0x03
    _is_deprecated = True


class CreateAccountWithSeedIxDecoder(DummyIxDecoder):
    _name = 'CreateAccountWithSeed'
    _ix_code = 0x04
    _is_deprecated = True


class DepositIxDecoder(DummyIxDecoder):
    _name = 'Deposit'
    _ix_code = 0x19
    _is_deprecated = False


class MigrateAccountIxDecoder(DummyIxDecoder):
    _name = 'MigrateAccount'
    _ix_code = 0x19
    _is_deprecated = True


class UpdateValidsTableIxDecoder(DummyIxDecoder):
    _name = 'UpdateValidsTable'
    _ix_code = 0x17
    _is_deprecated = True


class WriteValueToDistributedStorageDecoder(DummyIxDecoder):
    _name = 'WriteValueToDistributedStorage'
    _ix_code = 0x1c
    _is_deprecated = True


class ConvertDataAccountFromV1ToV2Decoder(DummyIxDecoder):
    _name = 'ConvertDataAccountFromV1ToV2'
    _ix_code = 0x1d
    _is_deprecated = True


def get_neon_ix_decoder_deprecated_list() -> List[Type[DummyIxDecoder]]:
    return [
        WriteIxDecoder,
        FinalizeIxDecode,
        CreateAccountIxDecoder,
        CallIxDecoder,
        CreateAccountWithSeedIxDecoder,
        CallFromRawIxDecoder,
        OnResultIxDecoder,
        OnEventIxDecoder,
        PartialCallIxDecoder,
        ContinueIxDecoder,
        ExecuteTrxFromAccountIxDecoder,
        CancelIxDecoder,
        PartialCallOrContinueIxDecoder,
        ExecuteOrContinueIxDecoder,
        ERC20CreateTokenAccountIxDecoder,
        WriteWithHolderIxDecoder,
        PartialCallV02IxDecoder,
        ContinueV02IxDecoder,
        CancelV02IxDecoder,
        ExecuteTrxFromAccountV02IxDecoder,
        UpdateValidsTableIxDecoder,
        DepositIxDecoder,
        ExecuteOrContinueNoChainIdIxDecoder,
        WriteValueToDistributedStorageDecoder,
        ConvertDataAccountFromV1ToV2Decoder,
    ]
