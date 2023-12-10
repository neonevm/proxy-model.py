from ..common_neon.evm_log_decoder import NeonLogTxEvent
from ..common_neon.neon_tx_result_info import NeonTxResultInfo


def _hex_to_bytes(_value: str) -> bytes:
    return bytes.fromhex(_value[2:])


def _hex_to_int(_value: str) -> int:
    return int(_value[2:], 16)


# TX: 0xe6f0782c013a37c3450e100508244353496cf6a0d1581dac4392b643463d04c2 from Ethereum Mainnet

test_tx_log_bloom = (
    '0x0000000104000000000000000000000000000080000000008000000000000000000000000000'
    '020008000000000000100000000000000000000000100000040008000000000000000000000800'
    '000000000000000000000000000000000000000000000000000000004000000000000000000000'
    '000000000000001000000000000000000000000000000000000000000000000000000000000000'
    '004000000004000000000000000000000000100000000000000000000000000000000000000000'
    '000200000000000000000004000000000000000080000000000000000000040000000000000000'
    '0000000000000000000000000000000000000000040000'
)


test_tx_res_info = NeonTxResultInfo(
    block_slot=_hex_to_int('0x11e2e76'),
    block_hash='0x807dd50334871b7c85ff551c1c7c082670029618973dc2723e74f6df936326ab',
    tx_idx=_hex_to_int('0x7a'),
    neon_sig='0xe6f0782c013a37c3450e100508244353496cf6a0d1581dac4392b643463d04c2',
    status=_hex_to_int('0x1'),
    gas_used=_hex_to_int('0x168d7'),
    sum_gas_used=_hex_to_int('0xa7dc37'),
    event_list=tuple([
        NeonLogTxEvent(
            NeonLogTxEvent.Type.Log,
            is_hidden=False,
            address=_hex_to_bytes('0xde30da39c46104798bb5aa3fe8b9e0e1f348163f'),
            topic_list=tuple(
                _hex_to_bytes(x)
                for x in (
                    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
                    '0x0000000000000000000000000e3efd5be54cc0f4c64e0d186b0af4b7f2a0e95f',
                    '0x000000000000000000000000e2de8854853c2cdd1fa9b4289b2e89aa9b0e62a1'
                )
            ),
            data=_hex_to_bytes('0x00000000000000000000000000000000000000000000000046c6d6faa27e0000'),
            block_slot=_hex_to_int('0x11e2e76'),
            block_hash='0x807dd50334871b7c85ff551c1c7c082670029618973dc2723e74f6df936326ab',
            neon_sig='0xe6f0782c013a37c3450e100508244353496cf6a0d1581dac4392b643463d04c2',
            neon_tx_idx=_hex_to_int('0x7a'),
            neon_tx_log_idx=_hex_to_int('0x105'),
        ),
        NeonLogTxEvent(
            NeonLogTxEvent.Type.Log,
            is_hidden=False,
            address=_hex_to_bytes('0xde30da39c46104798bb5aa3fe8b9e0e1f348163f'),
            topic_list=tuple(
                _hex_to_bytes(x)
                for x in (
                    '0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724',
                    '0x000000000000000000000000e2de8854853c2cdd1fa9b4289b2e89aa9b0e62a1',
                )
            ),
            data=_hex_to_bytes(
                '0x0000000000000000000000000000000000000000000000000de0b6b3a76400000000'
                '0000000000000000000000000000000000000000000054a78dae49e20000'
            ),
            block_slot=_hex_to_int('0x11e2e76'),
            block_hash='0x807dd50334871b7c85ff551c1c7c082670029618973dc2723e74f6df936326ab',
            neon_sig='0xe6f0782c013a37c3450e100508244353496cf6a0d1581dac4392b643463d04c2',
            neon_tx_idx=_hex_to_int('0x7a'),
            neon_tx_log_idx=_hex_to_int('0x106'),
        ),
        NeonLogTxEvent(
            NeonLogTxEvent.Type.Log,
            is_hidden=False,
            address=_hex_to_bytes('0x0e3efd5be54cc0f4c64e0d186b0af4b7f2a0e95f'),
            topic_list=tuple(
                _hex_to_bytes(x)
                for x in (
                    '0xdcf891885e788b94db6de05809e1c074e1396e919fa3ef010342de9dfbdd8361',
                )
            ),
            data=_hex_to_bytes(
                '0x00000000000000000000000000000000000000000000000000000'
                '00000000003000000000000000000000000e2de8854853c2cdd1fa9'
                'b4289b2e89aa9b0e62a100000000000000000000000000000000000'
                '000000000000046c6d6faa27e000000000000000000000000000000'
                '00000000000000000000000000000000000000'
            ),
            block_slot=_hex_to_int('0x11e2e76'),
            block_hash='0x807dd50334871b7c85ff551c1c7c082670029618973dc2723e74f6df936326ab',
            neon_sig='0xe6f0782c013a37c3450e100508244353496cf6a0d1581dac4392b643463d04c2',
            neon_tx_idx=_hex_to_int('0x7a'),
            neon_tx_log_idx=_hex_to_int('0x107'),
        ),
    ])
)

