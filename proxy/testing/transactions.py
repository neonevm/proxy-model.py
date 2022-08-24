from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0xf8658080831fc02094e442c8a04cde867473ab5dd4c9f3dd369945023380b844'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x7DB850f3a9CA0de897018cBa1eb2c2c86B3A0C6C'

# Solana`s transaction for simple case airdrop
pre_token_airdrop_trx = {
    'blockTime': 1661371581,
    'meta': {
        'err': None,
        'fee': 10000,
        'innerInstructions': [
            {
                'index': 4,
                'instructions': [  # INNER INSTRUCTIONS OF CLAIM
                    {
                        'accounts': [
                            0,
                            2
                        ],
                        'data': '3Bxs4PckVVt51W8w',
                        'programIdIndex': 11
                    },
                    {
                        'accounts': [
                            0,
                            8
                        ],
                        'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL',
                        'programIdIndex': 11
                    },
                    {
                        'accounts': [
                            8,  # <== new token account
                            6,  # <== mint account
                            5
                        ],
                        'data': '61c59tWbmzV9e3A7GPqmmvSupf6MoE1jCAj8E93iRNmXS',
                        'programIdIndex': 7  # TOKEN INITIALIZE ACCOUNT 2
                    },
                    {
                        'accounts': [
                            1,
                            8,  # <== new ERC20 token account
                            3   # <== new Neon account
                        ],
                        'data': '3QK1PgBtAWnb',
                        'programIdIndex': 7  # TOKEN TRANSFER
                    }
                ]
            }
        ],
        'loadedAddresses': {
            'readonly': [

            ],
            'writable': [

            ]
        },
        'logMessages': [
            'Program ComputeBudget111111111111111111111111111111 invoke [1]',
            'Program ComputeBudget111111111111111111111111111111 success',
            'Program ComputeBudget111111111111111111111111111111 invoke [1]',
            'Program ComputeBudget111111111111111111111111111111 success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
            'Program log: Instruction: Approve',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2284 of 499944 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]',
            'Program log: Instruction: Execute Transaction from Instruction',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program log: Applies begin',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: InitializeAccount2',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3394 of 276156 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: Transfer',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3131 of 269758 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program data: TE9HMw== s0BDV7HHvcd92RP1KhTUE4miOsg= AwAAAAAAAAA= 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAAfbhQ86nKDeiXAYy6HrLCyGs6DGw=  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=',
            'Program log: Applies done',
            'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12',
            'Program data: UkVUVVJO Eg== EJkfAAAAAAA= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=',
            'Program log: Total memory occupied: 25881',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 235891 of 497604 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
        ],
        'postBalances': [
            999997945720,
            2039280,
            895880,
            1392000,
            93257040,
            1009200,
            1461600,
            953185920,
            2039280,
            1,
            0,
            1,
            8588640000,
            1
        ],
        'postTokenBalances': [
            {
                'accountIndex': 1,
                'mint': 'EL12Jzpv4wpxC2k13r92b8xtoqYWZPe8MEkQU3LfQU22',
                'owner': 'd8wjSokAHEM9V4hCiFao17TRR2piKJXYs9PEJt6rgbg',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '999999876544',
                    'decimals': 9,
                    'uiAmount': 999.999876544,
                    'uiAmountString': '999.999876544'
                }
            },
            {
                'accountIndex': 8,
                'mint': 'EL12Jzpv4wpxC2k13r92b8xtoqYWZPe8MEkQU3LfQU22',
                'owner': 'Fw1DwtaBHjMLuqaam2w2pv5UfC4dJgbgRus2NJt97Xb2',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '123456',
                    'decimals': 9,
                    'uiAmount': 0.000123456,
                    'uiAmountString': '0.000123456'
                }
            }
        ],
        'preBalances': [
            1000000000000,
            2039280,
            890880,
            1392000,
            93257040,
            1009200,
            1461600,
            953185920,
            0,
            1,
            0,
            1,
            8588640000,
            1
        ],
        'preTokenBalances': [
            {
                'accountIndex': 1,
                'mint': 'EL12Jzpv4wpxC2k13r92b8xtoqYWZPe8MEkQU3LfQU22',
                'owner': 'd8wjSokAHEM9V4hCiFao17TRR2piKJXYs9PEJt6rgbg',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '1000000000000',
                    'decimals': 9,
                    'uiAmount': 1000.0,
                    'uiAmountString': '1000'
                }
            }
        ],
        'rewards': [],
        'status': {
            'Ok': None
        }
    },
    'slot': 189,
    'transaction': {
        'message': {
            'accountKeys': [
                'd8wjSokAHEM9V4hCiFao17TRR2piKJXYs9PEJt6rgbg',  # <== client Neon account (calculated from eth address 0x7DB850f3a9CA0de897018cBa1eb2c2c86B3A0C6C)
                '765VK2fJNFHXFdUm34foQrDTrFbKZVRXyLuySDJZr3Jf',
                'BTnEnoNFNnosnzM8n6c6fss4U8E3dw9mSaBEHYvQ3Ysm',
                '95eUKdsNyKvwD1Ja9nbHGMecY2a9vR9XRKLaFN1Qw4AU',
                'Fw1DwtaBHjMLuqaam2w2pv5UfC4dJgbgRus2NJt97Xb2',
                'SysvarRent111111111111111111111111111111111',
                'EL12Jzpv4wpxC2k13r92b8xtoqYWZPe8MEkQU3LfQU22',
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'JCPSFHmaqSccAa2SH5Jkn4HS7rHBWy7UEUCu8ZmYtoWg',
                'KeccakSecp256k11111111111111111111111111111',
                'Sysvar1nstructions1111111111111111111111111',
                '11111111111111111111111111111111',
                '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io',
                'ComputeBudget111111111111111111111111111111'
            ],
            'header': {
                'numReadonlySignedAccounts': 0,
                'numReadonlyUnsignedAccounts': 5,
                'numRequiredSignatures': 1
            },
            'instructions': [
                {
                    'accounts': [],
                    'data': '16TYTJ8fLSxF',
                    'programIdIndex': 13
                },
                {
                    'accounts': [],
                    'data': '7YXqSw',
                    'programIdIndex': 13
                },
                {
                    'accounts': [
                        1,
                        3,
                        0
                    ],
                    'data': '498XbEqWSBH1',
                    'programIdIndex': 7  # TOKEN APPROVE
                },
                {
                    'accounts': [
                        9
                    ],
                    'data': '2CgVmVHHZaFFdmwR',
                    'programIdIndex': 9  # KECCACK
                },
                {
                    'accounts': [
                        10,
                        0,
                        2,
                        3,
                        11,
                        12,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        1
                    ],
                    'data': 'Ce7sSZnkZfB9ed8FVPHRevqecTkWA2eWuXdwpsYkptQbDH9aiHiMbZza6TCWKSVc7AASunCKgToLhqVB1LTdCBDKfrFcJnvs1peswActBjxz3KF1XQoj6Bm6m2WfBq9Po5Teo3YV2ywqLaanqYPbLRYiyEHVGoYsbu5Ft2qWoPeweT3deZ1fMa9PzEQk76Sz3yLAgKtp121gHpRKEaKt6GivNxyqMbPMtEy8wDUZ2cPtAtR8VxmPJjbBgmMNnoLLJLoaqmZ',
                    'programIdIndex': 12  # NEON EVM CALL
                }
            ],
            'recentBlockhash': 'FmyrgTRCHNCwKyVY1U8vJqjTU5cC8pxE99ZWygq6ZkUh'
        },
        'signatures': [
            '2iUszBGUU7wJ2yb8ajwEKujFLY9JCHLpH2YKpTjFrqJ8davSjE5wuBr4E8N5KStDtFZPtrn9khcWBUcEUFJ6Y2r2'
        ]
    }
}
