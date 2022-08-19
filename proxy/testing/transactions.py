from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0xf8658080831fc02094e442c8a04cde867473ab5dd4c9f3dd369945023380b844'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0xaa2c8c7375bd9d47d4d80c9a193b4b7438df7d2e'

# Solana`s transaction for simple case airdrop
pre_token_airdrop_trx = {
    'blockTime': 1660736942,
    'meta': {
        'err': None,
        'fee': 10000,
        'innerInstructions': [
            {
                'index': 2,
                'instructions': [  # INNER INSTRUCTIONS OF CREATE ACCOUNT
                    {
                        'accounts': [
                            0,
                            1
                        ],
                        'data': '11115hqdWRoDRcQ1DD5PkJT6w8q5Cw77Q7CPkvGV6qUEaJaN9biJc7L3fqUjHMSRcUWmcB',
                        'programIdIndex': 9
                    }
                ]
            },
            {
                'index': 5,
                'instructions': [  # INNER INSTRUCTIONS OF CLAIM
                    {
                        'accounts': [
                            0,
                            3
                        ],
                        'data': '3Bxs4PckVVt51W8w',
                        'programIdIndex': 9
                    },
                    {
                        'accounts': [
                            0,
                            7
                        ],
                        'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL',
                        'programIdIndex': 9
                    },
                    {
                        'accounts': [
                            7,  # <== new token account
                            8,  # <== mint account
                            6
                        ],
                        'data': '5rFyaxnaeJ5ZNXwaRKi5ocMLmu3xdwuHAykr2EVUsZQzV',
                        'programIdIndex': 5  # TOKEN INITIALIZE ACCOUNT 2
                    },
                    {
                        'accounts': [
                            2,
                            7,  # <== new ERC20 token account
                            1   # <== new Neon account
                        ],
                        'data': '3QK1PgBtAWnb',
                        'programIdIndex': 5  # TOKEN TRANSFER
                    },
                    {
                        'accounts': [],
                        'data': 'APLWvPP1wEXUDXKD4tLjjB2iZZ264guETNt9mAjuF65Dxe81Wqvba6AYa6yMs3Q3oVZgdR3Lef3uWrJ418u3TCyjEjgfJjqWwddReY4U9a8uctVe8mCx2rh3x3pMTYqQkSE9w4jNSY7RV8fM9xda5ATaivshH87XRwb5fhXdKdyopakigSvM6bxoN8pUhnU9gt3m8qaH2W4xpbqCRvZaaK',
                        'programIdIndex': 12  # EVM ON EVENT
                    },
                    {
                        'accounts': [],
                        'data': '6sphUX89AzLs9pxG3HPWwWLrGsSqqZJEUgKaVZNraXkRdURmCDjtonqgc',
                        'programIdIndex': 12  # EVM ON RETURN
                    }
                ]
            }
        ],
        'loadedAddresses': {
            'readonly': [],
            'writable': []
        },
        'logMessages': [
            'Program ComputeBudget111111111111111111111111111111 invoke [1]',
            'Program ComputeBudget111111111111111111111111111111 success',
            'Program ComputeBudget111111111111111111111111111111 invoke [1]',
            'Program ComputeBudget111111111111111111111111111111 success',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]',
            'Program log: Instruction: Create Account',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program log: Total memory occupied: 488',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 8570 of 499944 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
            'Program log: Instruction: Approve',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2284 of 491318 compute units',
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
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3394 of 269948 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: Transfer',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3131 of 263538 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [2]',
            'Program log: Total memory occupied: 0',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 715 of 258787 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success',
            'Program log: Applies done',
            'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [2]',
            'Program log: Total memory occupied: 0',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 717 of 255363 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success',
            'Program log: Total memory occupied: 26080',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 235874 of 488978 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
        ],
        'postBalances': [
            999996553720,
            1392000,
            2039280,
            895880,
            93257040,
            953185920,
            1009200,
            2039280,
            1461600,
            1,
            1,
            0,
            8147821440,
            1
        ],
        'postTokenBalances': [
            {
                'accountIndex': 2,
                'mint': 'A6oAjJEPNc5rf6WrQTu3E7hzsydRCc2XLv73CnYNkCW3',
                'owner': '9JgndtJuNH5aAiEe9c7FeaEjy3sw7yX7a499WH51B9A6',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '999999876544',
                    'decimals': 9,
                    'uiAmount': 999.999876544,
                    'uiAmountString': '999.999876544'
                }
            },
            {
                'accountIndex': 7,
                'mint': 'A6oAjJEPNc5rf6WrQTu3E7hzsydRCc2XLv73CnYNkCW3',
                'owner': '6auf2AZ3bKm5Qd3jguF4WpWRu9fU2a9fEwapTkebJB45',
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
            0,
            2039280,
            890880,
            93257040,
            953185920,
            1009200,
            0,
            1461600,
            1,
            1,
            0,
            8147821440,
            1
        ],
        'preTokenBalances': [
            {
                'accountIndex': 2,
                'mint': 'A6oAjJEPNc5rf6WrQTu3E7hzsydRCc2XLv73CnYNkCW3',
                'owner': '9JgndtJuNH5aAiEe9c7FeaEjy3sw7yX7a499WH51B9A6',
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
    'slot': 282,
    'transaction': {
        'message': {
            'accountKeys': [
                '9JgndtJuNH5aAiEe9c7FeaEjy3sw7yX7a499WH51B9A6',
                '7s8Q2eE6AX8SAnviLjgUPYMU8dGtviAj9AKxhi54YMSK',  # <== client Neon account (calculated from eth address 0xAa2C8C7375BD9d47d4D80c9a193b4B7438df7d2e)
                '8hmm7t1ZXdEdphE9EtYGfns7TWfFNXH5BDggojq9EQfZ',  # <== source token account
                'AHtxTU3avoswonG9EygvXayrQGYnTxVxpeZNbBsWzkY2',
                '6auf2AZ3bKm5Qd3jguF4WpWRu9fU2a9fEwapTkebJB45',
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'SysvarRent111111111111111111111111111111111',
                'ECqNkcfeB7dAH5skRYDo9MCVKZBDtNXsxdtmsHCAMj2P',  # <== Token Mint
                'A6oAjJEPNc5rf6WrQTu3E7hzsydRCc2XLv73CnYNkCW3',
                '11111111111111111111111111111111',
                'KeccakSecp256k11111111111111111111111111111',
                'Sysvar1nstructions1111111111111111111111111',
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
                        0,
                        9,
                        1
                    ],
                    'data': '2ww6N4V5rZsoJ1cdibk9FWbapyoiV',
                    'programIdIndex': 12  # EVM CREATE ACCOUNT
                },
                {
                    'accounts': [
                        2,
                        1,
                        0
                    ],
                    'data': '498XbEqWSBH1',
                    'programIdIndex': 5  # TOKEN APPROVE
                },
                {
                    'accounts': [
                        10
                    ],
                    'data': '2CgVnE6omdn3yvxU',
                    'programIdIndex': 10  # KECCACK
                },
                {
                    'accounts': [
                        11,
                        0,
                        3,
                        1,
                        9,
                        12,
                        1,
                        4,
                        5,
                        6,
                        2,
                        7,
                        8
                    ],
                    'data': 'CdbVXwsdcyuhC4DU6iNhHUKECXzLh2WkGyBUtJHScKczcvjthdXMCjRDpRNJir9UzsPJVs4Bp2qvQPX7jbdCxmMVp1DmTrW5uyzRqNatNSfJSZX5NrtmvRZexNr6ZywGy16bTS8JUF2f1PJ2jtL2fWPSaECoeZRLD5VNgHdRQn1ffKoGBJhrebnB1vuYkWvaSGr7vNJkAJZ257w43Vv3pXvLsZWT8yjFLPXYSMbkBdD2SzCRm3cF29xZngVa2P7GafB9svP',
                    'programIdIndex': 12  # NEON EVM CALL
                }
            ],
            'recentBlockhash': '45m8R5XcMHRTB5LV5LP7Z3YgHxVBA5n1bqtY5k6bFsLh'
        },
        'signatures': [
            '3cZ5tqGKcgUQKLuAgwZ3HkkxZNduaEcoao39oztPgwCXTp5DTrT9hrdWAqhzo79TGAfBuZM1fnMSbreh8fvBmyLt'
        ]
    }
}
