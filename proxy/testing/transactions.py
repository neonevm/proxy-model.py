from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0xf8658080831fc020947d461de3cfa3a7e493f29d25b10604d870e82ec580b844'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0xe96696c0e634d1c82c95d09147e8a65e448413d7'

# Solana`s transaction for simple case airdrop
pre_token_airdrop_trx = {
    'blockTime': 1661425958,
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
            }, {
                'index': 5,
                'instructions': [
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
                            6
                        ],
                        'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL',
                        'programIdIndex': 9
                    },
                    {
                        'accounts': [
                            6,  # <== new token account
                            8,  # <== mint account
                            7
                        ],
                        'data': '5uuoM3KSVZHMRGzynD7pJJa8bsCpUWwfHv9HDXSTXWVmn',
                        'programIdIndex': 5 # TOKEN INITIALIZE ACCOUNT 2
                    },
                    {
                        'accounts': [
                            2,
                            6,  # <== new ERC20 token account
                            1   # <== new Neon account
                        ],
                        'data': '3QK1PgBtAWnb',
                        'programIdIndex': 5  ## TOKEN TRANSFER
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
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 7069 of 499944 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
            'Program log: Instruction: Approve',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2284 of 492819 compute units',
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
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3394 of 269263 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: Transfer',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3131 of 262721 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program data: TE9HMw== fUYd48+jp+ST8p0lsQYE2HDoLsU= AwAAAAAAAAA= 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAA6WaWwOY00cgsldCRR+imXkSEE9c=  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=',
            'Program log: Applies done',
            'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12',
            'Program data: UkVUVVJO Eg== EJkfAAAAAAA= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=',
            'Program log: Total memory occupied: 25881',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 235803 of 490479 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
        ],
        'postBalances': [
            999996553720,
            1392000,
            2039280,
            895880,
            93257040,
            953185920,
            2039280,
            1009200,
            1461600,
            1,
            1,
            0,
            8588640000,
            1
        ], 'postTokenBalances': [
            {
                'accountIndex': 2,
                'mint': '3QmRqfAKJ5VqMp3qJwWxqe8L4CAgoM7yDdYQ61JjqvqQ',
                'owner': '2Japcp5VYbg3iyPxn8NqtaPMrMdDHd52pdDrvXMueaaF',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '999999876544',
                    'decimals': 9,
                    'uiAmount': 999.999876544,
                    'uiAmountString': '999.999876544'
                }
            },
            {
                'accountIndex': 6,
                'mint': '3QmRqfAKJ5VqMp3qJwWxqe8L4CAgoM7yDdYQ61JjqvqQ',
                'owner': 'AEjR6hQtrXZ89gT6aJyZD3JFsJXJbcXnBL21khdFFFqN',
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
            0,
            1009200,
            1461600,
            1,
            1,
            0,
            8588640000,
            1
        ],
        'preTokenBalances': [
            {
                'accountIndex': 2,
                'mint': '3QmRqfAKJ5VqMp3qJwWxqe8L4CAgoM7yDdYQ61JjqvqQ',
                'owner': '2Japcp5VYbg3iyPxn8NqtaPMrMdDHd52pdDrvXMueaaF',
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
    'slot': 253,
    'transaction': {
        'message': {
            'accountKeys': [
                '2Japcp5VYbg3iyPxn8NqtaPMrMdDHd52pdDrvXMueaaF',  # <== client Neon account (calculated from eth address 0xE96696C0E634D1c82c95d09147e8A65e448413D7)
                '7Gj1Zaa2dtTc47RjTU6EztCTjb83nBZp9p3AVN8hfCXF',  # <== source token account
                'Fj39U77H3M8DMFNkRr8ZtwUVrGzMtKJt3skq76wkfUMK',
                'CmZQkRssybuGKNG1DfKKwH5cuC2EC75eYHrvTUeVWKNm',
                'AEjR6hQtrXZ89gT6aJyZD3JFsJXJbcXnBL21khdFFFqN',
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'DU4J8hKHjdbzA5wWpfxf1ZcvkWTvnFjtHmzgoY67d9oJ',
                'SysvarRent111111111111111111111111111111111',
                '3QmRqfAKJ5VqMp3qJwWxqe8L4CAgoM7yDdYQ61JjqvqQ',  # <== Token Mint
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
                    'data': '32P3JHwVoJKo1h5YGZkiDCNbenXQJ',
                    'programIdIndex': 12   # EVM CREATE ACCOUNT
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
                        2,
                        6,
                        7,
                        8
                    ],
                    'data': 'CZvrBc7wx9yfB1HWESv5chf6Y2x6Fi2QBL9aJDYnWSg8mHsfrr4KPqoZ8pXzvY4DLocRzcwvxvRXpkEJsc4uajsd24ey6JMvsgQdkLj7kjr9j8sYAfaqKGtLz2jkMSJCQcEXkjUqkWzrCLeBUzzcGcfAmVEDP8Tp23PNF14b2Jco79c3zfgGJ2CQXsbcVwFDe3vFr4PJVYUPYpjvFQC2HHWTkhA8jAXxwP2665npxSMgn8Gf293XEEKEQUBb4qcq286XnoZ',
                    'programIdIndex': 12  # NEON EVM CALL
                }
            ],
            'recentBlockhash': 'AR8YSGwXYtU6nskA9qdBuwDBwXDWQvdKzYH8vz1srj9c'
        },
        'signatures': [
            '64GpPFZe3Q4xKLzAXhirWD9NCh6CJg9H643y3zQrGagRSLBXv6FUg1DHT9ihgzer5Xo9fkXBbs3c22dvNQRr5F1T'
        ]
    }
}
