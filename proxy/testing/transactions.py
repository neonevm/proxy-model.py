from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0x738aaa80a1dc61d55fda38a234afa6ce93641efc'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x1117a1012e1dff20a69072e8a2aca3ccde6ac3dd'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = {
    'blockTime': 1662391582,
    'meta': {
        'err': None,
        'fee': 5000,
        'innerInstructions': [
            {
                'index': 2,
                'instructions': [
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
                'index': 4,
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
                            5
                        ],
                        'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL',
                        'programIdIndex': 9
                    },
                    {
                        'accounts': [
                            5,
                            6,
                            8
                        ],
                        'data': '5zBgnMkSCEeQHkKhyCRb8yTV4Tkh8otNc17nhpc58XQ3g',
                        'programIdIndex': 7
                    },
                    {
                        'accounts': [
                            2,
                            5,
                            1
                        ],
                        'data': '3QK1PgBtAWnb',
                        'programIdIndex': 7
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
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 14547 of 499944 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
            'Program log: Instruction: Approve',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2284 of 485341 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]',
            'Program log: Instruction: Execute Transaction from Instruction',
            'Program data: SEFTSA== A2VXi+naSTtCEtdWw+sgd0JXoqHk7Eo4J7bKHU78iYA=',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program log: Applies begin',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: InitializeAccount2',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3394 of 231428 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: Transfer',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3131 of 225078 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program data: TE9HMw== c4qqgKHcYdVf2jiiNK+mzpNkHvw= AwAAAAAAAAA= 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAAERehAS4d/yCmkHLooqyjzN5qw90=  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=',
            'Program log: Applies done',
            'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12',
            'Program data: UkVUVVJO Eg== EJkfAAAAAAA= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=',
            'Program log: Total memory occupied: 27337',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 265934 of 483001 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
        ],
        'postBalances': [
            999996558720,
            1392000,
            2039280,
            895880,
            93257040,
            2039280,
            1461600,
            953185920,
            1009200,
            1,
            8529006720,
            1
        ],
        'postTokenBalances': [
            {
                'accountIndex': 2,
                'mint': 'FV1weNQ2VFMRboHsviHvi22cCZUK2mwM6RZL14fNVdDq',
                'owner': '8XBQG7muFZufza2s1X2EbWi4DGPqUCTvRPStWy3KCvfw',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '999999876544',
                    'decimals': 9,
                    'uiAmount': 999.999876544,
                    'uiAmountString': '999.999876544'
                }
            },
            {
                'accountIndex': 5,
                'mint': 'FV1weNQ2VFMRboHsviHvi22cCZUK2mwM6RZL14fNVdDq',
                'owner': 'EWcrR8QbXtbzd1BHZckPsveiTrPxtZF6GJXW3sErGA7G',
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
            0,
            1461600,
            953185920,
            1009200,
            1,
            8529006720,
            1
        ],
        'preTokenBalances': [
            {
                'accountIndex': 2,
                'mint': 'FV1weNQ2VFMRboHsviHvi22cCZUK2mwM6RZL14fNVdDq',
                'owner': '8XBQG7muFZufza2s1X2EbWi4DGPqUCTvRPStWy3KCvfw',
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
    'slot': 257,
    'transaction': {
        'message': {
            'accountKeys': [
                '8XBQG7muFZufza2s1X2EbWi4DGPqUCTvRPStWy3KCvfw',
                'D3UHQxMF2JxiDXvJUnXDzeMR7BRqrKE8BrAZoMSeR2uQ',
                '6u7sd4YW8VLLDAWpcJkiGeaiJ9SYZkiDnRF5bsB4W2mU',
                'CjJnfcgbn3SMrop5jP61CoWkrNfoKyTgk4gJssvkXrWt',
                'EWcrR8QbXtbzd1BHZckPsveiTrPxtZF6GJXW3sErGA7G',
                'GfqfGakLHPgQRhsVWkFx3UDcVyfVF8PHYFHHUAQXRKXa',
                'FV1weNQ2VFMRboHsviHvi22cCZUK2mwM6RZL14fNVdDq',
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'SysvarRent111111111111111111111111111111111',
                '11111111111111111111111111111111',
                '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io',
                'ComputeBudget111111111111111111111111111111'
            ],
            'header': {
                'numReadonlySignedAccounts': 0,
                'numReadonlyUnsignedAccounts': 3,
                'numRequiredSignatures': 1
            },
            'instructions': [
                {
                    'accounts': [

                    ],
                    'data': '16TYTJ8fLSxF',
                    'programIdIndex': 11
                },
                {
                    'accounts': [

                    ],
                    'data': '7YXqSw',
                    'programIdIndex': 11
                },
                {
                    'accounts': [
                        0,
                        9,
                        1
                    ],
                    'data': '3Tu7g5vZuWZNc4DF3cNXbtVjQbhHW',
                    'programIdIndex': 10  ### EVM CREATE ACCOUNT
                },
                {
                    'accounts': [
                        2,
                        1,
                        0
                    ],
                    'data': '498XbEqWSBH1',
                    'programIdIndex': 7  ### TOKEN APPROVE
                },
                {
                    'accounts': [
                        0,
                        3,
                        1,
                        9,
                        10,
                        4,
                        1,
                        5,
                        6,
                        2,
                        7,
                        8
                    ],
                    'data': '2XkqzGbiEyovabshcWpmmJuXxLMQDikSkJUrEeRxoPXgroZUySgA3UywUGDVwBijRU7w32a8aBrsAJhNpegvPjYjvYLYYpKBFcyFiDF924VQnFqUkLSxuLr9yGwA9odaZrsfH6GYy4SUUktDyamYMiUX4duXMXYoPqAhRjTdJi5Gz26ekwZCuch1fMEKWniKzkUKUjHSriqRXVLLcSZPmpwyPdmTydd5VVdkYEWpNh9Sk8',
                    'programIdIndex': 10  #### NEON EVM CALL
                }
            ],
            'recentBlockhash': '7j8VFQTEgksCa5CZddfroTyhsAUddy2XdpM4Su8SHgwt'
        },
        'signatures': [
            '2U6DCZXe2ktib2ddKWdUrPfSPVi6kdb4Morh1b7J2otUq2pV2UpojAdqEKZWwSKG8wbxbaxsvzCsG1TVbQ4RfMPk'
        ]
    }
}
