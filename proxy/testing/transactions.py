from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0x80f573dbe9df3163d95d37bc24677e461f637eab'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x2046c47a75e8931cd1bd63f7ce934f21bc453f5d'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = {
    'blockTime': 1664374562,
    'meta': {
        'computeUnitsConsumed': 258931,
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
                        'data': '11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf',
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
                            6
                        ],
                        'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL',
                        'programIdIndex': 9
                    },
                    {
                        'accounts': [
                            6,
                            8,
                            5
                        ],
                        'data': '5y6y1AhNodC9fS5rkiR7mmrpYQ2g5gnr2QButZWTwSFou',
                        'programIdIndex': 7
                    },
                    {
                        'accounts': [
                            2,
                            6,
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
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 6960 of 499944 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
            'Program log: Instruction: Approve',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2902 of 492928 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]',
            'Program log: Instruction: Execute Transaction from Instruction',
            'Program data: SEFTSA== P1MsINNxGhyIX5Z+cRM3+8Gkm3I+RkhYuk4b22G1AaA=',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program 11111111111111111111111111111111 invoke [2]',
            'Program 11111111111111111111111111111111 success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: InitializeAccount2',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4362 of 265125 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
            'Program log: Instruction: Transfer',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4735 of 257545 compute units',
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
            'Program data: TE9HMw== gPVz2+nfMWPZXTe8JGd+Rh9jfqs= AwAAAAAAAAA= 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAAIEbEenXokxzRvWP3zpNPIbxFP10=  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=',
            'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12',
            'Program log: used gas 2065800',
            'Program data: UkVUVVJO Eg== iIUfAAAAAAA= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=',
            'Program log: Total memory occupied: 25707',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 248901 of 489970 compute units',
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
        ],
        'postBalances': [
            999996565680,
            1385040,
            2039280,
            895880,
            93250080,
            1009200,
            2039280,
            929020800,
            1461600,
            1,
            8391755520,
            1
        ],
        'postTokenBalances': [
            {
                'accountIndex': 2,
                'mint': '3degSTzK61HgJthMep492UhcCtv3LAFRu94fphAMzFom',
                'owner': 'EGDp4oZ69PZ2qqJzHAK854s46yeJRyKp1VecVUCittuB',
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
                'mint': '3degSTzK61HgJthMep492UhcCtv3LAFRu94fphAMzFom',
                'owner': 'DRu5E5MCvSMNJmL55cH2gKzCQ8NumTiWfNegnmdfB1sV',
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
            93250080,
            1009200,
            0,
            929020800,
            1461600,
            1,
            8391755520,
            1
        ],
        'preTokenBalances': [
            {
                'accountIndex': 2,
                'mint': '3degSTzK61HgJthMep492UhcCtv3LAFRu94fphAMzFom',
                'owner': 'EGDp4oZ69PZ2qqJzHAK854s46yeJRyKp1VecVUCittuB',
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'uiTokenAmount': {
                    'amount': '1000000000000',
                    'decimals': 9,
                    'uiAmount': 1000.0,
                    'uiAmountString': '1000'
                }
            }
        ],
        'returnData': None,
        'rewards': [],
        'status': {
            'Ok': None
        }
    },
    'slot': 242,
    'transaction': {
        'message': {
            'accountKeys': [
                'EGDp4oZ69PZ2qqJzHAK854s46yeJRyKp1VecVUCittuB',
                'DheXfp2VfwpRGsa76SMeLjiXDZvQoUXGzyY71xty3hps',
                '8acgQvuYmktMq97hLY8UDDTKHDJde4bWb5rM7VGK2i9R',
                '9o5E4FkcZWKwfUr7X9JRH1BDVbC9yEP94FgVSzZaMRrn',
                'DRu5E5MCvSMNJmL55cH2gKzCQ8NumTiWfNegnmdfB1sV',
                'SysvarRent111111111111111111111111111111111',
                'HM1Hs5Xuhq5qnoi3Qkepk6xoxonWVRRFkC7dHJs2NjjT',
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                '3degSTzK61HgJthMep492UhcCtv3LAFRu94fphAMzFom',
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
                    'data': '3U7PJBQ2XjQN6DqMgBnkeharUsQbE',
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
                        7,
                        8,
                        2
                    ],
                    'data': '2XiFcMucgafM7uM9i766GoQj4Msm5hVBVvu6xvtSqUnFcpD1abUyJpMp8LgNaeVFfTvfBFUxL815Dy1nanuzM6AWVw1fRh8ooa6DXM4zJTV74SsdhU6fKZm7hPipzhsQCpvCds8XXo7bKsqbhsHWGBFiJXqe4E21kjqnjqqXxNTEVE7QgLcFtr2zLr9HCWBYu2g7V24VAzrUr6wNeWGjyPMfJkSCNxEdYkLHn7zWdw5jTd',
                    'programIdIndex': 10  #### NEON EVM CALL
                }
            ],
            'recentBlockhash': '6B1NWExpnfEG2pij7YVppCLwUc9TRvMnitTk1Eryxg6g'
        },
        'signatures': [
            'v9Kyffps7v82JrJB4XQyrBpibiH5pTfkuLq4WnXYpcmAMgnxo2spaqNat22YSmhfYyL9VvCzf68FR3rrbmXcqGC'
        ]
    }
}
