from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '5H7kvhPD7GECAmf227vTPYTS7SC2PmyuVZaT5zVTx7vb'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0xf71c4daca893e5333982e2956c5ed9b648818376'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = {
        'blockTime': 1637857371,
        'meta': {
            'err': None,
            'fee': 5000,
            'innerInstructions': [
                {
                    'index': 0,
                    'instructions': [
                        {
                            'accounts': [0, 1],
                            'data': '111112fUvhuhctf7ykHr29ATacqTktVJJSG9xpkwPTuR6WcMjZZQDYhZ5k4S6Zu6C5sdsn',
                            'programIdIndex': 7
                        },
                        {
                            'accounts': [0, 2, 1, 8, 7, 9, 11],
                            'data': '',
                            'programIdIndex': 10
                        },
                        {
                            'accounts': [0, 2],
                            'data': '3Bxs4h24hBtQy9rw',
                            'programIdIndex': 7
                        },
                        {
                            'accounts': [2], 'data':
                            '9krTDU2LzCSUJuVZ',
                            'programIdIndex': 7
                        },
                        {
                            'accounts': [2],
                            'data': 'SYXsBSQy3GeifSEQSGvTbrPNposbSAiSoh1YA85wcvGKSnYg',
                            'programIdIndex': 7
                        },
                        {
                            'accounts': [2, 8, 1, 11],
                            'data': '2',
                            'programIdIndex': 9
                        }
                    ]
                },
                {
                    'index': 1,
                    'instructions': [
                        {
                            'accounts': [0, 3],
                            'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL',
                            'programIdIndex': 7
                        },
                        {
                            'accounts': [3, 5, 1, 11],
                            'data': '2',
                            'programIdIndex': 9
                        }
                    ]
                }
            ],
            'logMessages': [
                f'Program {evm_loader_addr} invoke [1]',
                'Program 11111111111111111111111111111111 invoke [2]',
                'Program 11111111111111111111111111111111 success',
                'Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL invoke [2]',
                'Program log: Transfer 2039280 lamports to the associated token account',
                'Program 11111111111111111111111111111111 invoke [3]',
                'Program 11111111111111111111111111111111 success',
                'Program log: Allocate space for the associated token account',
                'Program 11111111111111111111111111111111 invoke [3]',
                'Program 11111111111111111111111111111111 success',
                'Program log: Assign the associated token account to the SPL Token program',
                'Program 11111111111111111111111111111111 invoke [3]',
                'Program 11111111111111111111111111111111 success',
                'Program log: Initialize the associated token account',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [3]',
                'Program log: Instruction: InitializeAccount',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3412 of 464826 compute units',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
                'Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL consumed 24626 of 485359 compute units',
                'Program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL success',
                'Program log: Total memory occupied: 1414',
                f'Program {evm_loader_addr} consumed 40680 of 500000 compute units',
                f'Program {evm_loader_addr} success',
                f'Program {evm_loader_addr} invoke [1]',
                'Program 11111111111111111111111111111111 invoke [2]',
                'Program 11111111111111111111111111111111 success',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]',
                'Program log: Instruction: InitializeAccount',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3412 of 486179 compute units',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success',
                'Program log: Total memory occupied: 1536',
                f'Program {evm_loader_addr} consumed 18381 of 500000 compute units',
                f'Program {evm_loader_addr} success',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
                'Program log: Instruction: Transfer',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3120 of 200000 compute units',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success'
            ],
            'postBalances': [5944954400, 2672640, 2039280, 2039280, 2672640, 1461600, 2039280, 1, 1461600, 1089991680, 898174080, 1009200, 1141440],
            'postTokenBalances': [
                {
                    'accountIndex': 2,
                    'mint': '89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g',
                    'owner': '8utQrai6so3pWtJhyCYafWhWJ3wJmi2eSurnMPZis4Aw',
                    'uiTokenAmount': {
                        'amount': '0',
                        'decimals': 9,
                        'uiAmount': None,
                        'uiAmountString': '0'
                    }
                },
                {
                    'accountIndex': 3,
                    'mint': '3vxj94fSd3jrhaGAwaEKGDPEwn5Yqs81Ay5j1BcdMqSZ',
                    'owner': '8utQrai6so3pWtJhyCYafWhWJ3wJmi2eSurnMPZis4Aw',
                    'uiTokenAmount': {
                        'amount': '1000000',
                        'decimals': 6,
                        'uiAmount': 1.0,
                        'uiAmountString': '1'
                    }
                },
                {
                    'accountIndex': 6,
                    'mint': '3vxj94fSd3jrhaGAwaEKGDPEwn5Yqs81Ay5j1BcdMqSZ',
                    'owner': 'CVAimMqtcmSUCV4RLZSJAreDpEd7JEZmrvCVj85yaRzZ',
                    'uiTokenAmount': {
                        'amount': '3798000000',
                        'decimals': 6,
                        'uiAmount': 3798.0,
                        'uiAmountString': '3798'
                    }
                }
            ],
            'preBalances': [5951710600, 0, 0, 0, 2672640, 1461600, 2039280, 1, 1461600, 1089991680, 898174080, 1009200, 1141440],
            'preTokenBalances': [
                {
                    'accountIndex': 6,
                    'mint': '3vxj94fSd3jrhaGAwaEKGDPEwn5Yqs81Ay5j1BcdMqSZ',
                    'owner': 'CVAimMqtcmSUCV4RLZSJAreDpEd7JEZmrvCVj85yaRzZ',
                    'uiTokenAmount': {
                        'amount': '3799000000',
                        'decimals': 6,
                        'uiAmount': 3799.0,
                        'uiAmountString': '3799'
                    }
                }
            ],
            'rewards': [],
            'status': {'Ok': None}
        },
        'slot': 96659490,
        'transaction': {
            'message': {
                'accountKeys': [
                    'CVAimMqtcmSUCV4RLZSJAreDpEd7JEZmrvCVj85yaRzZ',
                    '8utQrai6so3pWtJhyCYafWhWJ3wJmi2eSurnMPZis4Aw',
                    'J4zoYXUtxNJsCXLih7D7dVkfoT9pvsYa8HtHPEEN88U',
                    'AZqbo1ZCwS1grcqUdhs79YspjXME2BjrV5WCHabBS1ht',
                    erc20_wrapper,
                    '3vxj94fSd3jrhaGAwaEKGDPEwn5Yqs81Ay5j1BcdMqSZ',
                    '7XVY7C79A6UQa2JUN5hpqYHg9jgsgUPF7SErtbuvbHRc',
                    '11111111111111111111111111111111',
                    '89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g',
                    token_program,
                    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
                    'SysvarRent111111111111111111111111111111111',
                    evm_loader_addr
                ],
                'header': {
                    'numReadonlySignedAccounts': 0,
                    'numReadonlyUnsignedAccounts': 6,
                    'numRequiredSignatures': 1
                },
                'instructions': [
                    {
                        'accounts': [0, 7, 1, 3],
                        'data': '7mzxmWe9X6hGhfpmntNbEtuDfUgC9T',
                        'programIdIndex': 12
                    },
                    {
                        'accounts': [0, 3, 1, 4, 5, 7, 9, 11],
                        'data': 'G',
                        'programIdIndex': 12
                    },
                    {
                        'accounts': [6, 3, 0],
                        'data': '3QCwqmHZ4mdq',
                        'programIdIndex': 9
                    }
                ],
                'recentBlockhash': '8UBfYxDWWcEbXQPGxPRqK4oGnb6c2XAQm4xZwzM2fxCB'
            },
            'signatures': ['3np8r1PBJW9uuw7o7P86B46zH7nW4UufQa716NUsSscJ1mN5nG6K74JHcMb6YmTmu9Les2NSe1iQyLJZwgS5RpvE']
        }
    }

create_sol_acc_and_airdrop_trx = {
        'blockTime': 1638178743,
        'meta': {
            'err': None,
            'fee': 10000,
            'innerInstructions': [],
            'logMessages': [
                'Program 11111111111111111111111111111111 invoke [1]',
                'Program 11111111111111111111111111111111 success',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]',
                'Program log: Instruction: InitializeMint',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2833 of 200000000 compute units',
                'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success'],
            'postBalances': [999998528400, 1461600, 1009200, 1, 1130582400],
            'postTokenBalances': [],
            'preBalances': [1000000000000, 0, 1009200, 1, 1130582400],
            'preTokenBalances': [],
            'rewards': [],
            'status': {'Ok': None}
        },
        'slot': 15029,
        'transaction': {
            'message': {
                'accountKeys': [
                    'D4Aa2HU5kwF3nByGYk7pdjbP4n3cFFjPjYASdKUfpH4H',
                    'EHDze1sDhUk7dR9iBgV4Mm3dYMk3ZQXKGHiiuVTEYaYr',
                    'SysvarRent111111111111111111111111111111111',
                    '11111111111111111111111111111111',
                    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
                ],
                'header': {
                    'numReadonlySignedAccounts': 0,
                    'numReadonlyUnsignedAccounts': 3,
                    'numRequiredSignatures': 2
                },
                'instructions': [
                    {
                        'accounts': [0, 1],
                        'data': '11114XtYk9gGfZoo968fyjNUYQJKf9gdmkGoaoBpzFv4vyaSMBn3VKxZdv7mZLzoyX5YNC',
                        'programIdIndex': 3
                    },
                    {
                        'accounts': [1, 2],
                        'data': '1DidxzgH8WA79wndRY2Vc8EsYn3Rf9CKWmB3tRLNtzhWUZD',
                        'programIdIndex': 4
                    }
                ],
                'recentBlockhash': '6kT9KCR37ZWhu9fbdacwUsXAHXvPo9kYwzQsQnh9dWyW'
            },
            'signatures': [
                '4wNHEzKDpqKpQ51A3cYWGsLXAxc3cxHtk45cs1RMUYgY6bViBUu6w7VaDMSQjprbwC7AF4bMy3ejR69FAVwQWUgh',
                '4n6PzpFyQ5e9PTDFTUmHoPXUJYtNqsfQgwinu5ujYeY6EigseJHGgykmzMMb8exKsC45E7RjiyahLqhbR1uQo5V5'
            ]
        }
    }
