from ..common_neon.environment_data import EVM_LOADER_ID
import json

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0xd3162f585207d9e4a2ea9e58e0a5bbfd6c1da4e8'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0xd26b4b78bcfc8bf05be71049e56295eb01051a7e'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = json.loads('''
    {
        "blockTime": 1675087279,
        "meta": {
            "computeUnitsConsumed": 210210,
            "err": null,
            "fee": 5000,
            "innerInstructions": [
                {
                    "index": 2,
                    "instructions": [
                        {
                            "accounts": [
                                0,
                                3
                            ],
                            "data": "11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf",
                            "programIdIndex": 9
                        }
                    ]
                },
                {
                    "index": 3,
                    "instructions": [
                        {
                            "accounts": [
                                0,
                                2
                            ],
                            "data": "11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf",
                            "programIdIndex": 9
                        }
                    ]
                },
                {
                    "index": 5,
                    "instructions": [
                        {
                            "accounts": [
                                0,
                                7
                            ],
                            "data": "3Bxs4PckVVt51W8w",
                            "programIdIndex": 9
                        },
                        {
                            "accounts": [
                                0,
                                5
                            ],
                            "data": "11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL",
                            "programIdIndex": 9
                        },
                        {
                            "accounts": [
                                5,
                                6,
                                11
                            ],
                            "data": "5vo1xRhvZ2ueuTVpqRQQwwdTX838reqTk8hnpHZ9Ft5ZZ",
                            "programIdIndex": 12
                        },
                        {
                            "accounts": [
                                8,
                                5,
                                1
                            ],
                            "data": "3QK1PgBtAWnb",
                            "programIdIndex": 12
                        }
                    ]
                }
            ],
            "loadedAddresses": {
                "readonly": [],
                "writable": []
            },
            "logMessages": [
                "Program ComputeBudget111111111111111111111111111111 invoke [1]",
                "Program ComputeBudget111111111111111111111111111111 success",
                "Program ComputeBudget111111111111111111111111111111 invoke [1]",
                "Program ComputeBudget111111111111111111111111111111 success",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
                "Program log: Instruction: Create Account",
                "Program log: Address: 0xe0a75b0a3b5d22196f17a43d1e8fad66a8abb6a1",
                "Program 11111111111111111111111111111111 invoke [2]",
                "Program 11111111111111111111111111111111 success",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 11956 of 499944 compute units",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
                "Program log: Instruction: Create Account",
                "Program log: Address: 0xd26b4b78bcfc8bf05be71049e56295eb01051a7e",
                "Program 11111111111111111111111111111111 invoke [2]",
                "Program 11111111111111111111111111111111 success",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 13456 of 487932 compute units",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
                "Program log: Instruction: Approve",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2902 of 474420 compute units",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
                "Program log: Instruction: Execute Transaction from Instruction",
                "Program data: SEFTSA== VvcNVStoqqPLg8GZjNoDSEnmjF30FzNcW2I0Jfae8z0=",
                "Program 11111111111111111111111111111111 invoke [2]",
                "Program 11111111111111111111111111111111 success",
                "Program data: RU5URVI= Q0FMTA== 0xYvWFIH2eSi6p5Y4KW7/WwdpOg=",
                "Program data: TE9HMw== 0xYvWFIH2eSi6p5Y4KW7/WwdpOg= Aw== 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAA0mtLeLz8i/Bb5xBJ5WKV6wEFGn4= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=",
                "Program data: RVhJVA== UkVUVVJO",
                "Program 11111111111111111111111111111111 invoke [2]",
                "Program 11111111111111111111111111111111 success",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
                "Program log: Instruction: InitializeAccount2",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4362 of 306059 compute units",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
                "Program log: Instruction: Transfer",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4735 of 298579 compute units",
                "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
                "Program data: R0FT AEUfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AEUfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "Program log: exit_status=0x12",
                "Program data: UkVUVVJO Eg==",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 181672 of 471462 compute units",
                "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success"
            ],
            "postBalances": [
                999995180640,
                0,
                1385040,
                1385040,
                87417600,
                2039280,
                1461600,
                895880,
                2039280,
                1,
                1,
                1009200,
                929020800,
                1141440
            ],
            "postTokenBalances": [
                {
                    "accountIndex": 5,
                    "mint": "F8tbFAgsQu7W7fTwCRe67XKTZU8PFrAL2YyjPYandB8a",
                    "owner": "B7x2V5txL9rcLBJ9nbaCr6dB88qgjWLEPtXcWpJycqd9",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "uiTokenAmount": {
                        "amount": "123456",
                        "decimals": 9,
                        "uiAmount": 0.000123456,
                        "uiAmountString": "0.000123456"
                    }
                },
                {
                    "accountIndex": 8,
                    "mint": "F8tbFAgsQu7W7fTwCRe67XKTZU8PFrAL2YyjPYandB8a",
                    "owner": "CTzLPY4am3ykyKvffrCJUBcvoFcc36B5a4gHT2t1q6Fw",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "uiTokenAmount": {
                        "amount": "999999876544",
                        "decimals": 9,
                        "uiAmount": 999.999876544,
                        "uiAmountString": "999.999876544"
                    }
                }
            ],
            "preBalances": [
                1000000000000,
                0,
                0,
                0,
                87417600,
                0,
                1461600,
                890880,
                2039280,
                1,
                1,
                1009200,
                929020800,
                1141440
            ],
            "preTokenBalances": [
                {
                    "accountIndex": 8,
                    "mint": "F8tbFAgsQu7W7fTwCRe67XKTZU8PFrAL2YyjPYandB8a",
                    "owner": "CTzLPY4am3ykyKvffrCJUBcvoFcc36B5a4gHT2t1q6Fw",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "uiTokenAmount": {
                        "amount": "1000000000000",
                        "decimals": 9,
                        "uiAmount": 1000.0,
                        "uiAmountString": "1000"
                    }
                }
            ],
            "returnData": null,
            "rewards": [],
            "status": {
                "Ok": null
            }
        },
        "slot": 4469,
        "transaction": {
            "message": {
                "accountKeys": [
                    "CTzLPY4am3ykyKvffrCJUBcvoFcc36B5a4gHT2t1q6Fw",
                    "3f5krra8iSd5qAWXBvqhx2GHQC6RG8uWkY2374jt1mVV",
                    "8nTzbe3g4n6BSnVkkfnvaHZJ1NSP9C1V6YMF5s2dFxsv",
                    "9kJSHdt14PRSdtAAKLGyQwKEJznySrJsb962TSjgduwY",
                    "B7x2V5txL9rcLBJ9nbaCr6dB88qgjWLEPtXcWpJycqd9",
                    "CfwyuMxWBg91bka2M1ajy4F9gAW2B3DqUryidyJZ8j9u",
                    "F8tbFAgsQu7W7fTwCRe67XKTZU8PFrAL2YyjPYandB8a",
                    "FNBZzzRLgmKv738Fi9tuZQM27hKVGsW98B6R2TJgRm2h",
                    "HTPMUZSptfqVQjJt35VNCjAuBfiUyLTi54WjioRnfkuZ",
                    "11111111111111111111111111111111",
                    "ComputeBudget111111111111111111111111111111",
                    "SysvarRent111111111111111111111111111111111",
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io"
                ],
                "header": {
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 5,
                    "numRequiredSignatures": 1
                },
                "instructions": [
                    {
                        "accounts": [],
                        "data": "7YXqSw",
                        "programIdIndex": 10
                    },
                    {
                        "accounts": [],
                        "data": "EvSMNP",
                        "programIdIndex": 10
                    },
                    {
                        "accounts": [
                            0,
                            9,
                            3
                        ],
                        "data": "3WnqHUktn47C7vJBGMkp2kmxdoMa8",
                        "programIdIndex": 13
                    },
                    {
                        "accounts": [
                            0,
                            9,
                            2
                        ],
                        "data": "3WbLAQvG7rekqERuRiT1vtezohCVT",
                        "programIdIndex": 13
                    },
                    {
                        "accounts": [
                            8,
                            1,
                            0
                        ],
                        "data": "498XbEqWSBH1",
                        "programIdIndex": 12
                    },
                    {
                        "accounts": [
                            0,
                            7,
                            3,
                            9,
                            13,
                            3,
                            4,
                            1,
                            11,
                            6,
                            12,
                            8,
                            5
                        ],
                        "data": "TddjEEGgcJdRRHJPQxggctecav61vt8omEYWA83Ua6cZvBQSL12eMUdWgQVuBNhBqXpvCxGNFWcjQqDEKQeSq4XvDsLzDWc2LUv11k8wCzDtWDoVgjyke9PFfrEmtAEjcPCTaL2zxsXc3yNqQDRJ4dUoKo8g5LXD9ENhaat63WdY7wKsd6oe9muEzUju3CwFE4QhcX35K9s9kRtvLYofh7nQ51RyG2SGn3iagqueHPcD1huhpc4EWLarbfEijVvjaBs67G9xiZgRXRnq9j1a5pop1",
                        "programIdIndex": 13
                    }
                ],
                "recentBlockhash": "A7VbgEMmrvn1zUn7rbwmt83QahH9rYwrLp34wkhaYV19"
            },
            "signatures": [
                "4d9SCa8wNnzTvNV9hbhcVyHRtfpEKwWbbC5q4inDVipkBBs5BksmKUagouNf96dZYjHHn2vAXTViSy8NDfHW1zMi"
            ]
        }
    }
''')