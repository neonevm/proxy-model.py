from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0x6197a7e7fd1a8463697965e821a6d3e9c600ddeb'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0xf05a7fdf927d14dcf910b946df56ca820b2ac0b2'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = {
    "blockTime": 1662070412,
    "meta": {
        "err": None,
        "fee": 5000,
        "innerInstructions": [
            {
                "index": 2,
                "instructions": [
                    {
                        "accounts": [
                            0,
                            1
                        ],
                        "data": "111112gQz8Q2DLChCrULekEzng7cFTY6bAsdeXqpzowVNF3mgngXxd3xvEaqXNV92Dxr4w",
                        "programIdIndex": 10
                    }
                ]
            },
            {
                "index": 4,
                "instructions": [
                    {
                        "accounts": [
                            0,
                            3
                        ],
                        "data": "3Bxs4PckVVt51W8w",
                        "programIdIndex": 10
                    },
                    {
                        "accounts": [
                            0,
                            6
                        ],
                        "data": "11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL",
                        "programIdIndex": 10
                    },
                    {
                        "accounts": [
                            6,
                            7,
                            9
                        ],
                        "data": "5po8EdW9FXfctm8f1rkjp76FwqcQVQRW2VLtQQHaM3LQB",
                        "programIdIndex": 8
                    },
                    {
                        "accounts": [
                            2,
                            6,
                            1
                        ],
                        "data": "3QK1PgBtAWnb",
                        "programIdIndex": 8
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
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program log: Total memory occupied: 488",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 8856 of 499944 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
            "Program log: Instruction: Approve",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2284 of 491032 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
            "Program log: Instruction: Execute Transaction from Instruction",
            "Program data: SEFTSA== OviJFDojrhjsu1TS9LzYyWoCe/gqVMGWYu1ewOyNBEI=",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
            "Program log: Instruction: InitializeAccount2",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3394 of 227229 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
            "Program log: Instruction: Transfer",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 3131 of 220591 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program data: TE9HMw== YZen5/0ahGNpeWXoIabT6cYA3es= AwAAAAAAAAA= 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAA8Fp/35J9FNz5ELlG31bKggsqwLI=  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=",
            "Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12",
            "Program data: UkVUVVJO Eg== EJkfAAAAAAA= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
            "Program log: Total memory occupied: 28425",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 276068 of 488692 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success"
        ],
        "postBalances": [
            999996391680,
            1559040,
            2039280,
            1605880,
            1559040,
            93048240,
            2039280,
            1461600,
            953185920,
            1009200,
            1,
            8689365120,
            1
        ],
        "postTokenBalances": [
            {
                "accountIndex": 2,
                "mint": "7DWtjZjPtYkeYXUpBW5agYkK31Fs1HmgW5Ki6tJCqo4o",
                "owner": "Et6LGAWpyDKxQVuQQBhWRLdsEpvd72u1biTXE9mpNMdN",
                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "uiTokenAmount": {
                    "amount": "999999876544",
                    "decimals": 9,
                    "uiAmount": 999.999876544,
                    "uiAmountString": "999.999876544"
                }
            },
            {
                "accountIndex": 6,
                "mint": "7DWtjZjPtYkeYXUpBW5agYkK31Fs1HmgW5Ki6tJCqo4o",
                "owner": "584Jgt7epupbdp8LDwu51ZRbqi7KV6NWkXdCdYk4n6Tm",
                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "uiTokenAmount": {
                    "amount": "123456",
                    "decimals": 9,
                    "uiAmount": 0.000123456,
                    "uiAmountString": "0.000123456"
                }
            }
        ],
        "preBalances": [
            1000000000000,
            0,
            2039280,
            1600880,
            1559040,
            93048240,
            0,
            1461600,
            953185920,
            1009200,
            1,
            8689365120,
            1
        ],
        "preTokenBalances": [
            {
                "accountIndex": 2,
                "mint": "7DWtjZjPtYkeYXUpBW5agYkK31Fs1HmgW5Ki6tJCqo4o",
                "owner": "Et6LGAWpyDKxQVuQQBhWRLdsEpvd72u1biTXE9mpNMdN",
                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "uiTokenAmount": {
                    "amount": "1000000000000",
                    "decimals": 9,
                    "uiAmount": 1000.0,
                    "uiAmountString": "1000"
                }
            }
        ],
        "rewards": [],
        "status": {
            "Ok": None
        }
    },
    "slot": 383,
    "transaction": {
        "message": {
            "accountKeys": [
                "Et6LGAWpyDKxQVuQQBhWRLdsEpvd72u1biTXE9mpNMdN",
                "GrLNNCkBiPWYtiFPXLvMtdZxZFs4TabzWEKEivh2QKMx",
                "CbZ4zAykrTr1vqeg2gG8neoW1yHwX6RYNZY5kNwsPYXG",
                "7FjLWQ34Dwd7qR7f4azAPewJL8SMXr86XJUwBz1wXHn8",
                "584Jgt7epupbdp8LDwu51ZRbqi7KV6NWkXdCdYk4n6Tm",
                "3W4ZxbruMWRXM1aHt2mv6ohhPniSqVPZhgvPjXkTD8SF",
                "AUaGDJq7yBLe2mVKUh3oUrmUd78uQfwTbqf3NPL25uYm",
                "7DWtjZjPtYkeYXUpBW5agYkK31Fs1HmgW5Ki6tJCqo4o",
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "SysvarRent111111111111111111111111111111111",
                "11111111111111111111111111111111",
                "53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io",
                "ComputeBudget111111111111111111111111111111"
            ],
            "header": {
                "numReadonlySignedAccounts": 0,
                "numReadonlyUnsignedAccounts": 3,
                "numRequiredSignatures": 1
            },
            "instructions": [
                {
                    "accounts": [],
                    "data": "16TYTJ8fLSxF",
                    "programIdIndex": 12
                },
                {
                    "accounts": [],
                    "data": "7YXqSw",
                    "programIdIndex": 12
                },
                {
                    "accounts": [
                        0,
                        10,
                        1
                    ],
                    "data": "7mas2DkELtNNM7rHzbTDNVhWkmQJAR",
                    "programIdIndex": 11  ### EVM CREATE ACCOUNT
                },
                {
                    "accounts": [
                        2,
                        1,
                        0
                    ],
                    "data": "498XbEqWSBH1",
                    "programIdIndex": 8  ### TOKEN APPROVE
                },
                {
                    "accounts": [
                        0,
                        3,
                        1,
                        10,
                        11,
                        4,
                        5,
                        1,
                        6,
                        7,
                        8,
                        9,
                        2
                    ],
                    "data": "M7TQxa23r1F6bz1wgmf7gLoD43pZYGdVBumwvhSAJzKjZJAt7huhv85HiC1vEbpYoEAyYcVW17RjLp8pCBX2dQhkoVkxFmpj2UoPoKVMF1bgQYXpXpNjy5gSR4QcxmSYBeWwRk1aqYRsYaAssxS4HhXzT1YBeAzxAqNqH3TXBk1H9zeDqSBXh63wJpRnu2SPv5wnkcKMDrw5QUTvvUgTwpPrVgp1qPioQs2F9WiDBJ6p",
                    "programIdIndex": 11  #### NEON EVM CALL
                }
            ],
            "recentBlockhash": "E4SXaxEKLsGCgQeedTRpVCqPGocX3qKusEvCJbq48RHF"
        },
        "signatures": [
            "2zJCbp84uBFa5KpNrXbz9zEFGptrxwKwuhxBNeQnBMweoRjNPbxLM3aQFp51fYafpqUENcCoLagFcupxbZe6V16P"
        ]
    },
    "version": "legacy"
}
