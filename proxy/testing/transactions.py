from ..common_neon.environment_data import EVM_LOADER_ID
import json

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0x8ca9bfc0d669a6d3741e3ef184071d06f7ae66e2'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x3782062bc6d6f4584d360172e14d7bebfaaa6f2b'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = json.loads('''
{
    "blockTime": 1675177121,
    "meta": {
        "computeUnitsConsumed": 202108,
        "err": null,
        "fee": 5000,
        "innerInstructions": [
            {
                "index": 2,
                "instructions": [
                    {
                        "accounts": [0,7],
                        "data": "11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf",
                        "programIdIndex": 9
                    }
                ]
            },
            {
                "index": 3,
                "instructions": [
                    {
                        "accounts": [0,6],
                        "data": "11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf",
                        "programIdIndex": 9
                    }
                ]
            },
            {
                "index": 5,
                "instructions": [
                    {
                        "accounts": [0,5],
                        "data": "3Bxs4PckVVt51W8w",
                        "programIdIndex": 9
                    },
                    {
                        "accounts": [0,1],
                        "data": "11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL",
                        "programIdIndex": 9
                    },
                    {
                        "accounts": [1,4,11],
                        "data": "5uYKizwBRJTMdaVzGiUDXM9jZuSBqF4a19qzU7aa2P6DN",
                        "programIdIndex": 12
                    },
                    {
                        "accounts": [8,1,2],
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
            "Program log: Address: 0xd1ddb3bd5aed6b0ab3b6c97e03bca7023e1c006b",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 8956 of 499944 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
            "Program log: Instruction: Create Account",
            "Program log: Address: 0x3782062bc6d6f4584d360172e14d7bebfaaa6f2b",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 8956 of 490932 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
            "Program log: Instruction: Approve",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2902 of 481920 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
            "Program log: Instruction: Execute Transaction from Instruction",
            "Program data: SEFTSA== hlAUdgPk948DSwH9OEFAiK4ao9xnK0i5Y79+IBjmWD4=",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program data: RU5URVI= Q0FMTA== jKm/wNZpptN0Hj7xhAcdBveuZuI=",
            "Program data: TE9HMw== jKm/wNZpptN0Hj7xhAcdBveuZuI= Aw== 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAAN4IGK8bW9FhNNgFy4U176/qqbys= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=",
            "Program data: RVhJVA== UkVUVVJO",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
            "Program log: Instruction: InitializeAccount2",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4362 of 314020 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
            "Program log: Instruction: Transfer",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4735 of 306681 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program data: R0FT AEUfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AEUfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "Program log: exit_status=0x12",
            "Program data: UkVUVVJO Eg==",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 181070 of 478962 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success"
        ],
        "postBalances": [999995180640,2039280,0,87870000,1461600,895880,1385040,1385040,2039280,1,1,1009200,929020800,1141440],
        "postTokenBalances": [
            {
                "accountIndex": 1,
                "mint": "BV3wHh64tKNWX5ZkQT3XhFfgGLEVXcuS1xwbcqFBviPg",
                "owner": "9sFo4K9pbhZLTBTb5fNnFcuDuXtfKjSVR2jGLqjk7rGx",
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
                "mint": "BV3wHh64tKNWX5ZkQT3XhFfgGLEVXcuS1xwbcqFBviPg",
                "owner": "95D425WMnRv1GwFcaaAAVNsvFuNSumo7UfySWecrjvsX",
                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "uiTokenAmount": {
                    "amount": "999999876544",
                    "decimals": 9,
                    "uiAmount": 999.999876544,
                    "uiAmountString": "999.999876544"
                }
            }
        ],
        "preBalances": [1000000000000,0,0,87870000,1461600,890880,0,0,2039280,1,1,1009200,929020800,1141440],
        "preTokenBalances": [
            {
                "accountIndex": 8,
                "mint": "BV3wHh64tKNWX5ZkQT3XhFfgGLEVXcuS1xwbcqFBviPg",
                "owner": "95D425WMnRv1GwFcaaAAVNsvFuNSumo7UfySWecrjvsX",
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
    "slot": 667,
    "transaction": {
        "message": {
            "accountKeys": [
                "95D425WMnRv1GwFcaaAAVNsvFuNSumo7UfySWecrjvsX",
                "3mxao5wmx5ngUPoFK4B9RFzePM4h9tbrduxswJ11Mg38",
                "6D66c8hcrBASkoZppPpRYypYLnYPDDhkfwtJNsvrkzNX",
                "9sFo4K9pbhZLTBTb5fNnFcuDuXtfKjSVR2jGLqjk7rGx",
                "BV3wHh64tKNWX5ZkQT3XhFfgGLEVXcuS1xwbcqFBviPg",
                "CJvNEPQ4YD43kbo7bhZLifP7BVds887VB61ExLEgTGT8",
                "DipW5c64W55SR7CsXaDsR9TtzNdQMFNt2Wdpwe5m4jG9",
                "EZYePvLb57venxscyyZhQpxm4KJ3bte4sGMzJ9wnwWhP",
                "HruSXpEVqH8FLgqVHFp7dac439FoyvUx5NmJDPCnY212",
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
                    "accounts": [0,9,7],
                    "data": "3WatExwJ6eRBFhkBuAaPz7eGZuFpE",
                    "programIdIndex": 13
                },
                {
                    "accounts": [0,9,6],
                    "data": "3USA4rFoV3EcrXNmMqx61Abstc2mg",
                    "programIdIndex": 13
                },
                {
                    "accounts": [8,2,0],
                    "data": "498XbEqWSBH1",
                    "programIdIndex": 12
                },
                {
                    "accounts": [0,5,7,9,13,3,7,11,8,2,12,1,4],
                    "data": "TNEJGYMqNyQoEr9VJ4wkVacsvTjVzULHQk1iyGnVZ87v87co1irUCT82NK2SkJt9bj1CYBVWcfNsdJ4uw6srKZ1rCUQgTeNVeoGyH8TdJgJ4Y9s3VeidsRhMBJcxGH4xyyNMM8BT9CbhYSZ1PeGU8fct9R2hR4LaJjEWNxXg6PfpbpbFdXkEe9B3APadAHR8VANPFnpMXFZoRV9nuQnPRBKnboJBGYUYPs7tmo2aLhPv2v9NfFK4fUGRQBRipg1tiE1eHsC6yhubCn9h9rAbCjTCX",
                    "programIdIndex": 13
                }
            ],
            "recentBlockhash": "7Sxeic6dsUvDyWsgYGPbLBhfkf6szimHRGopUNuUaTcS"
        },
        "signatures": [
            "2adypp9rkmHBVSC3egDMsgvfM5nVydj71CPnxFwL9PpDmULECiwfJTxNTuqsBhpJHbPE8BjjjEUvqdHnmkgs3Niz"
        ]
    }
}
''')
