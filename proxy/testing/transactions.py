from ..common_neon.environment_data import EVM_LOADER_ID
import json

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0x04b27acb0013a31822ec1624c1a3066b023e3a93'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x4136faa9cae6c9afde37045a255b087f2ccfee75'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = json.loads('''
{
    "blockTime": 1675239756,
    "meta": {
        "computeUnitsConsumed": 209121,
        "err": null,
        "fee": 5000,
        "innerInstructions": [
            {
                "index": 2,
                "instructions": [
                    {
                        "accounts": [0,5],
                        "data": "11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf",
                        "programIdIndex": 9
                    }
                ]
            },
            {
                "index": 3,
                "instructions": [
                    {
                        "accounts": [0,1],
                        "data": "11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf",
                        "programIdIndex": 9
                    }
                ]
            },
            {
                "index": 5,
                "instructions": [
                    {
                        "accounts": [0,6],
                        "data": "3Bxs4PckVVt51W8w",
                        "programIdIndex": 9
                    },
                    {
                        "accounts": [
                            0,
                            8
                        ],
                        "data": "11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL",
                        "programIdIndex": 9
                    },
                    {
                        "accounts": [8,7,11],
                        "data": "5q9Uw58dPbh8oEmuZgSSVhSij54nUPaCiDFK46NkzLYCj",
                        "programIdIndex": 12
                    },
                    {
                        "accounts": [2,8,4],
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
            "Program log: Address: 0x508395a762322070ff52c5a62db814d7bdafbc71",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 10456 of 499944 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
            "Program log: Instruction: Create Account",
            "Program log: Address: 0x4136faa9cae6c9afde37045a255b087f2ccfee75",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 10456 of 489432 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
            "Program log: Instruction: Approve",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2902 of 478920 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]",
            "Program log: Instruction: Execute Transaction from Instruction",
            "Program data: SEFTSA== 831/i/uuxpLYk3Xk07MZje3Gfe1avaOGcpePh8Qyd/4=",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program data: RU5URVI= Q0FMTA== BLJ6ywAToxgi7BYkwaMGawI+OpM=",
            "Program data: TE9HMw== BLJ6ywAToxgi7BYkwaMGawI+OpM= Aw== 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAAQTb6qcrmya/eNwRaJVsIfyzP7nU= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=",
            "Program data: RVhJVA== UkVUVVJO",
            "Program 11111111111111111111111111111111 invoke [2]",
            "Program 11111111111111111111111111111111 success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
            "Program log: Instruction: InitializeAccount2",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4362 of 307054 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]",
            "Program log: Instruction: Transfer",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4735 of 299668 compute units",
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
            "Program data: R0FT AEUfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AEUfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "Program log: exit_status=0x12",
            "Program data: UkVUVVJO Eg==",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 185083 of 475962 compute units",
            "Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success"
        ],
        "postBalances": [999995180640,1385040,2039280,87368880,0,1385040,895880,1461600,2039280,1,1,1009200,929020800,1141440],
        "postTokenBalances": [
            {
                "accountIndex": 2,
                "mint": "Fu8h3siEnNdjoihPhRyzwsgmYw6CUfEfcva3futYAWX8",
                "owner": "FyzzR11RnSrJvfeofJMBdcuvBx4c3tCSNqvmaKYNj19p",
                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "uiTokenAmount": {
                    "amount": "999999876544",
                    "decimals": 9,
                    "uiAmount": 999.999876544,
                    "uiAmountString": "999.999876544"
                }
            },
            {
                "accountIndex": 8,
                "mint": "Fu8h3siEnNdjoihPhRyzwsgmYw6CUfEfcva3futYAWX8",
                "owner": "5UR18WbntwLW7TNt3dbkbutP5AVJUF5CUS3rKdvi5JGK",
                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "uiTokenAmount": {
                    "amount": "123456",
                    "decimals": 9,
                    "uiAmount": 0.000123456,
                    "uiAmountString": "0.000123456"
                }
            }
        ],
        "preBalances": [1000000000000,0,2039280,87368880,0,0,890880,1461600,0,1,1,1009200,929020800,1141440],
        "preTokenBalances": [
            {
                "accountIndex": 2,
                "mint": "Fu8h3siEnNdjoihPhRyzwsgmYw6CUfEfcva3futYAWX8",
                "owner": "FyzzR11RnSrJvfeofJMBdcuvBx4c3tCSNqvmaKYNj19p",
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
    "slot": 4072,
    "transaction": {
        "message": {
            "accountKeys": [
                "FyzzR11RnSrJvfeofJMBdcuvBx4c3tCSNqvmaKYNj19p",
                "qScMCUV95DCiy7Bj4nShJYgQmAkfK2eeUbxBfm7fRrr",
                "3snjoL3xURhTL5hPkdbQhP7ovBSzE9wvdsG4zdNq3dad",
                "5UR18WbntwLW7TNt3dbkbutP5AVJUF5CUS3rKdvi5JGK",
                "C5sx9dp1JZscWJD6datQHFqXYpmPY8U7DSCh8FToSn9C",
                "CGqu3RRPFyDGKbSUqKfUdJGn5nzRsEjvYffDrjDKc4UN",
                "E5FKFNZu4t6bPABb37vPrrdD2ouD2ycS6nsLcRQnj3Xv",
                "Fu8h3siEnNdjoihPhRyzwsgmYw6CUfEfcva3futYAWX8",
                "GPLo4L9j35PrecZaR62fqKLnLFdiDN32JXfa5Ui9zNAi",
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
                    "accounts": [0,9,5],
                    "data": "3UnN1NXKcJeCGcvmQV9sHoUiQvMeg",
                    "programIdIndex": 13
                },
                {
                    "accounts": [0,9,1],
                    "data": "3UZzzPrkk7ZnciWECoJ2VMzSVdLxL",
                    "programIdIndex": 13
                },
                {
                    "accounts": [2,4,0],
                    "data": "498XbEqWSBH1",
                    "programIdIndex": 12
                },
                {
                    "accounts": [0,6,5,9,13,3,5,7,8,2,4,11,12],
                    "data": "TjDbbsDNCryDtGGYA4MXa9pT7et6FgLvJPdf4ezz3twpbTrexM1HrC3QrKR1yNMYYizyEZNcYhXoLyzDbdpZGwCqPPrYsUMWgg4diCW6mbxXUzbyVwbMERRhADEY4rAqBAutTXaPq3BZxMVLRvffkSZGrZLTp3STFfmBVX8ZTZpks7b2iKsVqFuHAkxNtHpD8UWAhuptGzpheHyEybzKFDrn1bi1YL6zs6eRqB1VCv64tR1D52pzQ4WZWLt8VebjcbeYdQUeKihW4TsyMN825kJHJ",
                    "programIdIndex": 13
                }
            ],
            "recentBlockhash": "4Xss1Sw23WW2mWJvkr5GW7uwRsJxj6gC8yKnY7xqXZCm"
        },
        "signatures": [
            "2cv1WSMxCAUpLmug5RdNVeiBK4VYurFn6vQXLcs53bRyuWeD7wuf4X3FMGd2kMFnkrkyrRFxYZxr3PDA6pf8jnCv"
        ]
    }
}
''')
