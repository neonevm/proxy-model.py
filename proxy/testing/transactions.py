from ..common_neon.environment_data import EVM_LOADER_ID

token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
evm_loader_addr = EVM_LOADER_ID
erc20_wrapper = '0xf93af0b49bc6dca4806531efa6dfbc1d2be10925'
wrapper_whitelist = [erc20_wrapper]

token_airdrop_address = '0x75e4d39c59d106525f852570920099a6d53fbd39'

# Solana transaction for simple case airdrop
pre_token_airdrop_trx = {
    'blockTime': 1666260228, 
    'meta': {
        'computeUnitsConsumed': 269005, 
        'err': None, 
        'fee': 5000, 
        'innerInstructions': [
            {
                'index': 0, 
                'instructions': [
                    {
                        'accounts': [0, 4], 
                        'data': '11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf', 
                        'programIdIndex': 8
                    }
                ]
            }, {
                'index': 1, 
                'instructions': [
                    {
                        'accounts': [0, 2], 
                        'data': '11113wVRMNeTqMKuLWLrnhfLsDDSWgLi9gEuH53jqaF3ifDuquzHcp4Y9sH2iZ6JqvfVSf', 
                        'programIdIndex': 8
                    }
                ]
            }, {
                'index': 3, 
                'instructions': [
                    {
                        'accounts': [0, 3], 
                        'data': '3Bxs4PckVVt51W8w', 
                        'programIdIndex': 8
                    }, {
                        'accounts': [0, 5], 
                        'data': '11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL', 
                        'programIdIndex': 8
                    }, {
                        'accounts': [5, 6, 9], 
                        'data': '62q5Ao4Ftz87yzFn1Qq8Z25DFYrqTddpyfXnKTGjCQNXD', 
                        'programIdIndex': 10
                    }, {
                        'accounts': [1, 5, 4], 
                        'data': '3QK1PgBtAWnb', 
                        'programIdIndex': 10
                    }
                ]
            }
        ], 
        'loadedAddresses': {
            'readonly': [], 
            'writable': []
        }, 
        'logMessages': [
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]', 
            'Program log: Instruction: Create Account', 
            'Program 11111111111111111111111111111111 invoke [2]', 
            'Program 11111111111111111111111111111111 success', 
            'Program log: Total memory occupied: 488', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 8799 of 800000 compute units', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]', 
            'Program log: Instruction: Create Account', 
            'Program 11111111111111111111111111111111 invoke [2]', 
            'Program 11111111111111111111111111111111 success', 
            'Program log: Total memory occupied: 488', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 10299 of 791201 compute units', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]', 
            'Program log: Instruction: Approve', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 2902 of 780902 compute units', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io invoke [1]', 
            'Program log: Instruction: Execute Transaction from Instruction', 
            'Program data: SEFTSA== 6fZYiX8y6P8lXr/EZclnOK1D/ULgmPIa24Ed8g6Xnmw=', 
            'Program 11111111111111111111111111111111 invoke [2]', 
            'Program 11111111111111111111111111111111 success', 
            'Program 11111111111111111111111111111111 invoke [2]', 
            'Program 11111111111111111111111111111111 success', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]', 
            'Program log: Instruction: InitializeAccount2', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4362 of 549675 compute units', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]', 
            'Program log: Instruction: Transfer', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4735 of 542428 compute units', 
            'Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success', 
            'Program data: TE9HMw== +TrwtJvG3KSAZTHvpt+8HSvhCSU= AwAAAAAAAAA= 3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs+8= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= AAAAAAAAAAAAAAAAdeTTnFnRBlJfhSVwkgCZptU/vTk=  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4kA=', 
            'Program data: SVhfR0FT AEUfAAAAAAA=', 
            'Program log: ExitSucceed: Machine encountered an explict return. exit_status=0x12', 
            'Program data: UkVUVVJO Eg== AEUfAAAAAAA=', 
            'Program log: Total memory occupied: 25729', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io consumed 247005 of 778000 compute units', 
            'Program 53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io success'
        ], 
        'postBalances': [999995180640, 2039280, 1385040, 895880, 1385040, 2039280, 1461600, 96862320, 1, 1009200, 929020800, 8404673280], 
        'postTokenBalances': [
            {
                'accountIndex': 1, 
                'mint': 'GxSMe9ifHQ4hZY69uFqZA9orvF4m8g5GsLoSF9MUtYmm', 
                'owner': 'EXWUHz4YPG39tdNc7MrGa16P8eHiQ37LFe2BocpChzsP', 
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 
                'uiTokenAmount': {
                    'amount': '999999876544', 
                    'decimals': 9, 
                    'uiAmount': 999.999876544, 
                    'uiAmountString': 
                    '999.999876544'
                }
            }, {
                'accountIndex': 5, 
                'mint': 'GxSMe9ifHQ4hZY69uFqZA9orvF4m8g5GsLoSF9MUtYmm', 
                'owner': 'HA1ErSEJHNKgrwFKn2HovYNuYxYHiJhTviX7gXtv98ao', 
                'programId': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 
                'uiTokenAmount': {
                    'amount': '123456', 
                    'decimals': 9, 
                    'uiAmount': 0.000123456, 
                    'uiAmountString': '0.000123456'
                }
            }
        ], 
        'preBalances': [1000000000000, 2039280, 0, 890880, 0, 0, 1461600, 96862320, 1, 1009200, 929020800, 8404673280], 
        'preTokenBalances': [
            {
                'accountIndex': 1, 
                'mint': 'GxSMe9ifHQ4hZY69uFqZA9orvF4m8g5GsLoSF9MUtYmm', 
                'owner': 'EXWUHz4YPG39tdNc7MrGa16P8eHiQ37LFe2BocpChzsP', 
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
        'status': {'Ok': None}
    }, 
    'slot': 247, 
    'transaction': {
        'message': {
            'accountKeys': [
                'EXWUHz4YPG39tdNc7MrGa16P8eHiQ37LFe2BocpChzsP', 
                '7MKmwLg1jSMBtWKHM5ASzDH1KN3uFuiLPnTf4H2xs9Uq', 
                '7PNVw1eKM1JxQcutjk7HgwjEzNCJ2ayPPHJnFQSjAqqC', 
                'BTnEnoNFNnosnzM8n6c6fss4U8E3dw9mSaBEHYvQ3Ysm', 
                'E37Xc7uy2shCqpJgJzcDnHcuj3ooNwJevCG8ZRhEnEjs', 
                'GePDKY9cNMe9qFTbGC8sMN3G8TTVJGtrtv3CqArZDcBR', 
                'GxSMe9ifHQ4hZY69uFqZA9orvF4m8g5GsLoSF9MUtYmm', 
                'HA1ErSEJHNKgrwFKn2HovYNuYxYHiJhTviX7gXtv98ao', 
                '11111111111111111111111111111111', 
                'SysvarRent111111111111111111111111111111111', 
                'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 
                '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io'
            ], 
            'header': {
                'numReadonlySignedAccounts': 0, 
                'numReadonlyUnsignedAccounts': 4, 
                'numRequiredSignatures': 1
            }, 
            'instructions': [
                {
                    'accounts': [0, 8, 4], 
                    'data': '3Ux53Mc2Rv1upPKvfBJ8BSUKdQkD3', 
                    'programIdIndex': 11
                }, {
                    'accounts': [0, 8, 2], 
                    'data': '3VJZri4cPS7VCzTQJMmhA2UdbeJF2', 
                    'programIdIndex': 11
                }, {
                    'accounts': [1, 4, 0], 
                    'data': '498XbEqWSBH1', 
                    'programIdIndex': 10
                }, {
                    'accounts': [0, 3, 4, 8, 11, 4, 7, 5, 1, 6, 9, 10], 
                    'data': 'TNooUnBVUYkr3feDPkaHRTuPjPJMidnZmFM3jdgCC3TiQ3BMdU2UsC5JgUXcZah9mtKuSJ5rYMSLcrQ4bcwamFXML9cM1tpQUYRRoZJCDFs52TmpUMfhM8qduEBsZiXcwARvvRpcYykyJbXdpz7pissJ3jfPk769DYncJpRUQ8mbYYypf3YAJq4YCTScPAAFa6bsZrYt1TG7FER8wx3tizjXUHozRyRrz42VC8i5Qbg5R5FsmHVybEyPuGx257nmgrAEZcMZTYLwAdAsvhFCVNGzN', 
                    'programIdIndex': 11
                }
            ], 
            'recentBlockhash': '6DNbkiRMPKiPvk7UCcWcrJnD6Ji1macoW1QGqCLgk8Ut'
        }, 
        'signatures': ['Dgpyq4ocacYuJ6UbeQppc7FZzLGADHxpcd9AqJZuRGdTeWCfnmHde6BUFHRkkhR8dd4HHZmZzusZe9SyQEpBVfS']
    }, 
    'version': 'legacy'
}
