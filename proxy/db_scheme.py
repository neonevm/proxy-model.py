from typing import Tuple


def CREATE_TABLE_OPERATOR_COST() -> Tuple[str, str]:
    TABLE_NAME_OPERATOR_COST = 'OPERATOR_COST'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_OPERATOR_COST} (
            id SERIAL PRIMARY KEY,
            hash char(64),
            cost bigint,
            used_gas bigint,
            sender char(40),
            to_address char(40) ,
            sig char(100),
            status varchar(100),
            reason varchar(100)
        );
        """, TABLE_NAME_OPERATOR_COST


def CREATE_TABLE_NEON_ACCOUNTS() -> Tuple[str, str]:
    TABLE_NAME_NEON_ACCOUNTS = 'neon_accounts'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_NEON_ACCOUNTS} (
            neon_account CHAR(42),
            pda_account VARCHAR(50),
            code_account VARCHAR(50),
            slot BIGINT,
            code TEXT,

            UNIQUE(pda_account, code_account)
        );
        """, TABLE_NAME_NEON_ACCOUNTS


def CREATE_TABLE_FAILED_AIRDROP_ATTEMPTS() -> Tuple[str, str]:
    TABLE_NAME_FAILED_AIRDROP_ATTEMPTS = 'failed_airdrop_attempts'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_FAILED_AIRDROP_ATTEMPTS} (
            attempt_time    BIGINT,
            eth_address     TEXT,
            reason          TEXT
        );
        CREATE INDEX IF NOT EXISTS failed_attempt_time_idx ON {TABLE_NAME_FAILED_AIRDROP_ATTEMPTS} (attempt_time);
        """, TABLE_NAME_FAILED_AIRDROP_ATTEMPTS


def CREATE_TABLE_AIRDROP_READY() -> Tuple[str, str]:
    TABLE_NAME_AIRDROP_READY = 'airdrop_ready'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_AIRDROP_READY} (
            eth_address     TEXT UNIQUE,
            scheduled_ts    BIGINT,
            finished_ts     BIGINT,
            duration        INTEGER,
            amount_galans   INTEGER
        );
        """, TABLE_NAME_AIRDROP_READY


def CREATE_TABLE_SOLANA_BLOCK() -> Tuple[str, str]:
    TABLE_NAME_SOLANA_BLOCK = 'solana_block'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_SOLANA_BLOCK}_heights (
            slot BIGINT,
            height BIGINT,

            UNIQUE(slot),
            UNIQUE(height)
        );
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_SOLANA_BLOCK}_hashes (
            slot BIGINT,
            hash CHAR(66),

            parent_hash CHAR(66),
            blocktime BIGINT,
            signatures BYTEA,

            UNIQUE(slot),
            UNIQUE(hash)
        );
        """, TABLE_NAME_SOLANA_BLOCK


def CREATE_TABLE_NEON_TRANSACTION_LOGS() -> Tuple[str, str]:
    TABLE_NAME_NEON_TRANSACTION_LOGS = 'neon_transaction_logs'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_NEON_TRANSACTION_LOGS} (
            address CHAR(42),
            blockHash CHAR(66),
            blockNumber BIGINT,

            transactionHash CHAR(66),
            transactionLogIndex INT,
            topic TEXT,

            json TEXT,

            UNIQUE(blockNumber, transactionHash, transactionLogIndex)
        );
        CREATE INDEX IF NOT EXISTS {TABLE_NAME_NEON_TRANSACTION_LOGS}_block_hash ON {TABLE_NAME_NEON_TRANSACTION_LOGS}(blockHash);
        CREATE INDEX IF NOT EXISTS {TABLE_NAME_NEON_TRANSACTION_LOGS}_address ON {TABLE_NAME_NEON_TRANSACTION_LOGS}(address);
        CREATE INDEX IF NOT EXISTS {TABLE_NAME_NEON_TRANSACTION_LOGS}_topic ON {TABLE_NAME_NEON_TRANSACTION_LOGS}(topic);
        """, TABLE_NAME_NEON_TRANSACTION_LOGS


def CREATE_TABLE_SOLANA_NEON_TRANSACTIONS() -> Tuple[str, str]:
    TABLE_NAME_SOLANA_NEON_TRANSACTIONS = 'solana_neon_transactions'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_SOLANA_NEON_TRANSACTIONS} (
            sol_sign CHAR(88),
            neon_sign CHAR(66),
            slot BIGINT,
            idx INT,

            UNIQUE(sol_sign, neon_sign, idx),
            UNIQUE(neon_sign, sol_sign, idx)
        );
        """, TABLE_NAME_SOLANA_NEON_TRANSACTIONS


def CREATE_TABLE_NEON_TRANSACTIONS() -> Tuple[str, str]:
    TABLE_NAME_NEON_TRANSACTIONS = 'neon_transactions'
    return f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME_NEON_TRANSACTIONS} (
            neon_sign CHAR(66),
            from_addr CHAR(42),
            sol_sign CHAR(88),
            slot BIGINT,
            block_height BIGINT,
            block_hash CHAR(66),
            idx INT,

            nonce VARCHAR,
            gas_price VARCHAR,
            gas_limit VARCHAR,
            value VARCHAR,
            gas_used VARCHAR,

            to_addr CHAR(42),
            contract CHAR(42),

            status CHAR(3),

            return_value TEXT,

            v TEXT,
            r TEXT,
            s TEXT,

            calldata TEXT,
            logs BYTEA,

            UNIQUE(neon_sign),
            UNIQUE(sol_sign, idx)
        );
        """, TABLE_NAME_NEON_TRANSACTIONS


def CREATE_TABLE_TRANSACTION_RECEIPTS(table_name='transaction_receipts') -> Tuple[str, str]:
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            slot        BIGINT,
            signature   VARCHAR(88),
            trx         BYTEA,
            PRIMARY KEY (slot, signature)
        );
        """, table_name


