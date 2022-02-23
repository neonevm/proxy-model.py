from typing import Tuple


def CREATE_TABLE_OPERATOR_COST() -> Tuple[str, str]:
    table_name = 'OPERATOR_COST'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
        """, table_name


def CREATE_TABLE_NEON_ACCOUNTS() -> Tuple[str, str]:
    table_name = 'neon_accounts'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            neon_account CHAR(42),
            pda_account VARCHAR(50),
            code_account VARCHAR(50),
            slot BIGINT,
            code TEXT,

            UNIQUE(pda_account, code_account)
        );
        """, table_name


def CREATE_TABLE_FAILED_AIRDROP_ATTEMPTS() -> Tuple[str, str]:
    table_name = 'failed_airdrop_attempts'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            attempt_time    BIGINT,
            eth_address     TEXT,
            reason          TEXT
        );
        CREATE INDEX IF NOT EXISTS failed_attempt_time_idx ON {table_name} (attempt_time);
        """, table_name


def CREATE_TABLE_AIRDROP_READY() -> Tuple[str, str]:
    table_name = 'airdrop_ready'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            eth_address     TEXT UNIQUE,
            scheduled_ts    BIGINT,
            finished_ts     BIGINT,
            duration        INTEGER,
            amount_galans   INTEGER
        );
        """, table_name


def CREATE_TABLE_SOLANA_BLOCK() -> Tuple[str, str]:
    table_name = 'solana_block'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            slot BIGINT,
            hash CHAR(66),

            parent_hash CHAR(66),
            blocktime BIGINT,
            signatures BYTEA,

            UNIQUE(slot),
            UNIQUE(hash)
        );
        """, table_name


def CREATE_TABLE_NEON_TRANSACTION_LOGS() -> Tuple[str, str]:
    table_name = 'neon_transaction_logs'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            address CHAR(42),
            blockHash CHAR(66),
            blockNumber BIGINT,

            transactionHash CHAR(66),
            transactionLogIndex INT,
            topic TEXT,

            json TEXT,

            UNIQUE(blockNumber, transactionHash, transactionLogIndex)
        );
        CREATE INDEX IF NOT EXISTS {table_name}_block_hash ON {table_name}(blockHash);
        CREATE INDEX IF NOT EXISTS {table_name}_address ON {table_name}(address);
        CREATE INDEX IF NOT EXISTS {table_name}_topic ON {table_name}(topic);
        """, table_name


def CREATE_TABLE_SOLANA_NEON_TRANSACTIONS() -> Tuple[str, str]:
    table_name = 'solana_neon_transactions'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            sol_sign CHAR(88),
            neon_sign CHAR(66),
            slot BIGINT,
            idx INT,

            UNIQUE(sol_sign, neon_sign, idx),
            UNIQUE(neon_sign, sol_sign, idx)
        );
        """, table_name


def CREATE_TABLE_NEON_TRANSACTIONS() -> Tuple[str, str]:
    table_name = 'neon_transactions'
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            neon_sign CHAR(66),
            from_addr CHAR(42),
            sol_sign CHAR(88),
            slot BIGINT,
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
        """, table_name


def CREATE_TABLE_TRANSACTION_RECEIPTS(table_name='transaction_receipts') -> Tuple[str, str]:
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            slot        BIGINT,
            signature   VARCHAR(88),
            trx         BYTEA,
            PRIMARY KEY (slot, signature)
        );
        """, table_name


