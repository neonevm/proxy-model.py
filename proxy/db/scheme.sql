    CREATE TABLE IF NOT EXISTS constants (
        key TEXT UNIQUE,
        value BYTEA
    );

    CREATE TABLE IF NOT EXISTS airdrop_scheduled (
        key TEXT UNIQUE,
        value BYTEA
    );

    DROP TABLE IF EXISTS neon_accounts;

    CREATE TABLE IF NOT EXISTS failed_airdrop_attempts (
        attempt_time    BIGINT,
        eth_address     TEXT,
        reason          TEXT
    );
    CREATE INDEX IF NOT EXISTS failed_attempt_time_idx ON failed_airdrop_attempts (attempt_time);

    CREATE TABLE IF NOT EXISTS airdrop_ready (
        eth_address     TEXT UNIQUE,
        scheduled_ts    BIGINT,
        finished_ts     BIGINT,
        duration        INTEGER,
        amount_galans   INTEGER
    );

    CREATE TABLE IF NOT EXISTS solana_blocks (
        block_slot BIGINT,
        block_hash CHAR(66),
        block_time BIGINT,
        parent_block_slot BIGINT,
        is_finalized BOOL,
        is_active BOOL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_blocks_slot ON solana_blocks(block_slot);
    CREATE INDEX IF NOT EXISTS solana_blocks_hash ON solana_blocks(block_hash);
    CREATE INDEX IF NOT EXISTS solana_blocks_slot_active ON solana_blocks(block_slot, is_active);


    CREATE TABLE IF NOT EXISTS neon_transaction_logs (
        address CHAR(42),
        block_slot BIGINT,

        tx_hash CHAR(66),
        tx_idx INT,
        tx_log_idx INT,
        log_idx INT,

        topic CHAR(66),
        log_data TEXT,

        topic_list BYTEA
    );
    CREATE UNIQUE INDEX IF NOT EXISTS neon_transaction_logs_block_tx_log ON neon_transaction_logs(block_slot, tx_hash, tx_log_idx);
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_address ON neon_transaction_logs(address);
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_topic ON neon_transaction_logs(topic);
    CREATE INDEX IF NOt EXISTS neon_transaction_logs_block_slot ON neon_transaction_logs(block_slot);

    CREATE TABLE IF NOT EXISTS solana_neon_transactions (
        sol_sign CHAR(88),
        block_slot BIGINT,
        idx INT,
        inner_idx INT,

        neon_sign CHAR(66),

        neon_step_cnt INT,
        neon_income INT,

        heap_size INT,

        max_bpf_cycle_cnt INT,
        used_bpf_cycle_cnt INT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_neon_transactions_neon_sol_idx_inner ON solana_neon_transactions(sol_sign, block_slot, idx, inner_idx);
    CREATE INDEX IF NOT EXISTS solana_neon_transactions_neon_sign ON solana_neon_transactions(neon_sign, block_slot);
    CREATE INDEX IF NOT EXISTS solana_neon_transactions_neon_block ON solana_neon_transactions(block_slot);

    CREATE TABLE IF NOT EXISTS neon_transactions (
        neon_sign CHAR(66),
        from_addr CHAR(42),

        sol_sign CHAR(88),
        sol_ix_idx INT,
        sol_ix_inner_idx INT,
        block_slot BIGINT,
        tx_idx INT,

        nonce TEXT,
        gas_price TEXT,
        gas_limit TEXT,
        value TEXT,
        gas_used TEXT,

        to_addr CHAR(42),
        contract CHAR(42),

        status CHAR(3),

        return_value TEXT,

        v VARCHAR(66),
        r VARCHAR(66),
        s VARCHAR(66),

        calldata TEXT,
        logs BYTEA
    );
    CREATE INDEX IF NOT EXISTS neon_transactions_sol_sign_block ON neon_transactions(sol_sign, block_slot);
    CREATE UNIQUE INDEX IF NOT EXISTS neon_transactions_neon_sign_block ON neon_transactions(neon_sign, block_slot);
    CREATE INDEX IF NOT EXISTS neon_transactions_block_slot_tx_idx ON neon_transactions(block_slot, tx_idx);

    CREATE TABLE IF NOT EXISTS solana_transaction_costs (
        sol_sign CHAR(88),
        block_slot BIGINT,

        operator CHAR(50),
        sol_spent INT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_transaction_costs_sign ON solana_transaction_costs(sol_sign, block_slot);
    CREATE INDEX IF NOT EXISTS solana_transaction_costs_slot ON solana_transaction_costs(block_slot);
    CREATE INDEX IF NOT EXISTS solana_transaction_costs_operator ON solana_transaction_costs(operator, block_slot);

    CREATE TABLE IF NOT EXISTS solana_transaction_signatures (
        block_slot  BIGINT,
        signature   CHAR(88)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_transaction_signatures_sign ON solana_transaction_signatures(block_slot);
