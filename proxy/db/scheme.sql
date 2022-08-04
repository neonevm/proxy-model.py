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
        block_hash TEXT,
        block_time BIGINT,
        parent_block_slot BIGINT,
        is_finalized BOOL,
        is_active BOOL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_blocks_slot ON solana_blocks(block_slot);
    CREATE INDEX IF NOT EXISTS solana_blocks_hash ON solana_blocks(block_hash);
    CREATE INDEX IF NOT EXISTS solana_blocks_slot_active ON solana_blocks(block_slot, is_active);


    CREATE TABLE IF NOT EXISTS neon_transaction_logs (
        address TEXT,
        block_slot BIGINT,

        tx_hash TEXT,
        tx_idx INT,
        tx_log_idx INT,
        log_idx INT,

        topic TEXT,
        log_data TEXT,

        topic_list BYTEA
    );
    CREATE UNIQUE INDEX IF NOT EXISTS neon_transaction_logs_block_tx_log ON neon_transaction_logs(block_slot, tx_hash, tx_log_idx);
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_address ON neon_transaction_logs(address);
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_topic ON neon_transaction_logs(topic);
    CREATE INDEX IF NOt EXISTS neon_transaction_logs_block_slot ON neon_transaction_logs(block_slot);

    CREATE TABLE IF NOT EXISTS solana_neon_transactions (
        sol_sig TEXT,
        block_slot BIGINT,
        idx INT,
        inner_idx INT,

        neon_sig TEXT,
        neon_step_cnt INT,

        heap_size INT,

        max_bpf_cycle_cnt INT,
        used_bpf_cycle_cnt INT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_neon_transactions_neon_sol_idx_inner ON solana_neon_transactions(sol_sig, block_slot, idx, inner_idx);
    CREATE INDEX IF NOT EXISTS solana_neon_transactions_neon_sig ON solana_neon_transactions(neon_sig, block_slot);
    CREATE INDEX IF NOT EXISTS solana_neon_transactions_neon_block ON solana_neon_transactions(block_slot);

    CREATE TABLE IF NOT EXISTS neon_transactions (
        neon_sig TEXT,
        from_addr TEXT,

        sol_sig TEXT,
        sol_ix_idx INT,
        sol_ix_inner_idx INT,
        block_slot BIGINT,
        tx_idx INT,

        nonce TEXT,
        gas_price TEXT,
        gas_limit TEXT,
        value TEXT,
        gas_used TEXT,

        to_addr TEXT,
        contract TEXT,

        status TEXT,

        return_value TEXT,

        v TEXT,
        r TEXT,
        s TEXT,

        calldata TEXT,
        logs BYTEA
    );
    CREATE INDEX IF NOT EXISTS neon_transactions_sol_sig_block ON neon_transactions(sol_sig, block_slot);
    CREATE UNIQUE INDEX IF NOT EXISTS neon_transactions_neon_sig_block ON neon_transactions(neon_sig, block_slot);
    CREATE INDEX IF NOT EXISTS neon_transactions_block_slot_tx_idx ON neon_transactions(block_slot, tx_idx);

    CREATE TABLE IF NOT EXISTS solana_transaction_costs (
        sol_sig TEXT,
        block_slot BIGINT,

        operator TEXT,
        sol_spent BIGINT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_transaction_costs_sig ON solana_transaction_costs(sol_sig, block_slot);
    CREATE INDEX IF NOT EXISTS solana_transaction_costs_slot ON solana_transaction_costs(block_slot);
    CREATE INDEX IF NOT EXISTS solana_transaction_costs_operator ON solana_transaction_costs(operator, block_slot);

    CREATE TABLE IF NOT EXISTS solana_transaction_signatures (
        block_slot  BIGINT,
        signature   TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS solana_transaction_signatures_sign ON solana_transaction_signatures(block_slot);
