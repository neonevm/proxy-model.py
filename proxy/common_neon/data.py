

class NeonTxStatData:
    def __init__(self, neon_tx_hash: str, sol_spent: int, neon_income: int, tx_type: str, is_canceled: bool):
        self.neon_tx_hash = neon_tx_hash
        self.neon_income = neon_income
        self.tx_type = tx_type
        self.is_canceled = is_canceled
        self.sol_spent = sol_spent
        self.neon_step_cnt = 0
        self.bpf_cycle_cnt = 0
