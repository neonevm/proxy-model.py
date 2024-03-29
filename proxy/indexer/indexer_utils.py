import logging

from ..common_neon.config import Config, StartSlot


LOG = logging.getLogger(__name__)


def get_config_start_slot(cfg: Config, first_slot: int, finalized_slot: int, last_known_slot: int) -> int:
    cfg_start_slot = _get_cfg_start_slot(cfg, last_known_slot, finalized_slot)

    start_slot = max(cfg_start_slot, first_slot)
    LOG.info(
        f'FIRST_AVAILABLE_SLOT={first_slot}, FINALIZED_SLOT={finalized_slot}, '
        f'{cfg.start_slot_name}={cfg_start_slot}, '
        f'started from the slot {start_slot}'
    )
    return start_slot


def _get_cfg_start_slot(cfg: Config, last_known_slot: int, finalized_slot: int) -> int:
    """This function allow to skip some part of history.
    - LATEST - start from the last block slot from Solana
    - CONTINUE - the first start from the LATEST, on next starts from the last parsed slot
    - INTEGER - the first start from the INTEGER, on next starts CONTINUE
    """
    last_known_slot = 0 if not isinstance(last_known_slot, int) else last_known_slot

    start_slot = cfg.start_slot
    LOG.info(f'Starting with LAST_KNOWN_SLOT={last_known_slot} and {cfg.start_slot_name}={start_slot}')

    if isinstance(start_slot, int):
        if start_slot > finalized_slot:
            LOG.info(
                f'{cfg.start_slot_name}={start_slot} is bigger than finalized slot, '
                f"forced to use the Solana's finalized slot"
            )
            start_slot = StartSlot.Latest

    elif start_slot not in (StartSlot.Continue, StartSlot.Latest):
        LOG.error(f'Wrong value {cfg.start_slot_name}={start_slot}, forced to use {cfg.start_slot_name}=0')
        start_slot = 0

    if start_slot == StartSlot.Continue:
        if last_known_slot > 0:
            LOG.info(f'{cfg.start_slot_name}={start_slot}, started from the last run {last_known_slot}')
            return last_known_slot
        else:
            LOG.info(f"{cfg.start_slot_name}={start_slot}, forced to use the Solana's finalized slot")
            start_slot = StartSlot.Latest

    if start_slot == StartSlot.Latest:
        LOG.info(f"{cfg.start_slot_name}={start_slot}, started from the Solana's finalized slot {finalized_slot}")
        return finalized_slot

    assert isinstance(start_slot, int)
    if start_slot < last_known_slot:
        LOG.info(f'{cfg.start_slot_name}={start_slot}, started from the last run {last_known_slot}')
        return last_known_slot

    LOG.info(f'{cfg.start_slot_name}={start_slot}, started from the config start slot {start_slot}')
    return start_slot
