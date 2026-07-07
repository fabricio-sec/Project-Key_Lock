__version__  = "2.4.6"
__author__   = "Fabrício Almeida (https://www.linkedin.com/in/fabrici04/)"

def _get_vault_version() -> int:
    from core.vault import VAULT_VERSION
    return VAULT_VERSION

def _get_vaultkey_version() -> int:
    from core.vault_format import VAULTKEY_VERSION
    return VAULTKEY_VERSION

from core.vault import VAULT_VERSION as __vault_version__
from core.vault_format import VAULTKEY_VERSION as __vaultkey_version__
