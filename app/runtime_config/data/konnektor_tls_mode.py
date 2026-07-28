from enum import Enum

class KonnektorTlsMode(Enum):
    ALTERNATIVE = "alternative"
    INSECURE = "insecure"
    SMC_K = "smc_k"