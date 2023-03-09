import sys

sys.tracebacklimit = None  # type: ignore

from loguru import logger

from cashu.core.settings import DEBUG

# configure logger
logger.remove()
logger.add(sys.stderr, level="DEBUG" if DEBUG else "INFO")
