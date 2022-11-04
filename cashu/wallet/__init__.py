import sys
import pkg_resources

sys.tracebacklimit = None  # type: ignore
__version__ = pkg_resources.get_distribution("cashu").version
