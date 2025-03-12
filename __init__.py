from colorama import Fore, init, Style
import logging

# Setup colorama
init(autoreset=True)

# Setup logger
logging.basicConfig(
        format="[%(asctime)s] " \
            + "[%(levelname)s -> " \
            + f"{Fore.YELLOW}%(name)s{Style.RESET_ALL}] " \
            + "%(message)s",
        level=logging.DEBUG
    )
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# # Setup implicit loggers level
for l in [
        "httpcore.http11",
        "httpcore.connection",
        "urllib3.connectionpool"
    ]:
    logging.getLogger(l).setLevel(logging.ERROR)

from .api import DocumentDownloader
__all__ = [
        "DocumentDownloader"
    ]