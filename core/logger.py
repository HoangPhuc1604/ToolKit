import logging
import sys
from colorama import Fore, Style, init

init(autoreset=True)


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname:<8}{Style.RESET_ALL}"
        return super().format(record)


def get_logger(name="ceh"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter("[%(asctime)s] [%(levelname)s] %(message)s",
                                        datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    return logger