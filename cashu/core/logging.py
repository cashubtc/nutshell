import logging
import sys

from loguru import logger

from ..core.settings import settings


def configure_logger() -> None:
    class Formatter:
        def __init__(self):
            self.padding = 0
            self.minimal_fmt = (
                "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> |"
                " <level>{level}</level> | <level>{message}</level>\n"
            )
            if settings.debug:
                self.fmt = (
                    "<green>{time:YYYY-MM-DD HH:mm:ss.SS}</green> | <level>{level:"
                    " <4}</level> |"
                    " <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan>"
                    " | <level>{message}</level>\n"
                )
            else:
                self.fmt = self.minimal_fmt

        def format(self, record):
            function = "{function}".format(**record)
            if function == "emit":  # uvicorn logs
                return self.minimal_fmt
            return self.fmt

    class InterceptHandler(logging.Handler):
        def emit(self, record):
            try:
                level = logger.level(record.levelname).name
            except ValueError:
                level = record.levelno
            logger.log(level, record.getMessage())

    logger.remove()
    log_level = settings.log_level
    if settings.debug and log_level == "INFO":
        log_level = "DEBUG"
    formatter = Formatter()
    logger.add(sys.stderr, level=log_level, format=formatter.format)

    logging.getLogger("uvicorn").handlers = [InterceptHandler()]
    logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]
