"""Application logging helper."""

import logging
from pathlib import Path


def configure_logger(base_directory: Path | None = None) -> logging.Logger:
    base = base_directory or Path(__file__).resolve().parent
    log_directory = base / "logs"
    log_directory.mkdir(parents=True, exist_ok=True)
    log_file = log_directory / "activity.log"

    logger = logging.getLogger("group6_backup")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
