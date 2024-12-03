"""
Logging Utility
---------------
Provides a logger for debugging and monitoring.
"""

import logging

def get_logger(name: str) -> logging.Logger:
    """
    Create and configure a logger.

    Args:
        name (str): Name of the logger.

    Returns:
        logging.Logger: Configured logger.
    """
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger
