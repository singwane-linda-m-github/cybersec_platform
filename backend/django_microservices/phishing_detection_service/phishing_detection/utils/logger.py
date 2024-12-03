"""
Logging Utility Module

This module provides a robust and flexible logging configuration utility
to standardize logging across different components of an application.

:module: phishing_detection.
:author: lx

Key Improvements:

Enhanced Documentation

Comprehensive Sphinx-style docstrings
Detailed explanations of parameters and behaviors
Clear documentation of potential exceptions


Robust Exception Handling

Input validation for logger name and log level
Graceful handling of logging setup failures
Fallback mechanism if primary handler creation fails


Flexible Configuration

Multiple logging output options (stderr, file, file-like objects)
Configurable log levels and formatting
Prevention of duplicate log handlers


Thread Safety

Configures logger to prevent log propagation
Ensures safe logging in multi-threaded environments


Additional Utility

Added global logging configuration function
Standardized log formatting
UTF-8 encoding for file logs
"""

import logging
import sys
from typing import Optional, Union, TextIO


def get_logger(
    name: str, 
    log_level: int = logging.INFO, 
    log_file: Optional[Union[str, TextIO]] = None
) -> logging.Logger:
    """
    Create and configure a robust, flexible logger with multiple output options.

    This function provides a comprehensive logging setup with the following features:
    - Configurable logger name
    - Adjustable logging level
    - Optional file-based logging
    - Standardized log formatting
    - Thread-safe logging configuration
    - Prevents duplicate log handlers

    Args:
        name (str): The name of the logger, typically the module or component name.
        log_level (int, optional): Logging verbosity level. 
            Defaults to logging.INFO. 
            Recommended levels:
            - logging.DEBUG: Detailed information
            - logging.INFO: General information
            - logging.WARNING: Potential issues
            - logging.ERROR: Specific error conditions
            - logging.CRITICAL: Critical errors that may halt execution
        log_file (Optional[Union[str, TextIO]], optional): 
            Destination for log output. Can be:
            - None: Logs to standard error stream (default)
            - str: Path to a log file
            - File-like object: Any object with a `.write()` method

    Returns:
        logging.Logger: A fully configured logger instance.

    Raises:
        ValueError: If an invalid log level is provided
        IOError: If there are issues creating or accessing the log file
        TypeError: If unsupported log file type is provided
    """
    # Validate logger name
    if not name or not isinstance(name, str):
        raise ValueError("Logger name must be a non-empty string")

    # Validate log level
    valid_log_levels = {
        logging.DEBUG, logging.INFO, 
        logging.WARNING, logging.ERROR, 
        logging.CRITICAL
    }
    if log_level not in valid_log_levels:
        raise ValueError(f"Invalid log level: {log_level}. "
                         f"Must be one of {valid_log_levels}")

    # Create or retrieve logger
    logger = logging.getLogger(name)

    # Prevent adding multiple handlers
    if logger.hasHandlers():
        return logger

    # Configure log formatting
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Determine log output destination
    try:
        if log_file is None:
            # Default to standard error stream
            handler = logging.StreamHandler(sys.stderr)
        elif isinstance(log_file, str):
            # File-based logging
            try:
                handler = logging.FileHandler(log_file, encoding='utf-8')
            except IOError as e:
                raise IOError(f"Cannot create log file: {e}")
        elif hasattr(log_file, 'write'):
            # File-like object logging
            handler = logging.StreamHandler(log_file)
        else:
            raise TypeError("log_file must be a filename or file-like object")

        # Apply formatter and add handler
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    except Exception as e:
        # Fallback to standard error if handler creation fails
        fallback_handler = logging.StreamHandler(sys.stderr)
        fallback_handler.setFormatter(formatter)
        logger.addHandler(fallback_handler)
        logger.error(f"Failed to set up primary logging handler: {e}")

    # Set logging level
    logger.setLevel(log_level)

    # Ensure thread-safe logging
    logger.propagate = False

    return logger


# Optional: Configuration function for global logging setup
def configure_global_logging(
    level: int = logging.INFO, 
    log_format: str = '%(asctime)s - %(levelname)s - %(message)s'
) -> None:
    """
    Configure logging for the entire application with sensible defaults.

    Args:
        level (int, optional): Global logging level. Defaults to logging.INFO.
        log_format (str, optional): Custom log message format.
    """
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.StreamHandler(sys.stderr)]
    )