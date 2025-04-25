import logging
import coloredlogs

def setup_logging(log_level=None):
    """Configure logging settings based on the LOG_LEVEL environment variable.
    The function sets up logging configuration with colored output using the coloredlogs package.
    If LOG_LEVEL is set to "OFF", all logging will be disabled.  
    
    The logging format is: [timestamp] - [log level] - [message] ([source file name]:[line number])  
    
    Args:
        log_level (str): The logging level to set. If None, defaults to INFO.
    Returns:
        logger: Configured logger instance.
    """
    logger = logging.getLogger("ePA-3-Service")
    
    # Remove existing handlers to avoid duplicate logs
    if logger.hasHandlers():
        logger.handlers.clear()

    if log_level is None:
        log_level = 'INFO'
    else:
        logger.info(f"Logging configured with level: {log_level}")
        
    if log_level == "OFF":
        logging.disable(logging.CRITICAL) 
    else:
        fmt = "%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
        coloredlogs.install(level=log_level, fmt=fmt, logger=logger, reconfigure=False)
    return logger

logger = setup_logging() 
from app.constants import LOG_LEVEL
logger = setup_logging(LOG_LEVEL) 