import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler('pr_dashboard.log', maxBytes=10**6, backupCount=5),
            logging.StreamHandler()
        ]
    )