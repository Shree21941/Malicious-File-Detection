"""
common.py - Common utilities for PDF genome analysis
This file provides shared functionality for pdf_genome.py
"""

import sys
import os
import logging

# Setup logging
logger = logging.getLogger(__name__)

def log(message, level='INFO'):
    """Log a message"""
    if level == 'ERROR':
        logger.error(message)
    elif level == 'WARNING':
        logger.warning(message)
    elif level == 'DEBUG':
        logger.debug(message)
    else:
        logger.info(message)

def error(message):
    """Log an error message"""
    logger.error(message)
    print(f"ERROR: {message}", file=sys.stderr)

def warning(message):
    """Log a warning message"""
    logger.warning(message)
    print(f"WARNING: {message}", file=sys.stderr)

def debug(message):
    """Log a debug message"""
    logger.debug(message)

def get_file_type(file_path):
    """Get file type from extension"""
    _, ext = os.path.splitext(file_path)
    return ext.lower()

def file_exists(file_path):
    """Check if file exists"""
    return os.path.isfile(file_path)

def read_file(file_path, mode='rb'):
    """Read file contents"""
    try:
        with open(file_path, mode) as f:
            return f.read()
    except Exception as e:
        error(f"Failed to read file {file_path}: {e}")
        return None

def ensure_dir(directory):
    """Ensure directory exists"""
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory

class PDFException(Exception):
    """Custom exception for PDF processing errors"""
    pass

class AnalysisException(Exception):
    """Custom exception for analysis errors"""
    pass

# Constants that might be used by pdf_genome
PDF_MAGIC = b'%PDF-'
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

def is_pdf(file_path):
    """Check if file is a PDF"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(5)
            return header == PDF_MAGIC
    except:
        return False

def safe_int(value, default=0):
    """Safely convert value to int"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def safe_float(value, default=0.0):
    """Safely convert value to float"""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_success(message):
    """Print success message"""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")

def print_error(message):
    """Print error message"""
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")

def print_warning(message):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")

def print_info(message):
    """Print info message"""
    print(f"{Colors.OKBLUE}ℹ {message}{Colors.ENDC}")

# Export all utility functions
__all__ = [
    'log', 'error', 'warning', 'debug',
    'get_file_type', 'file_exists', 'read_file', 'ensure_dir',
    'PDFException', 'AnalysisException',
    'is_pdf', 'safe_int', 'safe_float',
    'print_success', 'print_error', 'print_warning', 'print_info',
    'Colors', 'PDF_MAGIC', 'MAX_FILE_SIZE'
]