#!/usr/bin/env python3
"""
Main entry point for the Educational Antivirus Research Tool.

This script provides the primary command-line interface for the antivirus tool,
supporting all major operations including scanning, configuration management,
quarantine operations, and sample management.
"""
import sys
import os

# Add the current directory to Python path to ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == '__main__':
    main()