"""
Vercel Serverless Entrypoint for JOCKY FastAPI Backend
"""
import os
import sys

# Ensure project root is on sys.path so modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.main import app

# Export app for Vercel Serverless Functions
__all__ = ["app"]
