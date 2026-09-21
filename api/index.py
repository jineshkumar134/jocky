"""
Vercel Serverless Entrypoint for JOCKY FastAPI Backend
"""
import sys
from pathlib import Path

# Add project root directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from server.main import app

# Export app for Vercel Serverless Functions
__all__ = ["app"]
