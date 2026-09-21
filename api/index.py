"""
Vercel Serverless Entrypoint for JOCKY FastAPI Backend
"""
import sys
import traceback
from pathlib import Path

# Add project root directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

try:
    from server.main import app
except Exception as e:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    err_tb = traceback.format_exc()
    app = FastAPI(title="JOCKY Error Handler")

    @app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def catch_all_error(path_name: str):
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Failed to initialize server.main",
                "error": str(e),
                "traceback": err_tb,
            },
        )

# Export app for Vercel Serverless Functions
__all__ = ["app"]
