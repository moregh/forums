#!/usr/bin/env python3
"""
Integrated Forum Server
Serves both the FastAPI backend and static frontend files
"""
import uvicorn
import os
import sys
from config import DEFAULT_HOST, DEFAULT_PORT

def main():
    # Change to the directory containing this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    print("Starting integrated forum server...")
    print(f"Working directory: {os.getcwd()}")
    print("Available at:")
    print("  - http://localhost:8000 (or your configured host)")
    print("  - API endpoints: http://localhost:8000/api/*")
    print("  - Static files: http://localhost:8000/js/* and http://localhost:8000/styles.css")
    print("  - SPA routes: All other paths serve index.html")
    print()
    print("Press Ctrl+C to stop the server")

    try:
        # Import here to ensure we're in the right directory
        from app import app

        # Run the server
        uvicorn.run(
            app,
            host=DEFAULT_HOST,
            port=DEFAULT_PORT,
            reload=False,  # Set to True for development
            access_log=True
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()