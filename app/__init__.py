"""RE-Nexus application package.

    app/server.py      — Flask application + engine routes (entry point)
    app/singleshot.py  — dependency-free asyncio WSGI server
    app/engines/       — analysis & dashboard engine modules

Run from the project root:

    python -m app.server         # or: python app/server.py
"""

__version__ = "1.0.0"
