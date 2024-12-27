#!/bin/bash
cd "$(dirname "$0")"

if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
    PYTHON_EXECUTABLE="./.venv/bin/python"
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
    PYTHON_EXECUTABLE=".venv\\Scripts\\python.exe"
else
    echo "OS not supported: $OSTYPE"
    exit 1
fi

if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
    "$PYTHON_EXECUTABLE" pm_db.py
else
    sudo "$PYTHON_EXECUTABLE" pm_db.py
fi
