#!/bin/bash
cd "$(dirname "$0")"

if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
    VENV_DIR="./.venv"
    PYTHON_EXECUTABLE="./.venv/bin/python"
    PIP_EXECUTABLE="./.venv/bin/pip"
    ACTIVATE_SCRIPT="./.venv/bin/activate"
    PYTHON_COMMAND="python3"
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
    VENV_DIR=".venv"
    PYTHON_EXECUTABLE=".venv\\Scripts\\python.exe"
    PIP_EXECUTABLE=".venv\\Scripts\\pip.exe"
    ACTIVATE_SCRIPT=".venv\\Scripts\\activate"
    PYTHON_COMMAND="python"
else
    echo "OS not supported: $OSTYPE"
    exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
    echo "Virtual environment not found. Creating .venv..."
    virtualenv "$VENV_DIR"
    if [[ $? -ne 0 ]]; then
        echo "Failed to create the virtual environment. Ensure Python is installed and accessible."
        exit 1
    fi
    echo ".venv created successfully."

    echo "Activating .venv and installing dependencies..."
    if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
        source "$ACTIVATE_SCRIPT"
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
        call "$ACTIVATE_SCRIPT"
    fi

    $PIP_EXECUTABLE install -r requirements.txt

    if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
      clear
    elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
        cls
    fi

    echo "Starting GCMark-Vault..."

    if [[ $? -ne 0 ]]; then
        echo "Failed to install dependencies. Check your requirements.txt file and network connection."
        deactivate
        exit 1
    fi
    deactivate
fi

if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" ]]; then
    "$PYTHON_EXECUTABLE" gcmark/cli.py
else
    "$PYTHON_EXECUTABLE" gcmark/cli.py
fi
