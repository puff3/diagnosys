#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$HOME/.diagnosys_venv"
PYTHON_CMD="python3"

echo "=========================================="
echo "  diagnosys - Auto Setup & Run"
echo "=========================================="
echo ""

if ! command -v $PYTHON_CMD &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3.7+"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "Found Python: $PYTHON_VERSION"
echo ""

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at $VENV_DIR..."
    $PYTHON_CMD -m venv $VENV_DIR
    echo "✓ Virtual environment created"
    echo ""
fi

echo "Activating virtual environment..."
source $VENV_DIR/bin/activate

echo "Installing/upgrading dependencies..."
pip install --quiet --upgrade pip
pip install --quiet psutil rich

echo "✓ Dependencies installed"
echo ""

if [ ! -d "diagnosys" ]; then
    echo "Creating diagnosys package directory..."
    mkdir -p diagnosys
    touch diagnosys/__init__.py
    echo "✓ Package directory created"
    echo ""
    echo "Please add your module files (diagnostics.py, recon.py, tui.py, __main__.py)"
    echo "to the diagnosys/ directory, then run this script again."
    exit 0
fi

if [ ! -f "diagnosys/__init__.py" ]; then
    touch diagnosys/__init__.py
fi

export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

echo "=========================================="
echo "  Launching diagnosys..."
echo "=========================================="
echo ""

if [ "$1" == "--sudo" ] || [ "$1" == "-s" ]; then
    echo "Running with sudo privileges..."
    sudo PYTHONPATH="$PYTHONPATH" $VENV_DIR/bin/python -m diagnosys
else
    python -m diagnosys
fi

deactivate 2>/dev/null || true
