#!/bin/bash

# Script to manually install Python dependencies without pip
# Run this from the diagnosys-main directory

set -e  # Exit on error

echo "=== Installing dependencies manually (no pip required) ==="
echo ""

# Create lib directory
echo "Creating lib directory..."
mkdir -p lib
cd lib

# Install psutil
echo "Downloading and installing psutil..."
curl -L https://files.pythonhosted.org/packages/source/p/psutil/psutil-5.9.8.tar.gz -o psutil.tar.gz
tar -xzf psutil.tar.gz
cd psutil-5.9.8
python3 setup.py build
cp -r build/lib.*/psutil ../psutil
cd ..
rm -rf psutil-5.9.8 psutil.tar.gz
echo "✓ psutil installed"

# Install pygments (dependency for rich)
echo "Downloading and installing pygments..."
curl -L https://files.pythonhosted.org/packages/source/p/pygments/pygments-2.17.2.tar.gz -o pygments.tar.gz
tar -xzf pygments.tar.gz
cp -r pygments-2.17.2/pygments ./
rm -rf pygments-2.17.2 pygments.tar.gz
echo "✓ pygments installed"

# Install mdurl (dependency for markdown-it-py)
echo "Downloading and installing mdurl..."
curl -L https://files.pythonhosted.org/packages/source/m/mdurl/mdurl-0.1.2.tar.gz -o mdurl.tar.gz
tar -xzf mdurl.tar.gz
cp -r mdurl-0.1.2/mdurl ./
rm -rf mdurl-0.1.2 mdurl.tar.gz
echo "✓ mdurl installed"

# Install markdown-it-py (dependency for rich)
echo "Downloading and installing markdown-it-py..."
curl -L https://files.pythonhosted.org/packages/source/m/markdown-it-py/markdown_it_py-3.0.0.tar.gz -o markdown.tar.gz
tar -xzf markdown.tar.gz
cp -r markdown_it_py-3.0.0/markdown_it ./
rm -rf markdown_it_py-3.0.0 markdown.tar.gz
echo "✓ markdown-it-py installed"

# Install rich
echo "Downloading and installing rich..."
curl -L https://files.pythonhosted.org/packages/source/r/rich/rich-13.7.0.tar.gz -o rich.tar.gz
tar -xzf rich.tar.gz
cp -r rich-13.7.0/rich ./
rm -rf rich-13.7.0 rich.tar.gz
echo "✓ rich installed"

cd ..

echo ""
echo "=== All dependencies installed successfully! ==="
echo ""
echo "You can now run the application with:"
echo "  python3 -m diagnosys"
echo ""
