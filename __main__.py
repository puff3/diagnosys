import sys
from pathlib import Path

# Add lib folder to Python path so we can import manually installed dependencies
lib_path = Path(__file__).parent.parent / 'lib'
if lib_path.exists():
    sys.path.insert(0, str(lib_path))

from diagnosys.tui import DiagnosysTUI

def main():
    app = DiagnosysTUI()
    app.run()

if __name__ == "__main__":
    main()
