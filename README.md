# Frida Patcher
Frida Patcher is a patcher system designed for the Frida binary to avoid artifact-based detection. 
This tool helps bypass detection by patching binary artifacts.

# Features
- Patches Frida (Gadget, Server adn Inject) binaries to evade detection.
- Easy to use and integrate into existing workflows.

# Prerequisites
- Python version 3.x
- Frida binary (Gadget, Server or Inject).

# Installation
1. Clone the repository:
```bash
git clone https://github.com/electrondefuser/frida-bin-patcher.git
cd frida-bin-patcher
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

# How to use
Use the following command to patch a stock frida binary.
```bash
python main.py --binarypath bin/stock/<frida-binary> --output bin/patched/<output-path>
```
If you want to use the export verification system, use the following command.
```bash
python main.py --binarypath bin/stock/<frida-binary> --output bin/patched/<output-path> --verify
```
