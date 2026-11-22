GROUP 6 - ENCRYPTED BACKUP

Requirements:
- Windows
- Python 3.10 or newer

Run in VS Code:
1. Extract the ZIP and open the extracted Group6_Encrypted_Backup folder.
2. Open Terminal > New Terminal in VS Code.
3. Create and activate a virtual environment:

   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

4. Install dependencies:

   python -m pip install -r requirements.txt

5. Start the GUI:

   python main.py

Alternatively, press F5 and select "Run Encrypted Backup GUI".

If PowerShell blocks environment activation, run this once in the current
terminal, then activate the environment again:

   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1

The virtual environment is created on the user's own computer and is not
included in this ZIP. Never share real recovery key shares or real student data.
