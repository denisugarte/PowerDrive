# PowerDrive
## A tool for de-obfuscating PowerShell script

Obfuscation is a technique used by malicious software to avoid detection. This tool allows de-obfuscation of previously obfuscated PowerShell scripts.

**IMPORTANT: Always execute this tool in an isolated environment as malware could be executed during de-obfuscation process.

## Usage

1. Open a new PowerShell instance.
2. Import PowerDrive module:
> Import-Module PowerDrive.psm1
3. Run tool:
> PowerDrive \.obfuscated_script.ps1
