# PowerDrive
## A tool for de-obfuscating PowerShell script

Obfuscation is a technique used by malicious software to avoid detection. This tool allows de-obfuscation of previously obfuscated PowerShell scripts.

**IMPORTANT: Always execute this tool in an isolated environment as malware could be executed during de-obfuscation process.**

## How to use

1. Open a new PowerShell instance.
2. Import PowerDrive module:
> Import-Module PowerDrive.psm1
3. Run tool (file path with the obfuscated PowerShell script must be passed):
> PowerDrive .\obfuscated_script.ps1

## Additional information

To demonstrate correct functioning of the tool a set containing 4642 malicious PowerShell scripts has been analyzed. The output of every malicious script is located in the file named “deobfuscated_scripts.txt”.

Moreover, an example showing a multi-layer de-obfuscation process is located in the file named “multilayer_deobfuscation.txt”. This example shows the de-obfuscation process of a script that combines string-related obfuscation, encoding and compression.
