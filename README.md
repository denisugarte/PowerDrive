# PowerDrive
## A Tool for De-Obfuscating PowerShell Scripts

Obfuscation is a technique used by malicious software to avoid detection. This tool allows de-obfuscating PowerShell scripts, even after multiple obfuscation attempts.

**IMPORTANT: Always execute PowerDrive in an isolated environment, as malware could be downloaded and executed during the de-obfuscation process.**

## How to use

1. Open a new PowerShell instance.
2. Import the PowerDrive module:
> Import-Module PowerDrive.psm1
3. Run PowerDrive (the file path containing the obfuscated PowerShell script must be passed):
> PowerDrive .\obfuscated_script.ps1

## Additional information
This tool has been developed in the context of a scientific paper that is going to be presented at the 16th Conference on Detection of Intrusions and Malware & Vulnerability Assessment (DIMVA) [1]. 

In particular, the file deobfuscated-scripts.txt includes the 4642 malicious obfuscated scripts that have been analyzed by PowerDrive, along with the de-obfuscation results. Moreover, an example showing a multi-layer de-obfuscation process is located in the file named *“multilayer_deobfuscation.txt”*. This example shows the de-obfuscation process of a script that combines string-related obfuscation, encoding and compression.

[1] Denis Ugarte, Davide Maiorca, Fabrizio Cara and Giorgio Giacinto. PowerDrive: Accurate De-Obfuscation and Analysis of PowerShell Malware. To appear in the 16th Conference on Detection of Intrusions and Malware & Vulnerability Assessment (DIMVA), Gotheborg, Sweden, 2019. 
