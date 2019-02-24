<#
.SYNOPSIS
    Obfuscated PowerShell Script Deobfuscator
.DESCRIPTION
	This PowerShell Script allows to deobfuscate PowerShell Scripts that have been previously obfuscated. These obfuscation process can be several layers deep. The Script 
	runs iteratively deobfuscating each layer and finaly gets the Url where the malware is hosted. The main method used by the Script is called funtcion overwriting. With 
	these method, native PowerShell functions are changed so they can extract the information we want and thus, overcoming the obfuscation.

    ** Important Note: Only run this Script within an isolated sandbox, malware could be executed during the process. **
.NOTES
    File Name  : PowerDrive.psm1
    Author     : Denis Ugarte 
	Email      : denis.ugarte@gmail.com
	University : University of Cagliari
	Department : Department of Electrical and Electronic Engineering (DIEE)
	Laboratory : Pattern Recognition and Applications Lab (PRALab)
.PARAMETER InputObject
    The obfuscated PowerShell script.
.EXAMPLE
    PowerDrive .\ObfuscatedScript.ps1
#>

########################
# OVERWRITED FUNCTIONS #
########################

$Invoke_Expression_Override = @'
function Invoke-Expression() {
    param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	Write-Output "$($ObfuscatedScript)**ContinueDeobfuscating"
}
'@

#############
# FUNCTIONS #
#############

function GetObfuscatedScriptFromFile() {
	param(
        [Parameter(
			Mandatory = $True)]
        [PSObject[]]$InputFile
    )
	
    try {
		$FileEncoding = GetFileEncoding $InputFile
		if($FileEncoding -eq "ascii") {
			$FileContent = Get-Content $InputFile -ErrorAction Stop
		}
		else {
			$FileContent = Get-Content $InputFile -Encoding UTF8 -ErrorAction Stop
		}
		foreach($line in $FileContent) {
			$ObfuscatedScript += $line
		}
	}
    catch {
		throw "Error reading: '$($InputFile)'"
	}
	
	return $ObfuscatedScript
}

function GetFileEncoding() {
	param(
        [Parameter(
			Mandatory = $True)]
        [PSObject[]]$InputObject
    )
	
	[byte[]]$Bytes = Get-Content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $InputObject
	
	if($Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
		return "utf8"
	}
	else {
		return "ascii"
	}
}

function IsBase64() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$InputString
    )
	
	if($InputString -Match "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$") {
		return $True
	}
	else {
		return $False
	}
}

function DecodeBase64() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$StringBase64
    )
	
	
	$DecodedString = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($StringBase64))
	
	return $DecodedString
}

function ScriptToOneLine() {
	param(
        [Parameter(
			Mandatory = $True)]
        [array]$ObfuscatedScript
    )
	
	<#
	.DESCRIPTION
	Replaces new lines and carriage returns transforming multi-line scripts into one line ones.
	.PARAMETER ObfuscatedScript
	.OUTPUTS
	ObfuscatedScript in one line.
	#>
	
	$ObfuscatedScriptInOneLine = ""
	ForEach($line in $ObfuscatedScript) {
		$ObfuscatedScriptInOneLine += $line -replace "`n", "" -replace "`r", ""
	}
	
	return $ObfuscatedScriptInOneLine
}

function CleanScript() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	<#
	.DESCRIPTION
	Eliminates non ascii characters and escape characers with bad format.
	.PARAMETER ObfuscatedScript
	.OUTPUTS.
	Cleaned obfuscated script.
	#>
	
	if(ThereAreNonCompatibleAsciiCharacters $ObfuscatedScript) {
		$ObfuscatedScript = RemoveNonAsciiCharacters $ObfuscatedScript
	}
	if(EscapeCharactersWithBadFormat $ObfuscatedScript) {
		$ObfuscatedScript = RemoveEscapeCharactersWithBadFormat $ObfuscatedScript
	}
	
	return $ObfuscatedScript
}

function ThereAreNonCompatibleAsciiCharacters() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$RegexMatch = [Regex]::Match($ObfuscatedScript, "(?!\r|\n|\t)[\x00-\x1f\x7f-\xff]")
	if($RegexMatch.Success) {
		return $True
	}
	else {
		return $False
	}
}

function RemoveNonAsciiCharacters() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$ObfuscatedScript = $ObfuscatedScript -replace "[^\x00-\x7e]+", ""
	
	return $ObfuscatedScript
}

function EscapeCharactersWithBadFormat() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	if($ObfuscatedScript -Match '\"') {
		return $True
	}
	else {
		return $False
	}
}

function RemoveEscapeCharactersWithBadFormat() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
		
	$ObfuscatedScript = $ObfuscatedScript -replace '\\"', "'"
	
	return $ObfuscatedScript
}

function GoodSyntax() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	<#
	.DESCRIPTION
	Checks if script's syntax is correct.
	.PARAMETER ObfuscatedScript
	.OUTPUTS
	A boolean indicating whether the syntax is correct or not.
	#>
	
	$Errors = @()
	[void][System.Management.Automation.Language.Parser]::ParseInput($ObfuscatedScript, [ref]$Null, [ref]$Errors)
	
	return [bool]($Errors.Count -lt 1)
}

function UsesFileExplorer() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	<#
	.DESCRIPTION
	Check if the obfuscated script uses Internet Explorer to download the malware from a remote server.
	.PARAMETER ObfuscatedScript
	.OUTPUTS
	A boolean indicating whether the script uses Internet Explorer to download the malware or not.
	#>
	
	
	$RegexMatch = [Regex]::Match($ObfuscatedScript, "explorer\.exe ")
	
	if($RegexMatch.Success) {
		return $True
	}
	else {
		return $False
	}
}

function ExtractUrls() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$Script
    )
	
	<#
	.DESCRIPTION
	Extracts URLs from the script.
	.PARAMETER Script
	.OUTPUTS
	An array with all the extracted URLs.
	#>
	
	$Urls = @()
	$Url = ""
	$Pattern = "(((http|https):\/\/)|www\.?)(.*?)(\""|\'|\})"
	$Regex = [Regex]::Matches($Script, $Pattern)
	Foreach($Group in $Regex.Groups) {
		if($Group.Name -eq 0) {
			$Url = $Group.Value
			$Url = $Url.SubString(0, $Url.Length - 1)
			$Urls += $Url
		}
	}
		
	return $Urls
}

function IsUrlActive() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$Url
    )
	
	$HTTP_Request = [System.Net.WebRequest]::Create($Url)
	try {
		$HTTP_Response = $HTTP_Request.GetResponse()
	}
	catch [Net.WebException] {
		return $False
	}
	$HTTP_Status = [int]$HTTP_Response.StatusCode
	
	if($HTTP_Status -eq 200) {
		return $True
	}
	else {
		return $False
	}
}

function ContainsSleepCommand() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	if($ObfuscatedScript -Match "sleep") {
		return $True
	}
	else {
		return $False
	}
}

function ReduceSleepCounter() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$RegexMatch = [Regex]::Match($ObfuscatedScript, "(.*?)(?i)sleep (.*?)\;(.*?)\z")
	if($RegexMatch.Success) {
		$ObfuscatedScript = $RegexMatch.Groups[1].Value + " sleep 1;" + $RegexMatch.Groups[3].Value
	}
	
	return $ObfuscatedScript
}

function ThereIsNullOutputRedirection() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	<#
	.DESCRIPTION
	Checks whether malware output is redirected to null output.
	.PARAMETER ObfuscatedScript
	.OUTPUTS
	A boolean indicating whether output is redirected to null output or not.
	#>
	
	$RegexMatch = [Regex]::Match($ObfuscatedScript, "(?i)out-null")
	if($RegexMatch.Success) {
		return $True
	}
	else {
		return $False
	}
}

function RemoveOutputHiding() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	<#
	.DESCRIPTION
	Removes null output redirection.
	.PARAMETER ObfuscatedScript
	.OUTPUTS
	Original script without null output redirection.
	#>
	
	$ObfuscatedScriptWithoutOutputHiding = ""
	$RegexMatch = [Regex]::Match($ObfuscatedScript, "(.*?)\|\s*(?i)out-null\s*(.*?)\z")
	Foreach($Group in $RegexMatch.Groups) {
		if($Group.Name -ne 0) {
			$ObfuscatedScriptWithoutOutputHiding += $Group.Value
		}
	}
	
	return $ObfuscatedScriptWithoutOutputHiding
}

function ContainsEndlessLoopType1() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$Regex = [Regex]::Match($ObfuscatedScript, "do\s*\{(.*?)\}\s*(i?)while\s*\(\!\$\?\)")
	if($Regex.Success) {
		return $True
	}
	else {
		return $False
	}
	
	return $Found
}

function RemoveEndlessLoopType1() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$ObfuscatedScriptWithoutEndlessLoops = ""
	$Regex = [Regex]::Match($ObfuscatedScript, "(.*?)do\s*\{(.*?)\}\s*(i?)while\s*\(\!\$\?\)(.*?)\z")
	Foreach($Group in $Regex.Groups) {
		if($Group.Name -ne 0) {
			$ObfuscatedScriptWithoutEndlessLoops += $Group.Value
		}
	}
	
	return $ObfuscatedScriptWithoutEndlessLoops
}

function ContainsEndlessLoopType2() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$Regex = [Regex]::Match($ObfuscatedScript, "do\s*\{(.*?)\}\s*(i?)while\s*\(\!\$\{\?\}\)")
	if($Regex.Success) {
		return $True
	}
	else {
		return $False
	}
	
	return $Found
}

function RemoveEndlessLoopType2() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$ObfuscatedScriptWithoutEndlessLoops = ""
	$Regex = [Regex]::Match($ObfuscatedScript, "(.*?)do\s*\{(.*?)\}\s*(i?)while\s*\(\!\$\{\?\}\)(.*?)\z")
	Foreach($Group in $Regex.Groups) {
		if($Group.Name -ne 0) {
			$ObfuscatedScriptWithoutEndlessLoops += $Group.Value
		}
	}
	
	return $ObfuscatedScriptWithoutEndlessLoops
}

function TryCatchBlockExists() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$ObfuscatedScript = $ObfuscatedScript -replace "`t|`n|`r", ""
	if($ObfuscatedScript -Match "(.*?)(?i)try\s*\{(.*?)\}\s*(?i)catch\s*\{(.*?)\}") {
		return $True
	}
	else {
		return $False
	}
}

function RemoveTryCatchBlocks() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$ObfuscatedScript = $ObfuscatedScript -replace "`t|`n|`r", ""
	$RegexMatch = [Regex]::Match($ObfuscatedScript, "(.*?)(?i)try\s*\{(.*?)\}(.*?)\{(.*?)\}(.*)")
	Foreach($Match in $RegexMatch.Groups) {
		if($Match.Value -Match "catch" -and $Match.Name -ne 0) {
			$CatchCodeBlockIndex = [convert]::ToInt32($Match.Name, 10) + 1
		}
	}
	Foreach($Match in $RegexMatch.Groups) {
		if($Match.Value -notMatch "try" -and $Match.Value -notMatch "catch" -and $Match.Name -ne 0 -and $Match.Name -ne $CatchCodeBlockIndex) {
			$ObfuscatedScriptWithoutTryCatch = $ObfuscatedScriptWithoutTryCatch + $Match.Value
		}
	}
	
	return $ObfuscatedScriptWithoutTryCatch
}

function AddErrorHandlerToObfuscatedScript() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscatedScript
    )
	
	$ErrorHandler1 = @'
	try {
	
'@
	$ObfuscatedScriptErrorHandled = $ErrorHandler1 + $ObfuscatedScript	
	$ErrorHandler2 = @'

	}
	catch [Net.WebException] {
		Write-Output "connectionError"
	}
	catch {
		Write-Output "executionError"
		return $_
	}
'@
	$ObfuscatedScriptErrorHandled = $ObfuscatedScriptErrorHandled + $ErrorHandler2

	return $ObfuscatedScriptErrorHandled
}

function ContinueDeobfuscating() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$DeobfuscationProcess
    )
	
	if($DeobfuscationProcess -eq "ContinueDeobfuscating") {
		return $True
	}
	else {
		return $False
	}
}

function DeobfuscateALayer() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$Deobfuscator
    )
	
	$DeobfuscationOutput = (powershell $Deobfuscator)
	
	return $DeobfuscationOutput
}

function ThereIsAnErrorDuringScriptExecution() {
	param(
        [Parameter(
			Mandatory = $True)]
        [array]$DeobfuscationOutput
    )
	
	$ErrorFound = $False
	Foreach($Element in $DeobfuscationOutput) {
		if($Element -Match "executionError" -or $Element -Match "connectionError") {
			$ErrorFound = $True
		}
	}
	
	return $ErrorFound
}

function GetErrorInfoFromOutput() {
	param(
        [Parameter(
			Mandatory = $True)]
        [array]$DeobfuscationOutput
    )
	
	$ErrorFound = $False
	$ErrorMessage = ""
	$ErrorType = ""
	Foreach($Element in $DeobfuscationOutput) {
		if($ErrorFound) {
			$ErrorMessage += "$($Element)`n"
		}
		else {
			if($Element -Match "executionError" -or $Element -Match "connectionError") {
				$ErrorType = $Element
				$ErrorFound = $True
			}
		}
	}
	
	return @($ErrorType, $ErrorMessage)
}

function IsAnArray() {
	param(
        [Parameter(
			Mandatory = $True)]
        [array]$DeobfuscationOutput
    )
	
	if($DeobfuscationOutput -is [array]) {
		return $True
	}
	else {
		return $False
	}
}

function FromArrayToString() {
	param(
        [Parameter(
			Mandatory = $True)]
        [array]$DeobfuscationOutput
    )
	
	$String = ""
	Foreach($Element in $DeobfuscationOutput) {
		$String = $String + $Element
	}
	
	return $String
}

function CommandIsObfuscated() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$Command
    )
	
	$Found = $False
	Foreach($Line in $Command.Split("`n")) {
		$Regex = [Regex]::Match($Command, "(\{\d\}\'\s*-f)|(\'(.*?)\'\s*\+\s*\'(.*?)\')")
		if($Regex.Success) {
			$Found = $True
		}
	}
	
	return $Found
}

function DeobfuscateCommand() {
    param(
        [Parameter(
			Mandatory = $True)]
        [string]$Command
    )
	
	$Command = $Command -replace "\'\s*\+\s*\'", ""
	$Command = $Command -replace '\"\s*\+s*\"', ""
	$Command = $Command -replace "``", ""
	
	$Regex = [Regex]::Match($Command, "\'\{(.*?)\}\'\s*-f")
	if($Regex.Success) {
		$Command = RemoveStringFormatting $Command
	}
	
	return $Command
}

function RemoveStringFormatting() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$Script
    )
	
	<#
	.DESCRIPTION
	Removes string formatting used for obfuscation.
	.PARAMETER Script
	.OUTPUTS
	Script without formatted strings.
	#>
	
	$NewScript = ""
	
	$Regex = [Regex]::Matches($Script, "(.*?)\(\'\{(.*?)\}\'\s*-f\s*\'(.*?)\'\)")
	Foreach($Match in $Regex) {
		$FormattedStringPositionsPart = "{$($Match.Groups[2].Value)}"
		$FormattedStringWordsPart = "'$($Match.Groups[3].Value)'"
		$FormattedString = RemoveOneStringFormatting $FormattedStringPositionsPart $FormattedStringWordsPart
		$NewScript += $Match.Groups[1].Value + "'" + $FormattedString + "'"
	}
	
	$LastPartOfScript = $Script -replace "(.*?)\'\{(.*?)\}\'\s*-f\s*\'(.*?)\'\)", ""
	
	$Script = $NewScript + $LastPartOfScript
	
	return $Script
}

function RemoveOneStringFormatting() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$FormattedStringPositionsPart,
		[string]$FormattedStringWordsPart
    )
	
	<#
	.DESCRIPTION
	Removes one string formatting.
	.PARAMETER FormattedStringWordPositions
	Indexes of the formatted string words.
	.PARAMETER FormattedStringWords
	Words in the formatting string.
	.OUTPUTS
	String without string formatting operation.
	#>
	
	$RegexPositions = [Regex]::Matches($FormattedStringPositionsPart, "\{(.*?)\}")
	$RegexWords = [Regex]::Matches($FormattedStringWordsPart, "\'(.*?)\'")
	
	$FormattedStringWordsPositions = GetFormattingStringPositions $RegexPositions
	$FormattedStringWords = GetFormattingStringWords $RegexWords
	
	$originalString = ""
	For($pos = 0; $pos -lt $FormattedStringWords.Length; $pos++) {
		$originalString += $FormattedStringWords[$FormattedStringWordsPositions[$pos]]
	}
	
	return $originalString
}

function GetFormattingStringPositions() {
	param(
        [Parameter(
			Mandatory = $True)]
		[array]$RegexPositions
    )
	
	<#
	.DESCRIPTION
	Get positions of words the formated string.
	.PARAMETER RegexPositions
	.OUTPUTS
	Positions of words the formated string.
	#>
	
	$FormattedStringWordsPositions = @()
	Foreach($Match in $RegexPositions) {
		Foreach($Group in $Match.Groups) {
			if($Group.Name -ne 0) {
				$FormattedStringWordsPositions += $Group.Value
			}
		}
	}
	
	return $FormattedStringWordsPositions
}

function GetFormattingStringWords() {
	param(
        [Parameter(
			Mandatory = $True)]
		[array]$RegexWords
    )
	
	<#
	.DESCRIPTION
	Gets words from the formatted string.
	.PARAMETER RegexWords
	.OUTPUTS
	Words from the fomatted string.
	#>
	
	$FormattedStringWords = @()
	Foreach($Match in $RegexWords) {
		Foreach($Group in $Match.Groups) {
			if($Group.Name -ne 0) {
				$FormattedStringWords += $Group.Value
			}
		}
	}
	
	return $FormattedStringWords
}

function GetObfuscationLayers() {
	param(
        [Parameter(
			Mandatory = $False)]
        [array]$ObfuscationLayers
    )
	
	ForEach ($Layer in $ObfuscationLayers) {
		$Heading = "#"*30 + " Layer " + ($ObfuscationLayers.IndexOf($Layer) + 1) + " " + "#"*30
		$ScriptOutput = "$($ScriptOutput)$($Heading)`n$($Layer)`n"
	}
	
	return $ScriptOutput
}

function FormatSyntaxErrorOutput() {
	param(
		[Parameter(
			Mandatory = $True)]
		[string]$CommandWithSyntaxErrors,
        [Parameter(
			Mandatory = $False)]
        [string]$ObfuscationLayersOutput
    )
	
	<#
	.DESCRIPTION
	Give specific format to Syntax Error output.
	.PARAMETER CommandWithSyntaxErrors
	.PARAMETER ObfuscationLayersOutput
	.OUTPUTS
	Output with specific format.
	#>
	
	$Heading = "#"*30 + " Syntax error " + "#"*30
	if($ObfuscationLayersOutput -eq "") {
		$Output = "$($Heading)`n$($CommandWithSyntaxErrors)"
	}
	else {
		$Output = "$($ObfuscationLayersOutput)`n$($Heading)`n$($CommandWithSyntaxErrors)"
	}
	
	return $Output
}

function FormatMalwareCodeOutput() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscationLayersOutput,
		[Parameter(
			Mandatory = $True)]
        [string]$Url
    )
	
	<#
	.DESCRIPTION
	Give specific format to Syntax Error output.
	.PARAMETER ObfuscationLayersOutput
	.PARAMETER Url
	.OUTPUTS
	Output with specific format.
	#>

	$Heading = "#"*30 + " Malicious code " + " " + "#"*30
	$Output = "$($ObfuscationLayersOutput)$($Heading)`nMalware hosting URLs: "
	ForEach($UrlUp in $UrlsUp) {
		$Output = "$($Output)$($UrlUp), "
	}
	$Output = $Output.Substring(0, $Output.Length - 2)
	
	return $Output
}

function FormatConnectionErrorOutput() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscationLayersOutput,
		[Parameter(
			Mandatory = $True)]
        [array]$UrlsDown,
		[Parameter(
			Mandatory = $False)]
        [array]$UrlsUp
    )
	
	<#
	.DESCRIPTION
	Give specific format to Syntax Error output.
	.PARAMETER ObfuscationLayersOutput
	.PARAMETER UrlsDown
	.PARAMETER UrlsUp
	.OUTPUTS
	Output with specific format.
	#>
	
	$Heading = "#"*26 + " Connection error " + "#"*26
	$Output = "$($ObfuscationLayersOutput)$($Heading)`nCannot connect to remote malware hosting servers. Remote URLs: "
	
	ForEach($UrlDown in $UrlsDown) {
		$Output = "$($Output)$($UrlDown), "
	}
	$Output = $Output.Substring(0, $Output.Length - 2)
	if($UrlsUp) {
		$Output = "$($Output)`nSome malware hosting servers are active. Remote URLs: "
		ForEach($UrlUp in $UrlsUp) {
			$Output = "$($Output)$($UrlUp), "
		}
		$Output = $Output.Substring(0, $Output.Length - 2)
	}
			
	return $Output
}

function FormatExecutionErrorOutput() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscationLayersOutput,
		[Parameter(
			Mandatory = $True)]
        [string]$ErrorMessage,
		[Parameter(
			Mandatory = $True)]
        [string]$Command
    )
	
	<#
	.DESCRIPTION
	Give specific format to Syntax Error output.
	.PARAMETER ObfuscationLayersOutput
	.PARAMETER ErrorMessage
	.PARAMETER Command
	.OUTPUTS
	Output with specific format.
	#>

	$Heading = "#"*30 + " Execution error " + "#"*30
	$Output = "$($ObfuscationLayersOutput)$($Heading)`nObfuscated Script execution error:`n$($ErrorMessage)"
	
	return $Output
}

function FormatNotDeobfuscatedOutput() {
	param(
        [Parameter(
			Mandatory = $True)]
        [string]$ObfuscationLayersOutput
    )
	
	<#
	.DESCRIPTION
	Give specific format to Syntax Error output.
	.PARAMETER ObfuscationLayersOutput
	.OUTPUTS
	Output with specific format.
	#>
	
	$Output = "$($ObfuscationLayersOutput)`nCould not deobfuscate PowerShell Script."
	
	return $Output
}

function PowerDrive {
    param(
        [Parameter(
			Mandatory = $True)]
        [PSObject[]]$InputFile
	)

	#Initialize variables
    $OverriddenFunctions = @()
	$OverriddenFunctions += $Invoke_Expression_Override
	$ObfuscationLayers  = New-Object System.Collections.Generic.List[System.Object]
	$DeobfuscationProcess = "ContinueDeobfuscating"
    $ObfuscatedScript = GetObfuscatedScriptFromFile $InputFile
	$ObfuscationLayersOutput = ""
	
	#Start deobfuscation process
	if(IsBase64 $ObfuscatedScript) {
		$ObfuscationLayers.Add($ObfuscatedScript)
		$ObfuscatedScript = DecodeBase64 $ObfuscatedScript
	}
	$ObfuscatedScriptOriginal = $ObfuscatedScript
	$ObfuscatedScriptModified = $ObfuscatedScript
	$ObfuscatedScriptModified = ScriptToOneLine $ObfuscatedScriptModified
	$ObfuscatedScriptModified = CleanScript $ObfuscatedScriptModified
	if(!(GoodSyntax $ObfuscatedScriptModified)) {
		$ObfuscationLayersOutput = GetObfuscationLayers $ObfuscationLayers
		$Output = FormatSyntaxErrorOutput $ObfuscatedScriptOriginal $ObfuscationLayersOutput
		Write-Output $Output
		
		return
	}
	if(UsesFileExplorer $ObfuscatedScriptModified) {
		$ObfuscationLayers.Add($ObfuscatedScriptOriginal)
		$ObfuscationLayersOutput = GetObfuscationLayers $ObfuscationLayers
		$Urls = ExtractUrls $ObfuscatedScriptModified
		if(IsUrlActive $Urls[0]) {
			$Output = FormatMalwareCodeOutput $ObfuscationLayersOutput $Urls[0]
			Write-Output $Output
		}
		else {
			$Output = FormatConnectionErrorOutput $ObfuscationLayersOutput $Urls[0] @()
			Write-Output $Output
		}
		
		return
	}
	if(ContainsSleepCommand $ObfuscatedScriptModified) {
		$ObfuscatedScriptModified = ReduceSleepCounter $ObfuscatedScriptModified
	}
	if(ThereIsNullOutputRedirection $ObfuscatedScriptModified) {
		$ObfuscatedScriptModified = RemoveOutputHiding $ObfuscatedScriptModified
	}
	if(ContainsEndlessLoopType1 $ObfuscatedScriptModified) {
		$ObfuscatedScriptModified = RemoveEndlessLoopType1 $ObfuscatedScriptModified
	}
	if(ContainsEndlessLoopType2 $ObfuscatedScriptModified) {
		$ObfuscatedScriptModified = RemoveEndlessLoopType2 $ObfuscatedScriptModified
	}
	if(TryCatchBlockExists $ObfuscatedScriptModified) {
		$ObfuscatedScriptWithoutTryCatch = RemoveTryCatchBlocks $ObfuscatedScriptModified
		$ObfuscatedScriptErrorHandled = AddErrorHandlerToObfuscatedScript $ObfuscatedScriptWithoutTryCatch
		$Deobfuscator = ($OverriddenFunctions -join "`r`n`r`n") + "`r`n`r`n" + $ObfuscatedScriptErrorHandled
	}
	else {
		$ObfuscatedScriptErrorHandled = AddErrorHandlerToObfuscatedScript $ObfuscatedScriptModified
		$Deobfuscator = ($OverriddenFunctions -join "`r`n`r`n") + "`r`n`r`n" + $ObfuscatedScriptErrorHandled
	}
 
	while(ContinueDeobfuscating $DeobfuscationProcess) {
		$ObfuscationLayers.Add($ObfuscatedScriptOriginal)
        $DeobfuscationOutput = DeobfuscateALayer $Deobfuscator
		if(!$DeobfuscationOutput) {
			$DeobfuscationProcess = "StopDeobfuscating"
		}
		else {
			if(ThereIsAnErrorDuringScriptExecution $DeobfuscationOutput) {
				$ErrorOutput = GetErrorInfoFromOutput $DeobfuscationOutput
				$ErrorType = $ErrorOutput | Select-Object -Index 0
				if(CommandIsObfuscated $ObfuscatedScriptModified) {
					$ObfuscatedScriptModified = DeobfuscateCommand $ObfuscatedScriptModified
					$ObfuscationLayers.Add($ObfuscatedScriptModified)
				}
				$ObfuscationLayersOutput = GetObfuscationLayers $ObfuscationLayers
				if($ErrorType -eq "executionError") {
					$ErrorMessage = $ErrorOutput | Select-Object -Index 1
					$Output = FormatExecutionErrorOutput $ObfuscationLayersOutput $ErrorMessage $ObfuscationLayers[-1]
					Write-Output $Output
				
					return
				}
				else {
					if(ThereIsNullOutputRedirection $ObfuscatedScriptModified) {
						$ObfuscatedScriptModified = RemoveOutputHiding $ObfuscatedScriptModified
					}
					$Urls = ExtractUrls $ObfuscatedScriptModified
					if($Urls) {
						$UrlsDown = @()
						$UrlsUp = @()
						ForEach($Url in $Urls) {
							if(IsUrlActive $Url) {
								$UrlsUp += $Url
							}
							else {
								$UrlsDown += $Url
							}
						}
						$Output = FormatConnectionErrorOutput $ObfuscationLayersOutput $UrlsDown $UrlsUp
						Write-Output $Output
					}
					else {
						$ErrorMessage = "URLs with bad syntax."
						$Output = FormatExecutionErrorOutput $ObfuscationLayersOutput $ErrorMessage $ObfuscationLayers[-1]
						Write-Output $Output
					}
				
					return
				}
			}
			else {
				if($DeobfuscationOutput -ne "") {
					$OutputArray = $DeobfuscationOutput.split("**", [System.StringSplitOptions]::RemoveEmptyEntries).Trim()
					$ObfuscatedScript = $OutputArray | Select-Object -Index 0
					$DeobfuscationProcess = $OutputArray | Select-Object -Index 1
					$ObfuscatedScriptOriginal = $ObfuscatedScript
					$ObfuscatedScriptModified = $ObfuscatedScript
					$ObfuscatedScriptModified = ScriptToOneLine $ObfuscatedScriptModified
					$ObfuscatedScriptModified = CleanScript $ObfuscatedScriptModified
					if(!(GoodSyntax $ObfuscatedScriptModified)) {
						$ObfuscationLayersOutput = GetObfuscationLayers $ObfuscationLayers
						$Output = FormatSyntaxErrorOutput $ObfuscatedScriptOriginal $ObfuscationLayersOutput
						Write-Output $Output
		
						return
					}
					if(UsesFileExplorer $ObfuscatedScriptModified) {
						$ObfuscationLayers.Add($ObfuscatedScriptOriginal)
						$ObfuscationLayersOutput = GetObfuscationLayers $ObfuscationLayers
						$Urls = ExtractUrls $ObfuscatedScriptModified
						if(IsUrlActive $Urls[0]) {
							$Output = FormatMalwareCodeOutput $ObfuscationLayersOutput $Urls[0]
							Write-Output $Output
						}
						else {
							$Output = FormatConnectionErrorOutput $ObfuscationLayersOutput $Urls[0] @()
							Write-Output $Output
						}
						
						return
					}
					if(ContainsSleepCommand $ObfuscatedScriptModified) {
						$ObfuscatedScriptModified = ReduceSleepCounter $ObfuscatedScriptModified
					}
					if(ThereIsNullOutputRedirection $ObfuscatedScriptModified) {
						$ObfuscatedScriptModified = RemoveOutputHiding $ObfuscatedScriptModified
					}
					if(ContainsEndlessLoopType1 $ObfuscatedScriptModified) {
						$ObfuscatedScriptModified = RemoveEndlessLoopType1 $ObfuscatedScriptModified
					}
					if(ContainsEndlessLoopType2 $ObfuscatedScriptModified) {
						$ObfuscatedScriptModified = RemoveEndlessLoopType2 $ObfuscatedScriptModified
					}
					if(TryCatchBlockExists $ObfuscatedScriptModified) {
						$ObfuscatedScriptWithoutTryCatch = RemoveTryCatchBlocks $ObfuscatedScriptModified
						$ObfuscatedScriptErrorHandled = AddErrorHandlerToObfuscatedScript $ObfuscatedScriptWithoutTryCatch
						$Deobfuscator = ($OverriddenFunctions -join "`r`n`r`n") + "`r`n`r`n" + ($ObfuscatedScriptErrorHandled -replace('"', '\"'))
					}
					else {
						$ObfuscatedScriptErrorHandled = AddErrorHandlerToObfuscatedScript $ObfuscatedScriptModified
						$Deobfuscator = ($OverriddenFunctions -join "`r`n`r`n") + "`r`n`r`n" + ($ObfuscatedScriptErrorHandled -replace('"', '\"'))
					}
				}
			}
		}
	}
	
	#Last Layer of offuscation
	$ObfuscatedScript = $ObfuscationLayers[-1]
	if(CommandIsObfuscated $ObfuscatedScript) {
		$ObfuscatedScript = DeobfuscateCommand $ObfuscatedScript
		$ObfuscationLayers.Add($ObfuscatedScript)
	}
	if(ThereIsNullOutputRedirection $ObfuscatedScript) {
		$ObfuscatedScript = RemoveOutputHiding $ObfuscatedScript
	}
	$ObfuscationLayersOutput = GetObfuscationLayers $ObfuscationLayers
	$Urls = ExtractUrls $ObfuscatedScript
	$UrlsDown = @()
	$UrlsUp = @()
	ForEach($Url in $Urls) {
		if(IsUrlActive $Url) {
			$UrlsUp += $Url
		}
		else {
			$UrlsDown += $Url
		}
	}
	if($Urls) {
		if($UrlsDown) {
			$Output = FormatConnectionErrorOutput $ObfuscationLayersOutput $UrlsDown $UrlsUp
			Write-Output $Output
		}
		else {
			$Output = FormatMalwareCodeOutput $ObfuscationLayersOutput $Urls[0]
			Write-Output $Output
		}
	}
	else {
		$Output = FormatNotDeobfuscatedOutput $ObfuscationLayersOutput
		Write-Output $Output
	}
	
	return
}