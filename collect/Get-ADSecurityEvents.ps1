[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$Hours = 24,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$eventIds = 1102, 4728, 4732, 4756, 4768, 4769
$startTime = (Get-Date).AddHours(-$Hours)
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $resolvedOutput
New-Item -ItemType Directory -Path $parent -Force | Out-Null

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $startTime; Id = $eventIds } |
    Select-Object TimeCreated, Id, MachineName, RecordId, UserId, Message |
    Export-Csv -NoTypeInformation -Encoding UTF8 $resolvedOutput

Write-Output "Exported selected AD security events to $resolvedOutput"
