<#
.SYNOPSIS
  Analyzes a Windows memory dump using cdb.exe and outputs a JSON summary.

.PARAMETER DumpFile
  Path to the .dmp file to analyze.

.PARAMETER CdbPath
  (Optional) Full path to cdb.exe. Defaults to 'cdb.exe' assuming it's on the PATH.

.EXAMPLE
  .\Analyze-Dump.ps1 -DumpFile "C:\dumps\memory.dmp"
#>

Param(
    [Parameter(Mandatory)]
    [string]$DumpFile,

    [string]$CdbPath = "cdb.exe"
)

function Get-DumpAnalysis {
    param(
        [string]$DumpFilePath,
        [string]$Debugger
    )

    if (-not (Test-Path $DumpFilePath)) {
        Throw "Dump file not found: $DumpFilePath"
    }

    # Run the debugger and capture output
    $analysis = & $Debugger -z $DumpFilePath -c "!analyze -v; q" 2>&1

    # Prepare the result object
    $result = [PSCustomObject]@{
        DumpFile           = $DumpFilePath
        BugCheckCode       = $null
        BugCheckParameters = @()
        CausedBy           = $null
        ModulesLoaded      = 0
        StackTrace         = @()
    }

    foreach ($line in $analysis) {
        if ($line -match "^BugCheck\s+Code:\s+([0-9A-Fx]+)\s*\((.*)\)") {
            $result.BugCheckCode = $Matches[1]
            if ($Matches[2]) { $result.CausedBy = $Matches[2].Trim() }
        }
        elseif ($line -match "BugCheckParameter(\d+)\s+=\s+(0x[0-9A-Fa-f]+)") {
            $idx = [int]$Matches[1] - 1
            $result.BugCheckParameters[$idx] = $Matches[2]
        }
        elseif ($line -match "^Probably caused by\s+:\s+(.*)$") {
            $result.CausedBy = $Matches[1].Trim()
        }
        elseif ($line -match "^Loaded\s+Module\s+Name\s+Count:\s+(\d+)") {
            $result.ModulesLoaded = [int]$Matches[1]
        }
        elseif ($line -match "^\s+[0-9A-Fa-f]+\s+([\w\.\+\!\?`_]+)") {
            $result.StackTrace += $Matches[1]
        }
    }

    return $result
}

# Run analysis and output JSON
$summary = Get-DumpAnalysis -DumpFilePath $DumpFile -Debugger $CdbPath
$summary | ConvertTo-Json -Depth 4
