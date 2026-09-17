param(
    [Parameter(Position=0)]
    [string]$Command = "list",

    [Parameter(
        Position=1,
        ValueFromRemainingArguments=$true
    )]
    [string[]]$Rest
)

$Script = Join-Path $PSScriptRoot "claude_sync.py"

$PyLauncher = Get-Command py -ErrorAction SilentlyContinue

if ($PyLauncher) {
    & py -3 $Script $Command @Rest
    exit $LASTEXITCODE
}

$Python = Get-Command python -ErrorAction SilentlyContinue

if ($Python) {
    & python $Script $Command @Rest
    exit $LASTEXITCODE
}

Write-Error "Python 3 was not found."
Write-Host "Install Python 3 and make sure 'python' or 'py' is in PATH."
exit 1