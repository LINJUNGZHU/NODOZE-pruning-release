param(
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$database = "output\tc\cadets-e3-v2.db"
$config = "configs\tc_pruning_depimpact_poi.json"
$groundTruthSource = "ubc-provenance-ground-truth-ff65bc7\darpa\E3-CADETS"
$groundTruthOutput = "output\tc\ubc-cadets-e3\ubc-provenance-source"

# Do not trust the caller's PATH: PowerShell may resolve `python` from the base
# Conda environment even after this script is launched through another shell.
$condaCommand = Get-Command conda -ErrorAction SilentlyContinue
if ($null -eq $condaCommand) {
    throw "Conda was not found in PATH; cannot locate the graphenv environment."
}
$condaBase = (& conda info --base).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($condaBase)) {
    throw "Unable to obtain the Conda installation directory."
}
$pythonExe = Join-Path $condaBase "envs\graphenv\python.exe"
if (-not (Test-Path -LiteralPath $pythonExe)) {
    throw "graphenv Python was not found: $pythonExe"
}

& $pythonExe -c "import psutil; import tc_pruning"
if ($LASTEXITCODE -ne 0) {
    throw "graphenv is missing project dependencies; run: conda run -n graphenv pip install -r requirements.txt"
}
Write-Host "Using Python: $pythonExe"

if ($ValidateOnly) {
    Write-Host "Environment validation completed successfully."
    exit 0
}

# Rebuild evaluation labels from the original UBC provenance CSV files on every
# run. POI files remain independent inputs and are never generated from these
# labels, so the online search cannot use evaluation ground truth.
Write-Host "Rebuilding UBC provenance ground truth from: $groundTruthSource"
& $pythonExe -m tc_pruning.cli prepare-ubc-annotations `
    --db $database `
    --groundtruth-dir $groundTruthSource `
    --output-dir $groundTruthOutput `
    --scenario all
if ($LASTEXITCODE -ne 0) {
    throw "UBC ground-truth preparation failed with exit code $LASTEXITCODE"
}

foreach ($day in @("06", "12", "13")) {
    $poi = "poi\cadets-e3-ubc-$day-description-pois.json"
    # Keep the earlier description-POI result intact for reproducible comparison.
    $output = "output\tc\ubc-cadets-e3\cadets-e3-ubc-$day-e3-report-poi-results.json"

    Write-Host "[UBC$day] Starting DEPIMPACT-style POI experiment..."
    # Keep evaluation truth out of the online search/pruning process. The
    # protocol-v2 step below joins the frozen result with truth exactly once.
    & $pythonExe -m tc_pruning.cli experiment `
        --db $database `
        --poi-events $poi `
        --output $output `
        --config $config

    if ($LASTEXITCODE -ne 0) {
        throw "UBC$day failed with exit code $LASTEXITCODE"
    }
    Write-Host "[UBC$day] Completed: $output"
}

Write-Host "Generating evaluation protocol v2 reports without rerunning search..."
& $pythonExe scripts\generate_protocol_v2_reports.py
if ($LASTEXITCODE -ne 0) {
    throw "Protocol v2 report generation failed with exit code $LASTEXITCODE"
}
Write-Host "Protocol v2 report: output\tc\ubc-cadets-e3\protocol-v2\ubc-06-12-13-protocol-v2.md"
