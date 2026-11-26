# Run at the repository root on the reorg/clean-layout branch.
# Pure path restructure: git mv only, no file contents are changed.
# Binaries and history are preserved (git tracks the moves as renames).

$ErrorActionPreference = 'Stop'

function Move-IfPresent {
    param([string]$Source, [string]$Dest)
    if (Test-Path $Source) {
        $parent = Split-Path $Dest -Parent
        if ($parent -and -not (Test-Path $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        git mv "$Source" "$Dest"
        Write-Host "moved  $Source -> $Dest"
    } else {
        Write-Host "skip   $Source (not present)"
    }
}

Move-IfPresent '2_src_port'   'overlay'
Move-IfPresent '3_src_driver' 'driver'
Move-IfPresent '5_src_loader' 'launcher'
Move-IfPresent '4_src_mapper' 'mapper-analysis'
Move-IfPresent 'offsets'      'data/offsets'
Move-IfPresent 'tools'        'scripts'
Move-IfPresent '1_run'        'artifacts/run'
Move-IfPresent 'dist'         'artifacts/dist'
Move-IfPresent 'BUILD.md'        'docs/BUILD.md'
Move-IfPresent 'SINGLE_BUILD.md' 'docs/SINGLE_BUILD.md'

Write-Host ''
Write-Host 'Moves staged. Next steps:'
Write-Host '  1. git status      (review the rename detection)'
Write-Host '  2. Rebuild each component to catch hardcoded old paths'
Write-Host '  3. git commit -m "Restructure: apply clean layout"'
Write-Host '  4. git push origin reorg/clean-layout and open a PR'
Write-Host 'You can delete this script and REORGANIZE.md after merging.'
