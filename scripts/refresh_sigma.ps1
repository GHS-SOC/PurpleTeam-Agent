# Clone or update the SigmaHQ rule corpus into vendor/sigma.
#
# A shallow clone is enough -- we only ever read the working tree, never history.
# After this, rebuild the index:  python scripts/build_index.py

$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'vendor\sigma'

if (Test-Path (Join-Path $target '.git')) {
    Write-Output "Updating existing corpus at $target ..."
    git -C $target fetch --depth 1 origin master
    git -C $target reset --hard FETCH_HEAD
} else {
    Write-Output "Cloning SigmaHQ/sigma into $target ..."
    New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git $target
}

$count = (Get-ChildItem -Path $target -Filter '*.yml' -Recurse -File).Count
Write-Output ""
Write-Output "Corpus ready: $count YAML files."
Write-Output "Next: python scripts/build_index.py"
