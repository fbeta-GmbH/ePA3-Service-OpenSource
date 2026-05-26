Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Verwende aktuelle PATH-Variable
$machinePath = [System.Environment]::GetEnvironmentVariable('Path','Machine')
$userPath    = [System.Environment]::GetEnvironmentVariable('Path','User')
$env:Path    = "$machinePath;$userPath"

# Definiere Versionen und Pfade
$cmakeVersion  = '4.2.1'
$liboqsVersion = '0.14.0'
$venvPath     = '.venv'

# Paths
$root = $PWD
$dependencyPath = Join-Path $root 'dependencies'
if (-not (Test-Path $dependencyPath)) {
    New-Item -ItemType Directory -Path $dependencyPath | Out-Null
}

$cmakeDownloadPath   = Join-Path $dependencyPath 'cmake'
$cmakeInstallPath    = Join-Path $cmakeDownloadPath 'cmake\bin'

$liboqsDownloadPath  = Join-Path $dependencyPath "liboqs-$liboqsVersion"
$localLiboqsInstallPath = Join-Path $liboqsDownloadPath 'build'
$env:OQS_INSTALL_PATH = [System.Environment]::GetEnvironmentVariable('OQS_INSTALL_PATH', 'User')

$winlibsDownloadPath = Join-Path $dependencyPath 'winlibs'
$winlibsInstallPath  = Join-Path $winlibsDownloadPath 'mingw64\bin'

# Hilfsfunktionen
function Add-PathOnce([string]$path) {
    if ($path -and (Test-Path $path)) {
        $parts = $env:PATH -split ';'
        if (-not ($parts -contains $path)) { $env:PATH = "$path;" + $env:PATH }
    }
}

function Get-CMakeVersion {
    $cmd = Get-Command cmake -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    $m = (cmake --version | Select-String -Pattern 'version (\d+\.\d+\.\d+)')
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return $null
}

function Test-IsLibOqsVersionCorrect {
    param ([string]$pathToCheck)
    if (-not $pathToCheck -or -not (Test-Path $pathToCheck)) { return $false, $null }
    $installedOqsVersion = (($pathToCheck -split 'liboqs-')[-1] -split '[\\/]')[0]
    if (-not ($installedOqsVersion -match '^\d+\.\d+\.\d+$')) { return $false, $null }
    return ([version]$installedOqsVersion -eq [version]$liboqsVersion), $installedOqsVersion
}

function Download-ExtractZip {
    param (
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$ZipPath,
        [Parameter(Mandatory)] [string]$Destination
    )
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath
    Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
    Remove-Item $ZipPath
}

# --------- CMake ---------
Write-Output '---------- CMake ----------'
Add-PathOnce $cmakeInstallPath
$installedCmakeVersion = Get-CMakeVersion
if ($installedCmakeVersion -and ([version]$installedCmakeVersion -ge [version]$cmakeVersion)) {
    Write-Output "CMake version $installedCmakeVersion meets required $cmakeVersion."
} else {
    Write-Output "Installing CMake $cmakeVersion (current: '$installedCmakeVersion')."
    $cmakeZip = Join-Path $dependencyPath 'cmake.zip'
    Download-ExtractZip -Url "https://github.com/Kitware/CMake/releases/download/v$cmakeVersion/cmake-$cmakeVersion-windows-x86_64.zip" -ZipPath $cmakeZip -Destination $cmakeDownloadPath
    Rename-Item (Join-Path $cmakeDownloadPath "cmake-$cmakeVersion-windows-x86_64") (Join-Path $cmakeDownloadPath 'cmake')
    Add-PathOnce $cmakeInstallPath
    $installedCmakeVersion = Get-CMakeVersion
    if (-not $installedCmakeVersion -or ([version]$installedCmakeVersion -lt [version]$cmakeVersion)) {
        Write-Error "CMake installation failed or incorrect version installed. Current version: $installedCmakeVersion"
        exit 1
    }
    Write-Output 'CMake installation complete.'
}

# --------- GCC (WinLibs) ---------
Write-Output '---------- GCC (WinLibs) ----------'
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    # winget uninstall --id=BrechtSanders.WinLibs.POSIX.UCRT
    Write-Output 'Installing WinLibs (POSIX threads, UCRT runtime) via winget...'
    winget install --id=BrechtSanders.WinLibs.POSIX.UCRT --installer-type PORTABLE --scope user --no-upgrade
    # Add winlibs to PATH
    $env:Path = "$([System.Environment]::GetEnvironmentVariable('Path','User'));$env:Path"

    Write-Output ("WinLibs installation finished: ")
    winget list --id=BrechtSanders.WinLibs.POSIX.UCRT -e
} else {
    Add-PathOnce $winlibsInstallPath
    Write-Output 'GCC is already installed. Skipping WinLibs installation.'
}
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Error 'GCC installation failed.'
    exit 1
}

# --------- liboqs ---------
Write-Output '---------- liboqs ----------'
$liboqsCorrectVersion, $installedLibOqsVersion = Test-IsLibOqsVersionCorrect $env:OQS_INSTALL_PATH
if (-not $liboqsCorrectVersion) {
    $liboqsCorrectVersion, $installedLibOqsVersion = Test-IsLibOqsVersionCorrect $localLiboqsInstallPath
    if ($liboqsCorrectVersion) {
        [System.Environment]::SetEnvironmentVariable('OQS_INSTALL_PATH', $localLiboqsInstallPath, 'User')
        $env:OQS_INSTALL_PATH = $localLiboqsInstallPath
    }
}

if (-not $liboqsCorrectVersion) {
    Write-Output "liboqs version $liboqsVersion not found. Installing..."
    $liboqsZip = Join-Path $dependencyPath 'liboqs.zip'
    Download-ExtractZip -Url "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$liboqsVersion.zip" -ZipPath $liboqsZip -Destination $dependencyPath

    cmake -S $liboqsDownloadPath -B $localLiboqsInstallPath -DBUILD_SHARED_LIBS=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -G "MinGW Makefiles"
    cmake --build $localLiboqsInstallPath --parallel 12
    cmake --build $localLiboqsInstallPath --target install

    $env:OQS_INSTALL_PATH = $localLiboqsInstallPath
    [System.Environment]::SetEnvironmentVariable('OQS_INSTALL_PATH', $localLiboqsInstallPath, 'User')

    if (-Not (Test-Path (Join-Path $env:OQS_INSTALL_PATH 'bin\oqs.dll')) -and (Test-Path (Join-Path $env:OQS_INSTALL_PATH 'bin\liboqs.dll'))) {
        Rename-Item (Join-Path $env:OQS_INSTALL_PATH 'bin\liboqs.dll') (Join-Path $env:OQS_INSTALL_PATH 'bin\oqs.dll')
    }
    Write-Output 'liboqs installation finished.'
}

$liboqsCorrectVersion, $installedLibOqsVersion = Test-IsLibOqsVersionCorrect $env:OQS_INSTALL_PATH
if (-not $liboqsCorrectVersion) {
    Write-Error "liboqs installation failed or incorrect version installed. Current version: '$installedLibOqsVersion', expected version: '$liboqsVersion'"
    exit 1
} else {
    Write-Output "liboqs version $liboqsVersion found at $env:OQS_INSTALL_PATH."
}

# -------- Python dependencies ---------
Write-Output '---------- Python environment ----------'
if (-not (Test-Path $venvPath)) {
    Write-Output 'Creating virtual environment...'
    python -m venv $venvPath
}
. $venvPath\Scripts\activate
python -m pip install --upgrade pip
python -m pip install --group default

Write-Output 'Dependencies installed successfully.'

try {
    python -c "import oqs; print(f'Final OQS check: {oqs.oqs_version()}')"
    python -c "import oqs; print(f'oqs-version: {oqs.oqs_version()}, oqs-python-version: {oqs.oqs_python_version()}')"
} catch {
    Write-Error 'liboqs-python installation failed.'
    exit 1
}