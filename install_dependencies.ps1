# Installieren der Anforderungen aus der pyproject.toml
$ErrorActionPreference = "Stop"

pip install --upgrade pip
pip install --group default

Write-Output "Dependencies installed successfully."
# Installieren von cmake, wenn nicht in der gewünschten Version oder höher vorhanden
$cmakeVersion = "4.2.1"
try {
    $installedCmakeVersion = & cmake --version 2>$null | Select-String -Pattern "version (\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }
    if ($installedCmakeVersion) {
        Write-Output "Found cmake version: $installedCmakeVersion"
    } else {
        Write-Output "cmake not found."
        $installedCmakeVersion = $null
    }
} catch {
    Write-Output "cmake not found or not accessible."
    $installedCmakeVersion = $null
}

# Nach der cmake Installation, PATH aktualisieren
if ($installedCmakeVersion -notcontains "$cmakeVersion") {
    Write-Output "Installing cmake version $cmakeVersion..."
    $cmakeInstaller = "https://github.com/Kitware/CMake/releases/download/v$cmakeVersion/cmake-$cmakeVersion-windows-x86_64.msi"
    $cmakeInstallerPath = "$env:TEMP\cmake-installer.msi"
    Invoke-WebRequest -Uri $cmakeInstaller -OutFile $cmakeInstallerPath
    Start-Process msiexec.exe -ArgumentList "/i", $cmakeInstallerPath, "/norestart" -Wait
    Remove-Item $cmakeInstallerPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cmake installation failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Output "cmake installed successfully."

    # PATH neu laden aus der Registry
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

    # Alternativ: cmake direkt zum PATH hinzufügen
    $cmakePath = "C:\Program Files\CMake\bin"
    if (Test-Path $cmakePath) {
        $env:Path += ";$cmakePath"
    }

    winget install "WinLibs (POSIX threads, UCRT runtime)"
    Write-Output "WinLibs installed successfully."

    # PATH nochmal neu laden nach WinLibs Installation
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# check  againif cmake is now installed
$installedCmakeVersion = & cmake --version 2>$null
if ($installedCmakeVersion -contains "version $cmakeVersion") {
    Write-Error "cmake installation failed. cmake version $cmakeVersion not found."
    exit 1
}

# git clone --depth=1 https://github.com/open-quantum-safe/liboqs
$liboqsVersion = "0.14.0"
Write-Output "Downloading liboqs version $liboqsVersion..."
Invoke-WebRequest -Uri https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$liboqsVersion.zip -OutFile liboqs.zip
Expand-Archive -Path liboqs.zip -DestinationPath .
Remove-Item liboqs.zip
Rename-Item "liboqs-$liboqsVersion" "liboqs"


cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -G "MinGW Makefiles"
cmake --build liboqs/build --parallel 12 
cmake --build liboqs/build --target install 

# Set the OQS_INSTALL_PATH environment variable to the path where liboqs was installed
$env:OQS_INSTALL_PATH = "$pwd\liboqs\build"
[System.Environment]::SetEnvironmentVariable('OQS_INSTALL_PATH', "$pwd\liboqs\build", [System.EnvironmentVariableTarget]::User)

# Rename the liboqs.dll to oqs.dll if needed
# if (-Not (Test-Path "$env:OQS_INSTALL_PATH\bin\oqs.dll")) {
#     Rename-Item "$env:OQS_INSTALL_PATH\bin\liboqs.dll" "$env:OQS_INSTALL_PATH\bin\oqs.dll"
# }

# Klonen des Git-Repositorys
git clone --depth=1 -b fix-windows-dll-lookup https://github.com/open-quantum-safe/liboqs-python


# Wechseln in das geklonte Verzeichnis
cd liboqs-python

# Installieren des geklonten Repositorys
pip install .

# liboqs-python Verzeichnis verlassen
cd ..

# test if installation was successful
try {
    python -c "import oqs; print(f'Final OQS check: {oqs.oqs_version()}')"
} catch {
    Write-Error "liboqs-python installation failed."
    exit 1
}