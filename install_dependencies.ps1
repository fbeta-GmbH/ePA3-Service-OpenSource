
# Installieren der Anforderungen aus der requirements.txt Datei
pip install -r requirements.txt



# Installieren von cmake
if (-Not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Output "Installing cmake..."
    $cmakeInstaller = "https://github.com/Kitware/CMake/releases/download/v3.21.3/cmake-3.21.3-windows-x86_64.msi"
    $cmakeInstallerPath = "$env:TEMP\cmake-installer.msi"
    Invoke-WebRequest -Uri $cmakeInstaller -OutFile $cmakeInstallerPath
    Start-Process msiexec.exe -ArgumentList "/i", $cmakeInstallerPath, "/quiet", "/norestart" -Wait
    Remove-Item $cmakeInstallerPath
    Write-Output "cmake installed successfully."
} else {
    Write-Output "cmake is already installed."
}


git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE
cmake --build liboqs/build --parallel 12 
cmake --build liboqs/build --target install 

# Set the OQS_INSTALL_PATH environment variable to the path where liboqs was installed
$env:OQS_INSTALL_PATH = "$pwd\liboqs\build"
[System.Environment]::SetEnvironmentVariable('OQS_INSTALL_PATH', "$pwd\liboqs\build", [System.EnvironmentVariableTarget]::User)

# Rename the liboqs.dll to oqs.dll if needed
if (-Not (Test-Path "$env:OQS_INSTALL_PATH\bin\oqs.dll")) {
    Rename-Item "$env:OQS_INSTALL_PATH\bin\liboqs.dll" "$env:OQS_INSTALL_PATH\bin\oqs.dll"
}

# Klonen des Git-Repositorys
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python

# Wechseln in das geklonte Verzeichnis
cd liboqs-python

# Installieren des geklonten Repositorys
pip install .

# liboqs-python Verzeichnis verlassen
cd ..