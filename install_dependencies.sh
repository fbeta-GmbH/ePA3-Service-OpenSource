#!/bin/bash

# Install requirements from requirements.txt file
pip install -r requirements.txt

# Install cmake using Homebrew
if ! command -v cmake &> /dev/null; then
    echo "Installing cmake..."
    if ! command -v brew &> /dev/null; then
        echo "Error: Homebrew is not installed. Please install Homebrew first:"
        echo "/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    brew install cmake
    echo "cmake installed successfully."
else
    echo "cmake is already installed."
fi

# Clone liboqs repository
git clone --depth=1 https://github.com/open-quantum-safe/liboqs

# Build liboqs with local install prefix
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$PWD/liboqs/install"
cmake --build liboqs/build --parallel 12
cmake --build liboqs/build --target install

# Set the OQS_INSTALL_PATH environment variable
export OQS_INSTALL_PATH="$PWD/liboqs/install"
echo "export OQS_INSTALL_PATH=\"$PWD/liboqs/install\"" >> ~/.bash_profile
echo "export OQS_INSTALL_PATH=\"$PWD/liboqs/install\"" >> ~/.zshrc

# Check if liboqs library exists (different naming on macOS)
if [ ! -f "$OQS_INSTALL_PATH/lib/liboqs.dylib" ] && [ ! -f "$OQS_INSTALL_PATH/lib/liboqs.so" ]; then
    echo "Warning: liboqs library not found in expected location"
fi

# Clone liboqs-python repository
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python

# Change to the cloned directory
cd liboqs-python

# Install the cloned repository
pip install .

# Return to parent directory
cd ..

echo "Installation completed successfully."