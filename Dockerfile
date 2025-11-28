# Use Debian-based image for better liboqs support
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    cmake \
    git \
    libssl-dev \
    ca-certificates \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs
COPY liboqs/ ./liboqs/
RUN cd liboqs && \
    mkdir -p build && \
    cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        .. && \
    ninja && \
    ninja install && \
    ldconfig

# Install liboqs-python
COPY liboqs-python/ ./liboqs-python/
RUN cd liboqs-python && \
    pip install --no-cache-dir .

# Now install application dependencies
WORKDIR /app

# Install PDM
RUN pip install --no-cache-dir pdm

# Copy dependency files
COPY pyproject.toml pdm.lock ./

# Configure PDM to use pep582 (__pypackages__)
ENV PDM_USE_VENV=false

# Install dependencies
RUN pdm install --prod --no-lock --no-editable

# Copy liboqs-python oqs package to __pypackages__ to override the conflicting oqs package
RUN rm -rf /app/__pypackages__/3.13/lib/oqs && \
    cp -r /usr/local/lib/python3.13/site-packages/oqs /app/__pypackages__/3.13/lib/

# Runtime stage
FROM python:3.13-slim

WORKDIR /app

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs library from builder
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Update library cache
RUN ldconfig

# Copy Python packages from builder (includes oqs from liboqs-python)
COPY --from=builder /app/__pypackages__/3.13 /app/__pypackages__/3.13

# Copy application code
COPY app/ ./app/

# Set Python path to use __pypackages__
ENV PYTHONPATH=/app/__pypackages__/3.13/lib
ENV PATH="/app/__pypackages__/3.13/bin:$PATH"
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
