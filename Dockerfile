# Dockerfile for litefuzz
# Multi-platform fuzzer for poking at userland binaries, clients and servers
# Based on Ubuntu 24.04
#
# Usage:
#   Build: docker build -t litefuzz:latest .
#   
#   Example with example input (no input mount needed):
#     mkdir -p crashes
#     docker run --rm \
#       -v $(pwd)/crashes:/tmp/crashes \
#       litefuzz:latest \
#       python3 litefuzz.py -l -c "latex2rtf FUZZ" -i /litefuzz/input/tex -o /tmp/crashes -n 1000
#   
#   Example with your own input files:
#     mkdir -p input/tex crashes
#     # Add your test files to input/tex/ first
#     docker run --rm \
#       -v $(pwd)/input:/litefuzz/input \
#       -v $(pwd)/crashes:/tmp/crashes \
#       litefuzz:latest \
#       python3 litefuzz.py -l -c "latex2rtf FUZZ" -i /litefuzz/input/tex -o /tmp/crashes -n 1000
#
# Note: Example input is available at /litefuzz/input/tex
#       This Dockerfile works from within repo or standalone (clones from GitHub)

FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /litefuzz

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gnome-devel \
    gcc \
    gdb \
    libgtk-3-dev \
    python3 \
    python3-dev \
    python3-pip \
    python3-tk \
    python3-venv \
    electric-fence \
    git \
    latex2rtf \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3 as default python
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# Copy litefuzz repository if building from within repo, otherwise clone it
# This allows building both from within the repo (faster, uses local changes) 
# or from anywhere (standalone, gets latest from GitHub)
COPY . /litefuzz-temp/
RUN if [ -f "/litefuzz-temp/litefuzz.py" ]; then \
        echo "Using local repository files (building from within repo)"; \
        mv /litefuzz-temp /litefuzz; \
    else \
        echo "Cloning repository from GitHub (building standalone)"; \
        rm -rf /litefuzz-temp; \
        git clone https://github.com/sec-tools/litefuzz.git /litefuzz && \
        cd /litefuzz && \
        git checkout main || git checkout master || true; \
    fi

# Create virtual environment (avoids PEP 668 --break-system-packages requirement)
RUN python3 -m venv /opt/litefuzz

# Activate venv in PATH
ENV PATH="/opt/litefuzz/bin:$PATH"

# Install exploitable for GDB
RUN git clone https://github.com/jfoote/exploitable /tmp/exploitable && \
    cd /tmp/exploitable && \
    /opt/litefuzz/bin/pip install . && \
    rm -rf /tmp/exploitable

# Configure GDB to autoload exploitable
RUN EXPLOITABLE_PY=$(find /opt/litefuzz -name exploitable.py 2>/dev/null | head -1) && \
    if [ -n "$EXPLOITABLE_PY" ]; then \
        echo "source $EXPLOITABLE_PY" >> /root/.gdbinit; \
    fi

# Install Python dependencies in venv
RUN /opt/litefuzz/bin/pip install --no-cache-dir -r requirements/requirements-py3.txt || true && \
    (/opt/litefuzz/bin/pip install --no-cache-dir pyradamsa || echo "Note: pyradamsa not available on PyPI, skipping (optional Linux-only mutator)")

# Build test crash apps (if test directory exists)
RUN if [ -d "test/linux" ]; then \
        cd test/linux && make && cd /litefuzz; \
    else \
        echo "Note: test/linux directory not found, skipping test app build"; \
    fi

# Make litefuzz.py executable
RUN chmod +x litefuzz.py

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONWARNINGS=ignore::SyntaxWarning

# Default command - show help (using venv python)
CMD ["/opt/litefuzz/bin/python3", "litefuzz.py", "--help"]

