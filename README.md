# ATLAS 

**ATLAS** is a guided vulnerability assessment framework designed for educational purposes and security testing of Web and IoT applications. It combines reconnaissance, automated checks, and interactive workflows.

![ATLAS Banner](https://img.shields.io/badge/ATLAS-Security%20Framework-blue?style=for-the-badge)

## Key Features

*   **Reconnaissance**: Automated Nmap integration for port scanning and service detection.
*   **Guided Workflows**: Interactive demo mode for learning vulnerability exploitation.
*   **Automated Checks**: Modular engine for SQL Injection, XSS, Directory Traversal, and more.
*   **Web UI**: Modern, dark-themed dashboard for managing scans and reports.
*   **Preset Targets**: Pre-configured support for **VulnBank** (Web) and **IoTGoat** (IoT).
*   **Reporting**: Generate HTML & JSON assessment reports.

## Installation

1.  **Prerequisites**:
    *   Python 3.8+
    *   [Nmap](https://nmap.org/download.html) installed and in your system PATH.

2.  **Clone & Install**:
    ```bash
    git clone https://github.com/your-repo/atlas.git
    cd atlas
    pip install -r requirements.txt
    ```

## Usage

### 1. Web Interface (Recommended)
Start the API server and Web UI:
```bash
python -m uvicorn api.main:app --reload --port 8000
```
Open **http://localhost:8000** in your browser.

*   **Dashboard**: View scan history.
*   **New Scan**: Run a scan against any target URL/IP.
*   **Demo Targets**: Launch presets like VulnBank or IoTGoat with one click.
*   **Reports**: View, download, and delete past reports.

### 2. CLI Interface
Complete command-line control for automation.

**Start a Scan:**
```bash
python -m cli.main scan http://localhost:3000
```

**Demo Mode (Guided Testing):**
```bash
python -m cli.main demo              # Interactive selection
python -m cli.main demo vulnbank     # Start VulnBank demo
python -m cli.main demo iotgoat      # Start IoTGoat demo
```

**List Scans & Presets:**
```bash
python -m cli.main list
python -m cli.main presets
```

## Project Structure

```
atlas/
├── api/          # FastAPI backend routes & schemas
├── atlas/        # Core engine, checks, and logic
│   ├── checks/   # Vulnerability check modules
│   ├── core/     # State management & orchestration
│   └── recon/    # Nmap scanner integration
├── cli/          # Typer-based command line interface
├── web/          # HTML/CSS/JS frontend
└── data/         # SQLite DB and reports storage
```

