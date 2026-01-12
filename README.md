# CLI Antivirus, built with VirusTotal

Antivirus is a command-line tool built to check files for malware by leveraging the [VirusTotal API](https://www.virustotal.com/).

## Features

- Scan files for viruses and malware
- Get scan results from VirusTotal
- Store history of your scans
- Api key is stored ecnrypted using AES ( need to enter PIN when key is accessed)
- Simple CLI interface

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/cli-antivirus.git
cd cli-antivirus
```

2. Install dependencies (if any, e.g., Python example):

```bash
pip install -r requirements.txt
```

3. Set your virus total api key

```bash
python -m src set_api_key <your key>
```

## Usage

Basic usage:

```bash
python -m src /path/to/file
```

Options:

- `<file>` — scan file
- `set_api_key` `<virus total api key>` - store api key in encrypted way, in file in work directory
- `history` - shows all history of prevous scans
- `--help` — show help message

Example:

```bash
python antivirus.py scan example.exe --verbose
```

## How it works

1. The CLI tool reads the file to be scanned.
2. It uploads the file hash or the file itself to VirusTotal.
3. VirusTotal responds with a scan report.
4. The CLI displays the result in a human-readable format.
