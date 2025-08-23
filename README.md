# SCA Elevate CLI

A Python CLI for authenticating with CyberArk Identity Security Platform (ISP) and elevating access to cloud roles (AWS, Azure, GCP).

## Requirements

- Python 3.10+
- Dependencies:
  - `requests`
  - `ark-sdk-python`
  - *(optional)* `python-dotenv` if you want to use a `.env` file

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Configuration

You must provide your tenant API base URL in the format:

```
https://<subdomain>.sca.cyberark.cloud/api
```

### Option 1: Environment Variable (recommended)

**Windows PowerShell (session only):**

```powershell
$env:CYBERARK_API_BASE_URL="https://<subdomain>.sca.cyberark.cloud/api"
```

**Windows PowerShell (persistent):**

```powershell
setx CYBERARK_API_BASE_URL "https://<subdomain>.sca.cyberark.cloud/api"
```

**macOS/Linux (bash/zsh):**

```bash
export CYBERARK_API_BASE_URL="https://<subdomain>.sca.cyberark.cloud/api"
```

### Option 2: `.env` File

If you install `python-dotenv`, you can create a `.env` file in your repo:

```
CYBERARK_API_BASE_URL=https://<subdomain>.sca.cyberark.cloud/api
```

Add `.env` to `.gitignore` so the real value never gets committed.

### Quick start with `.env.example`

This repo includes a `.env.example` file as a template.  
To use it:

- Copy it to `.env`  
  ```bash
  cp .env.example .env   # Linux/macOS
  copy .env.example .env # Windows PowerShell
  ```
- Edit `.env` and set your tenant URL (replace `<subdomain>`).

---

## Usage

Run the CLI:

```bash
python elevate.py
```

You will be prompted for:
1. Your saved Ark profile name (defaults to `default` if left blank).
2. A cloud provider (AWS, Azure, or GCP).
3. A role to elevate into.

If AWS credentials are returned, they are written into `~/.aws/credentials` under the profile name `cyberark_elevated`.

---

## Notes

- The script will **never auto-select** a role; you will always be prompted.
- For AWS, credentials are stored locally; for Azure/GCP, you may need to use other tools with the returned information.
- If you cancel (`Ctrl+C`), the script exits cleanly without changes.
