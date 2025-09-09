import os
import sys
import time
import json
import configparser
from typing import Optional

import requests
from dotenv import load_dotenv

from ark_sdk_python.auth import ArkISPAuth
from ark_sdk_python.models.ark_profile import ArkProfile
from ark_sdk_python.models.ark_exceptions import ArkAuthException

# Load variables from .env file into environment
load_dotenv()

# --- Config ---
API_BASE_URL = os.getenv("CYBERARK_API_BASE_URL")
if not (API_BASE_URL and API_BASE_URL.startswith("https://") and API_BASE_URL.rstrip("/").endswith("/api")):
    raise SystemExit(
        "Set CYBERARK_API_BASE_URL (expected format: https://<subdomain>.sca.cyberark.cloud/api)"
    )


def flush_stdin():
    if sys.platform == "win32":
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getch()
    else:
        try:
            import termios
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass

def update_aws_credentials(profile_name, access_key, secret_key, session_token):
    aws_credentials_path = os.path.expanduser('~/.aws/credentials')
    os.makedirs(os.path.dirname(aws_credentials_path), exist_ok=True)

    config = configparser.ConfigParser()
    if os.path.exists(aws_credentials_path):
        config.read(aws_credentials_path)

    if profile_name not in config:
        config.add_section(profile_name)

    config[profile_name]['aws_access_key_id'] = access_key
    config[profile_name]['aws_secret_access_key'] = secret_key
    config[profile_name]['aws_session_token'] = session_token

    with open(aws_credentials_path, 'w') as configfile:
        config.write(configfile)

    print(f"✓ AWS credentials for profile '{profile_name}' updated.")

def load_profile_from_file(profile_name) -> ArkProfile:
    base = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    profiles_dir = os.path.join(base, ".ark_profiles")
    profile_path = os.path.join(profiles_dir, profile_name)
    if not os.path.isfile(profile_path):
        raise FileNotFoundError(f"Profile file not found: {profile_path}")
    with open(profile_path, "r") as f:
        profile_json = json.load(f)
    return ArkProfile.model_validate(profile_json)

def authenticate_with_profile(profile_name) -> Optional[str]:
    profile = load_profile_from_file(profile_name)
    auth = ArkISPAuth()
    try:
        token = auth.authenticate(profile=profile)
        print(f"✓ Authentication successful using profile '{profile_name}'")
        return token.token.get_secret_value()
    except ArkAuthException as e:
        print(f"✗ Authentication failed: {e}")
        return None

def get_roles(csp, headers):
    url = f"{API_BASE_URL}/access/{csp}/eligibility"
    params = {"limit": 50}  # Increase this to get more roles in one call
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

def elevate_access(body, headers):
    url = f"{API_BASE_URL}/access/elevate"
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()

def main():
    profile_name = input("Enter your saved profile name (leave blank for 'default'): ").strip() or "default"
    bearer_token = authenticate_with_profile(profile_name)
    if not bearer_token:
        return

    # Pause and flush right after auth to avoid input freeze
    time.sleep(1)
    flush_stdin()

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }

    providers = ["AWS", "AZURE", "GCP"]
    print("Select Cloud Provider:")
    for idx, p in enumerate(providers, start=1):
        print(f"{idx}. {p}")

    choice = input(f"Enter choice (1-{len(providers)}): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(providers)):
        print("Invalid choice.")
        return

    csp = providers[int(choice) - 1]
    data = get_roles(csp, headers)
    roles = data.get("response", [])

    if not roles:
        print("No eligible roles found.")
        return

    # Always prompt, even if only one role
    print(f"Select a role to elevate access for {csp}:")
    for idx, role_info in enumerate(roles, start=1):
        role = role_info.get("roleInfo", {})
        print(f"{idx}. Workspace Name: {role_info.get('workspaceName')}, Role Name: {role.get('name')}")

    prompt = f"Enter choice (1-{len(roles)}): " if len(roles) > 1 else "Enter choice (1): "
    role_choice = input(prompt).strip()
    if not role_choice.isdigit() or not (1 <= int(role_choice) <= len(roles)):
        print("Invalid choice.")
        return

    selected = roles[int(role_choice) - 1]
    role = selected.get("roleInfo", {})

    body = {
        "organizationId": selected.get("organizationId"),
        "csp": csp,
        "targets": [
            {
                "workspaceId": selected.get("workspaceId"),
                "roleid": role.get("id"),
                "roleName": role.get("name")
            }
        ]
    }

    elevate_response = elevate_access(body, headers)
    print(f"✓ Elevate access request sent for role '{role.get('name')}' in workspace '{selected.get('workspaceName')}'.")

    results = elevate_response.get("response", {}).get("results", [])
    credentials = {}

    if results and "accessCredentials" in results[0]:
        creds_json_str = results[0].get("accessCredentials")
        if creds_json_str:
            try:
                credentials = json.loads(creds_json_str)
            except json.JSONDecodeError as e:
                print(f"Failed to parse accessCredentials JSON: {e}")
        else:
            print("Access credentials were present but empty.")
    else:
        if csp == "AWS":
            print("No AWS credentials returned in elevation response (Most likely IDC account).")
        else:
            print(f"No access credentials returned (expected for {csp}).")

    aws_access_key = credentials.get("aws_access_key")
    aws_secret_access_key = credentials.get("aws_secret_access_key")
    aws_session_token = credentials.get("aws_session_token")

    if aws_access_key and aws_secret_access_key and aws_session_token:
        aws_profile_name = "cyberark_elevated"
        update_aws_credentials(aws_profile_name, aws_access_key, aws_secret_access_key, aws_session_token)

if __name__ == "__main__":
    main()
