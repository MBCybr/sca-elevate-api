import os
import json
import configparser
import requests
import sys
import time

from ark_sdk_python.auth import ArkISPAuth
from ark_sdk_python.models.ark_profile import ArkProfile
from ark_sdk_python.models.ark_exceptions import ArkAuthException

API_BASE_URL = "https://<yoursubdomain>.sca.cyberark.cloud/api"

def flush_stdin():
    if sys.platform == "win32":
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getch()
    else:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)

def update_aws_credentials(profile_name, access_key, secret_key, session_token):
    aws_credentials_path = os.path.expanduser('~/.aws/credentials')
    config = configparser.ConfigParser()
    config.read(aws_credentials_path)

    if profile_name not in config:
        config.add_section(profile_name)

    config[profile_name]['aws_access_key_id'] = access_key
    config[profile_name]['aws_secret_access_key'] = secret_key
    config[profile_name]['aws_session_token'] = session_token

    with open(aws_credentials_path, 'w') as configfile:
        config.write(configfile)

    print(f"AWS credentials for profile '{profile_name}' updated successfully.")

def load_profile_from_file(profile_name):
    profiles_dir = os.path.expandvars(r"%USERPROFILE%\.ark_profiles")
    profile_path = os.path.join(profiles_dir, profile_name)
    if not os.path.isfile(profile_path):
        raise FileNotFoundError(f"Profile file not found: {profile_path}")
    with open(profile_path, "r") as f:
        profile_json = json.load(f)
    return ArkProfile.model_validate(profile_json)

def authenticate_with_profile(profile_name):
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
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()

def elevate_access(body, headers):
    url = f"{API_BASE_URL}/access/elevate"
    resp = requests.post(url, headers=headers, json=body)
    resp.raise_for_status()
    return resp.json()

def main():
    profile_name = input("Enter your saved profile name (leave blank for 'default'): ").strip() or "default"
    bearer_token = authenticate_with_profile(profile_name)
    if not bearer_token:
        return

    # Pause and flush right after auth to avoid input freeze
    time.sleep(3)
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

    print(f"Select a role to elevate access for {csp}:")
    for idx, role_info in enumerate(roles, start=1):
        role = role_info.get("roleInfo", {})
        print(f"{idx}. Workspace Name: {role_info.get('workspaceName')}, Role Name: {role.get('name')}")

    role_choice = input(f"Enter choice (1-{len(roles)}): ").strip()
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

    print(f"Elevate access request sent successfully for role '{role.get('name')}' in workspace '{selected.get('workspaceName')}'.")
    
    elevate_response = elevate_access(body, headers)

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