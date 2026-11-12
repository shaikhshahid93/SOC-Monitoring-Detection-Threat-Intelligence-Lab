import getpass
import keyring
import sys

SERVICE = "SOC-Lab-Automation"

print("SOC Lab - Secure Credential Setup")

username = input("Splunk username [admin]: ").strip() or "admin"
splunk_password = getpass.getpass("Splunk password: ")
vt_api_key = getpass.getpass("VirusTotal API key: ")

if not splunk_password or not vt_api_key:
    print("ERROR: Credentials cannot be empty.")
    sys.exit(1)

try:
    keyring.set_password(SERVICE, "SPLUNK_USERNAME", username)
    keyring.set_password(SERVICE, "SPLUNK_PASSWORD", splunk_password)
    keyring.set_password(SERVICE, "VT_API_KEY", vt_api_key)

    # Verify that credentials can be retrieved.
    checks = [
        keyring.get_password(SERVICE, "SPLUNK_USERNAME"),
        keyring.get_password(SERVICE, "SPLUNK_PASSWORD"),
        keyring.get_password(SERVICE, "VT_API_KEY"),
    ]

    if not all(checks):
        raise RuntimeError("Credential verification failed.")

    print("\n[SUCCESS] Credentials saved and verified.")
    print("Storage: Windows Credential Manager")

except Exception as error:
    print(f"\n[ERROR] Could not save credentials: {error}")
    sys.exit(1)
