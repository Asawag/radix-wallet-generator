from radix_engine_toolkit import *
from typing import Tuple
import secrets
from pathlib import Path
import json

def new_account(network_id: int) -> Tuple[PrivateKey, PublicKey, Address, bytes]:
    """
    Creates a new random Ed25519 private key and then derives the public key and
    the account address associated with it
    """
    private_key_bytes: bytes = secrets.randbits(256).to_bytes(32, 'big')
    private_key: PrivateKey = PrivateKey.new_ed25519(private_key_bytes)
    public_key: PublicKey = private_key.public_key()
    account: Address = derive_virtual_account_address_from_public_key(
        public_key, network_id
    )
    return (private_key, public_key, account, private_key_bytes)

# A constant of the id of the network
NETWORK_ID: int = 0x01 # Example network ID, replace with the actual network ID you're targeting 0x02 = TDX

# Path to the JSON file to store accounts
json_file_path = Path("accounts.json")

# Check if JSON file exists, if not, initialize an empty list
if json_file_path.exists():
    with open(json_file_path, 'r') as file:
        accounts = json.load(file)
else:
    accounts = []

# Ask the user how many wallets they need
wallet_count = int(input("How many wallets do you need? "))

# Generate the wallets
for _ in range(wallet_count):
    (private_key, public_key, account, private_key_bytes) = new_account(NETWORK_ID)
    account_number = len(accounts) + 1

    # Save account details to JSON
    account_details = {
        "account_number": account_number,
        "account_address": account.as_str(),
        "public_key": private_key.public_key_bytes().hex(),
        "private_key": private_key_bytes.hex()
    }
    accounts.append(account_details)

    # Print wallet details
    print(f"Account Address: {account.as_str()}")
    print(f"Public Key: {private_key.public_key_bytes().hex()}")
    print(f"Private Key: {private_key_bytes.hex()}")

# Write updated accounts list to JSON file
with open(json_file_path, 'w') as file:
    json.dump(accounts, file, indent=4)
