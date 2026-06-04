# provision_token.py
import json
from core.shamir import serialize_share
from client.token import save_share

def main():
    # 1. Read the unencrypted share from token.json created by run.py
    with open("client/token.json", "r", encoding="utf-8") as f:
        token_data = json.load(f)

    # 2. Extract share coordinates
    x = token_data["share_x"]
    y = int(token_data["share_y"], 16) # JSON stores y as a hex string
    
    # 3. Serialize to bytes as expected by save_share
    share_bytes = serialize_share((x, y))
    
    # 4. Save it to ~/.hydra/token.bin with a passphrase of your choice
    # You can change "my-secure-passphrase" to whatever you want.
    save_share(
        share_bytes=share_bytes,
        share_index=3,
        node_id="client_token",
        passphrase="my-secure-passphrase"
    )

if __name__ == "__main__":
    main()
