import sys
import time

import requests

attester_host = sys.argv[1]
nonce_hex = sys.argv[2]

for attempt in range(5):
    try:
        resp = requests.post(
            f"http://{attester_host}:5000/sign",
            json={"nonce": nonce_hex},
            timeout=5,
        )
        print(resp.text)
        break
    except requests.RequestException:
        if attempt < 4:
            time.sleep(1)
        else:
            raise
