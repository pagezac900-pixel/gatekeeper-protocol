"""Minimal example: propose → authorize → verify (15 lines of user code)."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from gatekeeper import GatekeeperSession

payload = b"kubectl rollout restart deployment/api --namespace=production"
session = GatekeeperSession()

# 1. AI proposes an action
action = session.propose("Restart production API pods", payload)

# 2. Human reviews and types AUTHORIZE (or anything else to deny)
token = session.request_authorization(action)

# 3. Only execute if authorised
if token:
    print("Action authorised — executing.")
    assert session.verify(token, payload), "Token failed verification!"
    print(f"Verified. Approved by ...{token['approver_pubkey'][-8:]} at {token['approved_at']}")
else:
    print("Action denied — nothing executed.")
    sys.exit(1)
