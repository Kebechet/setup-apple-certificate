#!/usr/bin/env bash
set -euo pipefail

# Apple Distribution certificate management via App Store Connect API.
# Uses a persistent private key and reuses existing valid certificates.
# Only creates a new certificate when no valid matching one exists.
#
# Required environment variables:
#   APP_STORE_CONNECT_API_KEY_ID             - App Store Connect API Key ID
#   APP_STORE_CONNECT_API_ISSUER_ID          - App Store Connect API Issuer ID
#   APP_STORE_CONNECT_API_KEY_CONTENT_BASE64 - API key (.p8) content, base64-encoded
#   DISTRIBUTION_PRIVATE_KEY_BASE64          - Persistent RSA private key, base64-encoded
#   BUNDLE_IDENTIFIER                        - App bundle identifier (e.g. com.satisfit.app)
#   GITHUB_OUTPUT                            - GitHub Actions output file path
#
# Optional environment variables:
#   CERT_RENEWAL_BUFFER_DAYS                 - Days before expiry to trigger renewal (default: 30)
#
# Outputs (via $GITHUB_OUTPUT):
#   P12_DISTRIBUTION_CERTIFICATE_BASE64 - P12 certificate, base64-encoded
#   P12_DISTRIBUTION_PASSWORD           - random password for the P12
#   KEYCHAIN_PASSWORD                   - random keychain password
#   PROVISIONING_PROFILE_NAME           - name of the provisioning profile

WORK_DIR=$(mktemp -d)
export WORK_DIR
trap 'rm -rf "$WORK_DIR"' EXIT

API_BASE_URL="https://api.appstoreconnect.apple.com/v1"
CERT_RENEWAL_BUFFER_DAYS="${CERT_RENEWAL_BUFFER_DAYS:-30}"
export CERT_RENEWAL_BUFFER_DAYS

# ─── JWT Generation ──────────────────────────────────────────────────────────

generate_jwt() {
    local api_key_path="$WORK_DIR/api_key.p8"
    echo "$APP_STORE_CONNECT_API_KEY_CONTENT_BASE64" | base64 --decode > "$api_key_path"

    API_KEY_PATH="$api_key_path" python3 << 'PYEOF'
import jwt, time, os
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_der_private_key, Encoding, PrivateFormat, NoEncryption
)

with open(os.environ["API_KEY_PATH"], "rb") as f:
    key_data = f.read()

# Handle both PEM (text) and DER (binary) key formats
try:
    load_pem_private_key(key_data, password=None)
    private_key = key_data
except (ValueError, Exception):
    key = load_der_private_key(key_data, password=None)
    private_key = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

now = int(time.time())
payload = {
    "iss": os.environ["APP_STORE_CONNECT_API_ISSUER_ID"],
    "iat": now,
    "exp": now + 1200,
    "aud": "appstoreconnect-v1"
}
headers = {
    "kid": os.environ["APP_STORE_CONNECT_API_KEY_ID"],
    "typ": "JWT"
}

token = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
print(token)
PYEOF
}

# ─── API Helpers ─────────────────────────────────────────────────────────────

api_get() {
    local url="$1"
    curl -gsf -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" "$url"
}

api_post() {
    local url="$1"
    local data="$2"
    curl -gsf -X POST -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" -d "$data" "$url"
}

api_delete() {
    local url="$1"
    curl -gsf -X DELETE -H "Authorization: Bearer $JWT_TOKEN" "$url"
}

# ─── Certificate Management ─────────────────────────────────────────────────

list_distribution_certificates() {
    api_get "$API_BASE_URL/certificates?filter[certificateType]=DISTRIBUTION&limit=200"
}

delete_certificate() {
    local cert_id="$1"
    echo "Deleting certificate: $cert_id"
    api_delete "$API_BASE_URL/certificates/$cert_id"
}

create_certificate() {
    local csr_file="$1"
    local payload
    payload=$(CSR_FILE="$csr_file" python3 << 'PYEOF'
import json, os
with open(os.environ["CSR_FILE"]) as f:
    csr = f.read()
print(json.dumps({
    "data": {
        "type": "certificates",
        "attributes": {
            "certificateType": "DISTRIBUTION",
            "csrContent": csr
        }
    }
}))
PYEOF
)
    api_post "$API_BASE_URL/certificates" "$payload"
}

# ─── Provisioning Profile Management ──────────────────────────────────────────

list_appstore_profiles() {
    api_get "$API_BASE_URL/profiles?filter[profileType]=IOS_APP_STORE&limit=200"
}

delete_profile() {
    local profile_id="$1"
    echo "Deleting provisioning profile: $profile_id"
    api_delete "$API_BASE_URL/profiles/$profile_id"
}

lookup_bundle_id() {
    local identifier="$1"
    api_get "$API_BASE_URL/bundleIds?filter[identifier]=$identifier"
}

# ─── Main Logic ──────────────────────────────────────────────────────────────

echo "==> Installing PyJWT with cryptography support..."
pip3 install --quiet PyJWT[crypto] 2>/dev/null || pip3 install --quiet PyJWT cryptography

echo "==> Generating JWT for App Store Connect API..."
JWT_TOKEN=$(generate_jwt)
echo "JWT generated successfully."

# ── Decode persistent private key ────────────────────────────────────────────

PRIVATE_KEY_PATH="$WORK_DIR/private_key.pem"
echo "$DISTRIBUTION_PRIVATE_KEY_BASE64" | base64 --decode > "$PRIVATE_KEY_PATH"
echo "==> Persistent private key decoded."

# ── Find existing valid certificate matching our key ─────────────────────────

CERT_PATH="$WORK_DIR/certificate.cer"
export CERT_PATH
export PRIVATE_KEY_PATH

echo "==> Listing existing distribution certificates..."
list_distribution_certificates > "$WORK_DIR/certs_response.json"

# Python: compare each cert's public key modulus against our private key.
# If a match is found and it's not expiring soon, write its ID and DER content to disk.
MATCH_RESULT=$(python3 << 'PYEOF'
import json, base64, os, sys, datetime
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

work_dir = os.environ["WORK_DIR"]
cert_path = os.environ["CERT_PATH"]
key_path = os.environ["PRIVATE_KEY_PATH"]
buffer_days = int(os.environ.get("CERT_RENEWAL_BUFFER_DAYS", "30"))

with open(key_path, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

key_pub_numbers = private_key.private_numbers().public_numbers

with open(os.path.join(work_dir, "certs_response.json")) as f:
    data = json.load(f)

certs = data.get("data", [])
print(f"Found {len(certs)} distribution certificate(s).", file=sys.stderr)

now = datetime.datetime.now(datetime.timezone.utc)
buffer = datetime.timedelta(days=buffer_days)

for cert_entry in certs:
    cert_id = cert_entry["id"]
    cert_content_b64 = cert_entry.get("attributes", {}).get("certificateContent", "")
    expiry_str = cert_entry.get("attributes", {}).get("expirationDate", "")

    if not cert_content_b64:
        continue

    try:
        cert_bytes = base64.b64decode(cert_content_b64)
        cert = load_der_x509_certificate(cert_bytes)
        cert_pub_numbers = cert.public_key().public_numbers()
    except Exception as e:
        print(f"  Skipping cert {cert_id}: failed to parse ({e})", file=sys.stderr)
        continue

    if cert_pub_numbers.n != key_pub_numbers.n or cert_pub_numbers.e != key_pub_numbers.e:
        print(f"  Cert {cert_id}: key mismatch, skipping.", file=sys.stderr)
        continue

    # Key matches - check expiration
    not_valid_after = cert.not_valid_after_utc
    remaining = not_valid_after - now

    if remaining > buffer:
        print(f"  Cert {cert_id}: VALID (expires {not_valid_after.isoformat()}, {remaining.days}d remaining).", file=sys.stderr)
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        with open(os.path.join(work_dir, "matched_cert_id.txt"), "w") as f:
            f.write(cert_id)
        print("REUSE")
        sys.exit(0)
    else:
        print(f"  Cert {cert_id}: key matches but expiring soon ({remaining.days}d remaining, buffer={buffer_days}d).", file=sys.stderr)
        with open(os.path.join(work_dir, "expired_cert_id.txt"), "w") as f:
            f.write(cert_id)

print("CREATE")
PYEOF
)

if [ "$MATCH_RESULT" = "REUSE" ]; then
    echo "==> Reusing existing valid certificate."
    CERT_ID=$(cat "$WORK_DIR/matched_cert_id.txt")
else
    echo "==> No valid matching certificate found. Creating new one..."

    # Delete only the expired cert that matched our key (if any)
    if [ -f "$WORK_DIR/expired_cert_id.txt" ]; then
        EXPIRED_ID=$(cat "$WORK_DIR/expired_cert_id.txt")
        echo "==> Deleting expired matching certificate: $EXPIRED_ID"
        delete_certificate "$EXPIRED_ID" || echo "Warning: Failed to delete certificate $EXPIRED_ID"
    fi

    echo "==> Generating CSR with persistent key..."
    CSR_PATH="$WORK_DIR/certificate.csr"
    openssl req -new -key "$PRIVATE_KEY_PATH" -out "$CSR_PATH" -subj "/CN=Distribution/O=Distribution/C=US" 2>/dev/null

    echo "==> Submitting CSR to App Store Connect API..."
    create_certificate "$CSR_PATH" > "$WORK_DIR/create_response.json"

    python3 << 'PYEOF' || { echo "ERROR: Failed to create certificate"; exit 1; }
import json, base64, sys, os

work_dir = os.environ["WORK_DIR"]
cert_path = os.environ["CERT_PATH"]

with open(os.path.join(work_dir, "create_response.json")) as f:
    data = json.load(f)

cert_data = data.get("data", {})
cert_id = cert_data.get("id", "unknown")
cert_content = cert_data.get("attributes", {}).get("certificateContent", "")
expiry = cert_data.get("attributes", {}).get("expirationDate", "unknown")

if not cert_content:
    print("ERROR: No certificate content in API response", file=sys.stderr)
    sys.exit(1)

cert_bytes = base64.b64decode(cert_content)
with open(cert_path, "wb") as f:
    f.write(cert_bytes)

with open(os.path.join(work_dir, "matched_cert_id.txt"), "w") as f:
    f.write(cert_id)

print(f"Certificate created: {cert_id} (expires: {expiry})")
PYEOF

    CERT_ID=$(cat "$WORK_DIR/matched_cert_id.txt")
    echo "==> New certificate ID: $CERT_ID"
fi

# ── Provisioning Profile ─────────────────────────────────────────────────────

export CERT_ID
export BUNDLE_IDENTIFIER

echo "==> Looking up bundle ID for $BUNDLE_IDENTIFIER..."
lookup_bundle_id "$BUNDLE_IDENTIFIER" > "$WORK_DIR/bundle_id_response.json"

BUNDLE_ID_RESOURCE_ID=$(python3 << 'PYEOF' || { echo "ERROR: Failed to look up bundle ID"; exit 1; }
import json, sys, os

work_dir = os.environ["WORK_DIR"]
bundle_id = os.environ["BUNDLE_IDENTIFIER"]

with open(os.path.join(work_dir, "bundle_id_response.json")) as f:
    data = json.load(f)

bundle_ids = data.get("data", [])
if not bundle_ids:
    print(f"ERROR: No bundle ID found for {bundle_id}", file=sys.stderr)
    sys.exit(1)

print(bundle_ids[0]["id"])
PYEOF
)
echo "Bundle ID resource: $BUNDLE_ID_RESOURCE_ID"

echo "==> Checking existing provisioning profiles..."
list_appstore_profiles > "$WORK_DIR/profiles_response.json"

# Find an active profile linked to our certificate, or determine we need a new one
PROFILE_ACTION=$(CERT_ID="$CERT_ID" python3 << 'PYEOF'
import json, os, sys, base64

work_dir = os.environ["WORK_DIR"]
our_cert_id = os.environ["CERT_ID"]

with open(os.path.join(work_dir, "profiles_response.json")) as f:
    data = json.load(f)

profiles = data.get("data", [])
stale_ids = []

for profile in profiles:
    profile_id = profile["id"]
    state = profile.get("attributes", {}).get("profileState", "")
    name = profile.get("attributes", {}).get("name", "")

    if state != "ACTIVE":
        stale_ids.append(profile_id)
        print(f"  Profile {profile_id} ({name}): state={state}, marking for cleanup.", file=sys.stderr)
        continue

    # Profile is active - we'll reuse it
    # (maui-actions/apple-provisioning will handle cert-to-profile binding validation)
    profile_content = profile.get("attributes", {}).get("profileContent", "")
    if profile_content:
        profile_bytes = base64.b64decode(profile_content)
        with open(os.path.join(work_dir, "profile.mobileprovision"), "wb") as f:
            f.write(profile_bytes)

    with open(os.path.join(work_dir, "reuse_profile_name.txt"), "w") as f:
        f.write(name)

    print(f"  Profile {profile_id} ({name}): ACTIVE, reusing.", file=sys.stderr)
    print("REUSE")

    # Still record stale ones for cleanup
    with open(os.path.join(work_dir, "stale_profile_ids.txt"), "w") as f:
        for sid in stale_ids:
            f.write(sid + "\n")
    sys.exit(0)

# No active profile found
with open(os.path.join(work_dir, "stale_profile_ids.txt"), "w") as f:
    for sid in stale_ids:
        f.write(sid + "\n")

print("CREATE")
PYEOF
)

# Clean up stale profiles
if [ -f "$WORK_DIR/stale_profile_ids.txt" ]; then
    while IFS= read -r profile_id; do
        [ -z "$profile_id" ] && continue
        echo "==> Deleting stale provisioning profile: $profile_id"
        delete_profile "$profile_id" || echo "Warning: Failed to delete profile $profile_id"
    done < "$WORK_DIR/stale_profile_ids.txt"
fi

if [ "$PROFILE_ACTION" = "REUSE" ]; then
    PROFILE_NAME=$(cat "$WORK_DIR/reuse_profile_name.txt")
    echo "==> Reusing existing provisioning profile: $PROFILE_NAME"
else
    echo "==> Creating new provisioning profile..."

    PROFILE_NAME="${BUNDLE_IDENTIFIER}-profile-$(date +%s)"
    PROFILE_PAYLOAD=$(PROFILE_NAME="$PROFILE_NAME" BUNDLE_RESOURCE_ID="$BUNDLE_ID_RESOURCE_ID" CERT_ID="$CERT_ID" python3 << 'PYEOF'
import json, os
print(json.dumps({
    "data": {
        "type": "profiles",
        "attributes": {
            "name": os.environ["PROFILE_NAME"],
            "profileType": "IOS_APP_STORE"
        },
        "relationships": {
            "bundleId": {
                "data": { "type": "bundleIds", "id": os.environ["BUNDLE_RESOURCE_ID"] }
            },
            "certificates": {
                "data": [{ "type": "certificates", "id": os.environ["CERT_ID"] }]
            }
        }
    }
}))
PYEOF
)

    HTTP_CODE=$(curl -gs -o "$WORK_DIR/profile_create_response.json" -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$PROFILE_PAYLOAD" \
        "$API_BASE_URL/profiles")

    if [ "$HTTP_CODE" -ge 400 ]; then
        echo "ERROR: Profile creation failed with HTTP $HTTP_CODE"
        echo "Response body:"
        cat "$WORK_DIR/profile_create_response.json"
        exit 1
    fi

    python3 << 'PYEOF' || { echo "ERROR: Failed to parse profile creation response"; exit 1; }
import json, sys, os

work_dir = os.environ["WORK_DIR"]

with open(os.path.join(work_dir, "profile_create_response.json")) as f:
    data = json.load(f)

profile_data = data.get("data", {})
profile_id = profile_data.get("id", "unknown")
profile_state = profile_data.get("attributes", {}).get("profileState", "unknown")

if profile_state != "ACTIVE":
    print(f"WARNING: Profile created but state is {profile_state}, expected ACTIVE", file=sys.stderr)

print(f"Provisioning profile created: {profile_id} (state: {profile_state})")
PYEOF

    echo "==> Provisioning profile ready: $PROFILE_NAME"
fi

# ── Package into P12 ────────────────────────────────────────────────────────

echo "==> Converting DER certificate to PEM..."
PEM_CERT_PATH="$WORK_DIR/certificate.pem"
openssl x509 -inform DER -in "$CERT_PATH" -out "$PEM_CERT_PATH" 2>/dev/null

P12_PASSWORD=$(openssl rand -base64 32)
KEYCHAIN_PWD=$(openssl rand -base64 32)
P12_PATH="$WORK_DIR/certificate.p12"

echo "==> Packaging P12..."
openssl pkcs12 -export \
    -in "$PEM_CERT_PATH" \
    -inkey "$PRIVATE_KEY_PATH" \
    -out "$P12_PATH" \
    -passout "pass:$P12_PASSWORD" 2>/dev/null

P12_BASE64=$(base64 -w 0 "$P12_PATH")

# ── Write outputs ───────────────────────────────────────────────────────────

echo "==> Writing outputs..."

{
    echo "P12_DISTRIBUTION_CERTIFICATE_BASE64=$P12_BASE64"
    echo "P12_DISTRIBUTION_PASSWORD=$P12_PASSWORD"
    echo "KEYCHAIN_PASSWORD=$KEYCHAIN_PWD"
    echo "PROVISIONING_PROFILE_NAME=$PROFILE_NAME"
} >> "$GITHUB_OUTPUT"

echo "==> Done. Certificate and provisioning profile ready."
