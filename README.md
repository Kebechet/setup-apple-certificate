# Setup Apple Certificate

GitHub Action that manages Apple Distribution certificates and provisioning profiles via the App Store Connect API.

Uses a persistent private key and reuses existing valid certificates - only creates new ones when no valid matching certificate exists or when the current one is expiring soon.

## Setup

Add the following secrets to your repository (Settings > Secrets and variables > Actions):

| Secret | Description |
|---|---|
| `APP_STORE_CONNECT_KEY_ID` | API Key ID from App Store Connect (Keys section) |
| `APP_STORE_CONNECT_ISSUER_ID` | Issuer ID from App Store Connect (Keys section) |
| `APP_STORE_CONNECT_PRIVATE_KEY_BASE64` | The `.p8` API key file content, base64-encoded |
| `DISTRIBUTION_PRIVATE_KEY_BASE64` | A persistent RSA private key used for certificate signing, base64-encoded |

To generate the distribution private key:

```bash
openssl genrsa -out distribution_key.pem 2048
base64 -w 0 distribution_key.pem
```

Store the base64 output as the `DISTRIBUTION_PRIVATE_KEY_BASE64` secret.

## Usage

```yaml
- uses: kebechet/setup-apple-certificate@v1.0.0
  id: cert
  with:
    app-store-connect-key-id: ${{ secrets.APP_STORE_CONNECT_KEY_ID }}
    app-store-connect-issuer-id: ${{ secrets.APP_STORE_CONNECT_ISSUER_ID }}
    app-store-connect-private-key: ${{ secrets.APP_STORE_CONNECT_PRIVATE_KEY_BASE64 }}
    distribution-private-key: ${{ secrets.DISTRIBUTION_PRIVATE_KEY_BASE64 }}
    bundle-identifier: com.example.app
```

This action is designed to be used together with [maui-actions/apple-provisioning](https://github.com/maui-actions/apple-provisioning), which installs the certificate and provisioning profile on the macOS runner for signing:

```yaml
- uses: maui-actions/apple-provisioning@v4
  with:
    certificate: ${{ steps.cert.outputs.p12-certificate-base64 }}
    certificate-passphrase: ${{ steps.cert.outputs.p12-password }}
    bundle-identifiers: com.example.app
    profile-types: IOS_APP_STORE
    app-store-connect-key-id: ${{ secrets.APP_STORE_CONNECT_KEY_ID }}
    app-store-connect-issuer-id: ${{ secrets.APP_STORE_CONNECT_ISSUER_ID }}
    app-store-connect-private-key: ${{ secrets.APP_STORE_CONNECT_PRIVATE_KEY_BASE64 }}
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `app-store-connect-key-id` | yes | | App Store Connect API Key ID |
| `app-store-connect-issuer-id` | yes | | App Store Connect API Issuer ID |
| `app-store-connect-private-key` | yes | | API key (.p8) content, base64-encoded |
| `distribution-private-key` | yes | | Persistent RSA private key, base64-encoded |
| `bundle-identifier` | yes | | App bundle ID (e.g. `com.example.app`) |
| `cert-renewal-buffer-days` | no | `14` | Days before expiry to trigger renewal |

## Outputs

| Output | Description |
|---|---|
| `p12-certificate-base64` | P12 certificate, base64-encoded |
| `p12-password` | Random password for the P12 |
| `keychain-password` | Random keychain password |
| `provisioning-profile-name` | Name of the provisioning profile |

## How it works

1. Generates a JWT for the App Store Connect API
2. Lists existing distribution certificates and checks if any match the provided private key
3. If a valid matching certificate exists (not expiring within the buffer period), reuses it
4. If no valid match exists, creates a new CSR and submits it to get a new certificate
5. Looks up or creates an App Store provisioning profile linked to the certificate
6. Packages everything into a P12 and writes outputs for downstream steps

## Requirements

The runner must have `python3`, `openssl`, and `curl` available. The action installs `PyJWT[crypto]` automatically.

## License

[MIT](LICENSE)
