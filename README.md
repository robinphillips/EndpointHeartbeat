# Endpoint Heartbeat

A macOS command-line healthcheck for public HTTPS endpoints. It performs Apple's normal hostname and certificate-chain validation, then pins configured certificate hashes.

Endpoint Heartbeat supports expected successes and expected trust failures. This allows deliberately obsolete or incorrect pins to act as negative integration tests. DNS failures, timeouts and unexpected HTTP responses never count as expected trust failures.

## Quick start

1. Create a new public GitHub repository.
2. Upload the contents of this directory to its root.
3. Open the Actions tab and run **Endpoint heartbeat** manually.
4. Replace `Examples/heartbeat.json` with your endpoints and pins.

The included configuration is runnable: it checks a Let's Encrypt test endpoint with one correct and one deliberately incorrect root pin. The **On commit** workflow runs continuous integration and endpoint heartbeat on pushes to `main`; continuous integration also runs on pull requests. Endpoint heartbeat runs hourly at 45 minutes past the hour and manually.

## Configuration

```json
{
  "endpoints": [
    {
      "name": "Production API",
      "url": "https://api.example.com/health",
      "certificates": [
        {
          "id": "current-root",
          "role": "root",
          "sha256": "0123456789abcdef...",
          "encoding": "hexadecimal",
          "state": "active"
        }
      ],
      "expectedOutcome": "success",
      "acceptableStatusCodes": [200, 204]
    },
    {
      "name": "Deliberately obsolete pin",
      "url": "https://api.example.com/health",
      "certificates": [
        {
          "id": "obsolete-root",
          "role": "root",
          "sha256": "abcdef...",
          "encoding": "hexadecimal",
          "state": "active"
        }
      ],
      "expectedOutcome": "trustFailure",
      "acceptableStatusCodes": [200]
    }
  ]
}
```

`expectedOutcome` defaults to `success`. `acceptableStatusCodes` defaults to every status from 200 through 299.

Each endpoint requires at least one `active` certificate pin. `role` is `leaf`, `intermediate`, or `root`; any matching active pin is accepted. Set `encoding` to `hexadecimal` or `base64`. Hexadecimal values may be 64 characters or 32 colon-separated byte pairs; Base64 values must decode to 32 bytes.

`state` defaults to `active`. Use `state: "retiring"` with an ISO-8601 `retireAfter` date while rotating a pin. A retiring pin is accepted only before that date. `certificateExpiryWarningDays` defaults to `30`; expiring pins emit warnings unless the matching pin is retiring and another active pin exists for the same role.

```json
{
  "name": "Production API during root rotation",
  "url": "https://api.example.com/health",
  "certificateExpiryWarningDays": 30,
  "certificates": [
    {
      "id": "previous-root",
      "role": "root",
      "sha256": "old-root-hash...",
      "encoding": "base64",
      "state": "retiring",
      "retireAfter": "2026-12-01T00:00:00Z"
    },
    {
      "id": "replacement-root",
      "role": "root",
      "sha256": "new-root-hash...",
      "encoding": "base64",
      "state": "active"
    }
  ],
  "acceptableStatusCodes": [200, 204]
}
```

After `retireAfter`, a chain matching only `previous-root` fails. Keep the replacement pin active before deploying the retiring pin.

## Commands

```sh
swift run endpoint-heartbeat validate --config Examples/heartbeat.json
swift run endpoint-heartbeat check --config Examples/heartbeat.json
swift run endpoint-heartbeat inspect https://api.example.com/health
```

`validate` decodes the configuration and checks endpoint names, HTTPS URLs, certificate pin IDs, hash encodings, retirement dates, expiry-warning thresholds, and acceptable status codes. It does not make network requests.

`check` validates the configuration, performs one HTTPS request per endpoint, verifies the system trust chain and configured certificate pins, and checks the HTTP status code. It prints a tick or cross for every endpoint, followed by any imminent certificate-expiry warnings.

Pass `--report heartbeat-report.json` to write a machine-readable report, and `--markdown-report heartbeat-report.md` to write a Markdown summary. The scheduled workflow uploads the JSON report as a `heartbeat-report` artifact and adds the Markdown report to the GitHub Actions job summary.

`inspect` displays the evaluated certificate chain, SHA-256 hash, and expiry of every certificate.

To calculate a hash from a root certificate file:

```sh
openssl x509 -in root.pem -outform DER | openssl dgst -sha256
```

## Use as a library

Add the package URL in `Package.swift`, using a tagged release:

```swift
dependencies: [
    .package(url: "https://github.com/YOUR-NAME/endpoint-heartbeat.git", from: "1.0.0")
]
```

Add `EndpointHeartbeatCore` to the target dependencies, then:

```swift
import EndpointHeartbeatCore

let configuration = try ConfigurationLoader.load(from: configURL)
let results = await Heartbeat.checkAll(configuration.endpoints)
```

## Exit status

The CLI exits with status `0` when every observed result matches its expectation. Configuration errors or unexpected results produce a non-zero status, causing the GitHub workflow to fail.

## Platform support

macOS 13 or later. Security.framework is used so the healthcheck exercises Apple's trust evaluation.

Scheduled GitHub workflows can be delayed or occasionally dropped. Add an external dead-man monitor if a missed run must generate an alert.

## Licence

MIT
