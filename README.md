# Endpoint Heartbeat

A macOS command-line healthcheck for public HTTPS endpoints. It performs Apple's normal hostname and certificate-chain validation, then pins configured SubjectPublicKeyInfo (SPKI) SHA-256 hashes.

Endpoint Heartbeat supports expected successes and expected trust failures. This allows deliberately obsolete or incorrect pins to act as negative integration tests. DNS failures, timeouts and unexpected HTTP responses never count as expected trust failures.

## Quick start

1. Create `endpoint-heartbeat.json` in your repository using the configuration below.
2. Add `.github/workflows/endpoint-heartbeat.yml`:

```yaml
name: Endpoint heartbeat

on:
  workflow_dispatch:
  schedule:
    - cron: "45 * * * *"

permissions:
  contents: read

jobs:
  heartbeat:
    uses: robinphillips/EndpointHeartbeat/.github/workflows/heartbeat.yml@<release-tag>
    with:
      config_path: endpoint-heartbeat.json
      source_ref: <release-tag>
```

3. Replace both `<release-tag>` values with the same published version tag.
4. Open the Actions tab and run **Endpoint heartbeat** manually.

The reusable workflow checks out the caller repository to read its configuration and the referenced Endpoint Heartbeat release to run the check. The included configuration is runnable: it checks a Let's Encrypt test endpoint with one correct and one deliberately incorrect root pin. This repository's **On commit** workflow runs continuous integration and endpoint heartbeat on every push. Endpoint heartbeat also runs hourly at 45 minutes past the hour and manually.

## Configuration

```json
{
  "endpoints": [
    {
      "name": "Production API",
      "reportGroup": "Example service",
      "url": "https://api.example.com/health",
      "certificates": [
        {
          "id": "current-root",
          "role": "root",
          "spkiSHA256Base64": "Base64-encoded-SPKI-SHA-256...",
          "state": "active"
        }
      ],
      "acceptableStatusCodes": [200, 204]
    },
    {
      "name": "Deliberately obsolete pin",
      "url": "https://api.example.com/health",
      "certificates": [
        {
          "id": "obsolete-root",
          "role": "root",
          "spkiSHA256Base64": "Another-Base64-encoded-SPKI-SHA-256...",
          "expectedOutcome": "trustFailure",
          "state": "active"
        }
      ],
      "acceptableStatusCodes": [200]
    }
  ]
}
```

Each pin's `expectedOutcome` defaults to `success`. `acceptableStatusCodes` defaults to every status from 200 through 299.

`reportGroup` is optional. It supplies the heading for related checks in the Markdown report; otherwise the report uses the endpoint's domain.

Each endpoint requires at least one `active` certificate pin. `role` is `leaf`, `intermediate`, or `root`; `spkiSHA256Base64` is a Base64-encoded SHA-256 hash of the certificate's DER-encoded SubjectPublicKeyInfo and must decode to exactly 32 bytes. This is the same pin format as Apple's `SPKI-SHA256-BASE64`. Each pin is checked independently; `expectedOutcome` defaults to `success` and can be `trustFailure` for an intentionally unmatched pin.

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
      "spkiSHA256Base64": "old-root-SPKI-hash...",
      "state": "retiring",
      "retireAfter": "2026-12-01T00:00:00Z"
    },
    {
      "id": "replacement-root",
      "role": "root",
      "spkiSHA256Base64": "new-root-SPKI-hash...",
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

`validate` decodes the configuration and checks endpoint names, HTTPS URLs, certificate pin IDs, Base64 SPKI hashes, retirement dates, expiry-warning thresholds, and acceptable status codes. It does not make network requests.

`check` validates the configuration, performs one HTTPS request per endpoint, verifies the system trust chain and configured certificate pins, and checks the HTTP status code. It prints a tick or cross for every endpoint, followed by any imminent certificate-expiry warnings.

Pass `--report heartbeat-report.json` to write a machine-readable report, and `--markdown-report heartbeat-report.md` to write a Markdown summary. The scheduled workflow uploads the JSON report as a `heartbeat-report` artifact and adds the Markdown report to the GitHub Actions job summary.

`inspect` displays the evaluated certificate chain, Base64 SPKI SHA-256 hash, and expiry of every certificate.

To calculate an SPKI pin from a certificate file:

```sh
openssl x509 -in certificate.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | base64
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

## Compatibility

Release tags follow semantic versioning.

- Patch releases preserve the public Swift API, CLI options, JSON configuration schema, JSON report schema, and reusable workflow inputs.
- Minor releases may add optional configuration fields, report fields, CLI options, and workflow inputs without changing existing behaviour.
- Major releases may remove or change public Swift APIs, CLI options, configuration fields, JSON report fields, or workflow inputs.
- Markdown reports are for human reading and may change between releases. Use the JSON report for machine-readable integrations.
- The default branch is not a compatibility target. Consumers should reference a release tag in Swift Package Manager and reusable workflow references.

## Releases

Pull request titles must follow [Conventional Commits](https://www.conventionalcommits.org/). Squash-merge pull requests so the title becomes the commit message on `main`.

[Release Please](https://github.com/googleapis/release-please) creates and updates a release pull request from merged Conventional Commits. Merging the release pull request creates the semantic-version tag, changelog, and GitHub Release.

Scheduled GitHub workflows can be delayed or occasionally dropped. Add an external dead-man monitor if a missed run must generate an alert.

## Licence

MIT
