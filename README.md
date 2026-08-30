# Endpoint Heartbeat

A macOS command-line healthcheck for public HTTPS endpoints. It performs Apple's normal hostname and certificate-chain validation, then pins the SHA-256 hash of the evaluated root certificate.

Endpoint Heartbeat supports expected successes and expected trust failures. This allows deliberately obsolete or incorrect pins to act as negative integration tests. DNS failures, timeouts and unexpected HTTP responses never count as expected trust failures.

## Quick start

1. Create a new public GitHub repository.
2. Upload the contents of this directory to its root.
3. Open the Actions tab and run **Endpoint heartbeat** manually.
4. Replace `Examples/heartbeat.json` with your endpoints and pins.

The included configuration is runnable: it checks a Let's Encrypt test endpoint with one correct and one deliberately incorrect root pin. The workflow runs on pushes and pull requests, every night at 02:17 UTC, and manually.

## Configuration

```json
{
  "endpoints": [
    {
      "name": "Production API",
      "url": "https://api.example.com/health",
      "rootSHA256": "0123456789abcdef...",
      "expectedOutcome": "success",
      "acceptableStatusCodes": [200, 204]
    },
    {
      "name": "Deliberately obsolete pin",
      "url": "https://api.example.com/health",
      "rootSHA256": "abcdef...",
      "expectedOutcome": "trustFailure",
      "acceptableStatusCodes": [200]
    }
  ]
}
```

`expectedOutcome` defaults to `success`. `acceptableStatusCodes` defaults to every status from 200 through 299.

## Commands

```sh
swift run endpoint-heartbeat validate --config Examples/heartbeat.json
swift run endpoint-heartbeat check --config Examples/heartbeat.json
swift run endpoint-heartbeat inspect https://api.example.com/health
```

`inspect` displays the evaluated certificate chain and SHA-256 hash of every certificate. Use the final `root` hash in the configuration.

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
