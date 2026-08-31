import EndpointHeartbeatCore
import Foundation

struct HeartbeatReportCheck: Encodable {
    let name: String
    let url: URL
    let passed: Bool
    let expectedOutcome: String
    let observedOutcome: String
    let warnings: [String]
    let pins: [HeartbeatReportPin]

    init(_ result: CheckResult) {
        name = result.endpoint.name
        url = result.endpoint.url
        passed = result.passed
        expectedOutcome = result.endpoint.expectedOutcome.rawValue
        observedOutcome = result.observedOutcome.description
        warnings = result.warnings.map(\.description)
        pins = result.endpoint.certificates.map(HeartbeatReportPin.init)
    }
}
