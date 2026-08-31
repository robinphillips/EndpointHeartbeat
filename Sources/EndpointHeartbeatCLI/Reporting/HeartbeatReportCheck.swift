import EndpointHeartbeatCore
import Foundation

struct HeartbeatReportCheck: Encodable {
    let name: String
    let url: URL
    let passed: Bool
    let expectedOutcome: String
    let observedOutcome: String
    let warnings: [String]

    init(_ result: CheckResult) {
        name = result.endpoint.name
        url = result.endpoint.url
        passed = result.passed
        expectedOutcome = result.endpoint.expectedOutcome.rawValue
        observedOutcome = result.observedOutcome.description
        warnings = result.warnings.map(\.description)
    }
}
