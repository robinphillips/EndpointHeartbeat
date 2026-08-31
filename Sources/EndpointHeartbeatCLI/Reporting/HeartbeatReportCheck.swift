import EndpointHeartbeatCore
import Foundation

struct HeartbeatReportCheck: Encodable {
    let name: String
    let url: URL
    let passed: Bool
    let expectedOutcome: String
    let acceptableStatusCodes: [Int]
    let observedOutcome: String
    let outcome: String
    let outcomeDetails: String
    let warnings: [String]
    let pins: [HeartbeatReportPin]

    init(_ result: CheckResult) {
        name = result.endpoint.name
        url = result.endpoint.url
        passed = result.passed
        expectedOutcome = result.endpoint.expectedOutcome.rawValue
        acceptableStatusCodes = result.endpoint.acceptableStatusCodes
        observedOutcome = result.observedOutcome.description
        switch result.observedOutcome {
        case let .success(statusCode):
            outcome = "Success"
            outcomeDetails = "HTTP status: \(statusCode)"
        case let .trustFailure(message):
            outcome = "Trust failure"
            outcomeDetails = message
        case let .httpFailure(statusCode):
            outcome = "HTTP failure"
            outcomeDetails = "HTTP status: \(statusCode)"
        case let .transportFailure(message):
            outcome = "Transport failure"
            outcomeDetails = message
        }
        warnings = result.warnings.map(\.description)
        pins = result.endpoint.certificates.map(HeartbeatReportPin.init)
    }
}
