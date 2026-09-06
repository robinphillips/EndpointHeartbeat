import Foundation

public struct HeartbeatReportCheck: Encodable {
    public let name: String
    public let reportGroup: String?
    public let url: URL
    public let passed: Bool
    public let expectedOutcome: String
    public let acceptableStatusCodes: [Int]
    public let observedOutcome: String
    public let outcome: String
    public let outcomeDetails: String
    public let warnings: [String]
    public let pin: HeartbeatReportPin
    public let endpointCertificate: ObservedCertificate?

    init(_ result: CheckResult) {
        name = result.endpoint.name
        reportGroup = result.endpoint.reportGroup
        url = result.endpoint.url
        passed = result.passed
        expectedOutcome = result.pin.expectedOutcome.rawValue
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
        pin = HeartbeatReportPin(result.pin)
        endpointCertificate = result.endpointCertificate
    }
}
