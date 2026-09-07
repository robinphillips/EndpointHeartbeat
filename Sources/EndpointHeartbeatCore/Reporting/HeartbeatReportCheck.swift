import Foundation

public struct HeartbeatReportCheck: Encodable {
    public let requestID: UUID
    public let startedAt: Date
    public let evaluatedChain: [ObservedCertificate]
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
    public let pin: HeartbeatReportPin?
    public let pinSet: CertificatePinSet?
    public let pinSetMembers: [HeartbeatReportPin]
    public let matchedPinIDs: [String]
    public let matchedPins: [HeartbeatReportPin]
    public let endpointCertificate: ObservedCertificate?

    init(_ result: CheckResult) {
        requestID = result.requestID
        startedAt = result.startedAt
        evaluatedChain = result.evaluatedChain
        name = result.endpoint.name
        reportGroup = result.endpoint.reportGroup
        url = result.endpoint.url
        passed = result.passed
        expectedOutcome = result.expectedOutcome.rawValue
        acceptableStatusCodes = result.endpoint.acceptableStatusCodes
        observedOutcome = result.observedOutcome.description
        switch result.observedOutcome {
        case let .success(statusCode):
            outcome = "Success"
            outcomeDetails = "HTTP status: \(statusCode)"
        case let .trustFailure(message):
            outcome = "Trust failure"
            outcomeDetails = message
        case let .systemTrustFailure(message):
            outcome = "System trust failure"
            outcomeDetails = message
        case let .httpFailure(statusCode):
            outcome = "HTTP failure"
            outcomeDetails = "HTTP status: \(statusCode)"
        case let .transportFailure(message):
            outcome = "Transport failure"
            outcomeDetails = message
        }
        warnings = result.warnings.map(\.description)
        pin = result.pin.map(HeartbeatReportPin.init)
        pinSet = result.pinSet
        matchedPinIDs = result.matchedPinIDs
        matchedPins = result.endpoint.certificates.filter { result.matchedPinIDs.contains($0.id) }.map(HeartbeatReportPin.init)
        pinSetMembers = result.pinSet.map { set in
            result.endpoint.certificates.filter { set.pinIDs.contains($0.id) }.map(HeartbeatReportPin.init)
        } ?? []
        endpointCertificate = result.endpointCertificate
    }
}
