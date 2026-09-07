import Foundation

public struct CheckResult: Sendable {
    public let requestID: UUID
    public let startedAt: Date
    public let evaluatedChain: [ObservedCertificate]
    public let endpoint: Endpoint
    public let pin: CertificatePin?
    public let pinSet: CertificatePinSet?
    public var checkID: String { pinSet?.id ?? pin?.id ?? "system trust" }
    public let observedOutcome: ObservedOutcome
    public let endpointCertificate: ObservedCertificate?
    public let warnings: [CertificateWarning]

    public init(
        endpoint: Endpoint,
        pin: CertificatePin? = nil,
        observedOutcome: ObservedOutcome,
        endpointCertificate: ObservedCertificate? = nil,
        warnings: [CertificateWarning] = [],
        requestID: UUID = UUID(),
        startedAt: Date = .now,
        evaluatedChain: [ObservedCertificate] = [],
        pinSet: CertificatePinSet? = nil
    ) {
        self.requestID = requestID
        self.startedAt = startedAt
        self.evaluatedChain = evaluatedChain
        self.endpoint = endpoint
        self.pin = pin
        self.pinSet = pinSet
        self.observedOutcome = observedOutcome
        self.endpointCertificate = endpointCertificate
        self.warnings = warnings
    }

    public var passed: Bool {
        observedOutcome.expectedCategory == expectedOutcome
    }

    public var expectedOutcome: ExpectedOutcome {
        if let pinSet { return pinSet.expectedOutcome }
        if let pin { return pin.expectedOutcome }
        switch endpoint.systemTrustExpectation {
        case .success: return .success
        case .systemTrustFailure: return .systemTrustFailure
        }
    }
}
