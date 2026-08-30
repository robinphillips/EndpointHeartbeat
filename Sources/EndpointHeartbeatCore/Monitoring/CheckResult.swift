public struct CheckResult: Sendable {
    public let endpoint: Endpoint
    public let observedOutcome: ObservedOutcome
    public let warnings: [CertificateWarning]

    public init(
        endpoint: Endpoint,
        observedOutcome: ObservedOutcome,
        warnings: [CertificateWarning] = []
    ) {
        self.endpoint = endpoint
        self.observedOutcome = observedOutcome
        self.warnings = warnings
    }

    public var passed: Bool {
        observedOutcome.expectedCategory == endpoint.expectedOutcome
    }
}
