public struct CheckResult: Sendable {
    public let endpoint: Endpoint
    public let pin: CertificatePin
    public let observedOutcome: ObservedOutcome
    public let warnings: [CertificateWarning]

    public init(
        endpoint: Endpoint,
        pin: CertificatePin,
        observedOutcome: ObservedOutcome,
        warnings: [CertificateWarning] = []
    ) {
        self.endpoint = endpoint
        self.pin = pin
        self.observedOutcome = observedOutcome
        self.warnings = warnings
    }

    public var passed: Bool {
        observedOutcome.expectedCategory == pin.expectedOutcome
    }
}
