import Foundation

public enum Heartbeat {
    static func check(
        _ endpoint: Endpoint,
        pin: CertificatePin,
        sessionConfiguration configuration: URLSessionConfiguration
    ) async -> CheckResult {
        let delegate = CertificatePinningDelegate(
            pins: [pin],
            expiryWarningDays: endpoint.certificateExpiryWarningDays
        )
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        do {
            let (_, response) = try await session.data(from: endpoint.url)
            guard let response = response as? HTTPURLResponse else {
                return CheckResult(endpoint: endpoint, pin: pin, observedOutcome: .transportFailure("response was not HTTP"), endpointCertificate: delegate.observedCertificate(for: .leaf), warnings: delegate.warnings)
            }

            let outcome: ObservedOutcome = endpoint.acceptableStatusCodes.contains(response.statusCode)
                ? .success(statusCode: response.statusCode)
                : .httpFailure(statusCode: response.statusCode)
            return CheckResult(endpoint: endpoint, pin: pin, observedOutcome: outcome, endpointCertificate: delegate.observedCertificate(for: .leaf), warnings: delegate.warnings)
        } catch {
            if let trustFailure = delegate.trustFailure {
                return CheckResult(endpoint: endpoint, pin: pin, observedOutcome: .trustFailure(trustFailure), endpointCertificate: delegate.observedCertificate(for: .leaf), warnings: delegate.warnings)
            }
            return CheckResult(endpoint: endpoint, pin: pin, observedOutcome: .transportFailure(error.localizedDescription), endpointCertificate: delegate.observedCertificate(for: .leaf), warnings: delegate.warnings)
        }
    }

    public static func checkAll(_ endpoints: [Endpoint]) async -> [CheckResult] {
        await withTaskGroup(of: (Int, CheckResult).self) { group in
            let checks = endpoints.flatMap { endpoint in endpoint.certificates.map { (endpoint, $0) } }
            for (index, target) in checks.enumerated() {
                group.addTask { (index, await check(target.0, pin: target.1, sessionConfiguration: .ephemeral)) }
            }

            var results: [(Int, CheckResult)] = []
            for await result in group { results.append(result) }
            return results.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }
}
