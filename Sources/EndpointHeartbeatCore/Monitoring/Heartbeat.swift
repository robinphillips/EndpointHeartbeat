import Foundation

public enum Heartbeat {
    static func check(
        _ endpoint: Endpoint,
        pin: CertificatePin?,
        sessionConfiguration configuration: URLSessionConfiguration,
        pinSet: CertificatePinSet? = nil
    ) async -> CheckResult {
        let requestID = UUID()
        let startedAt = Date.now
        let delegate = CertificatePinningDelegate(
            pins: pinSet.map { set in endpoint.certificates.filter { set.pinIDs.contains($0.id) } } ?? pin.map { [$0] },
            expiryWarningDays: endpoint.certificateExpiryWarningDays,
            rotationPins: endpoint.certificates
        )
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        func result(_ outcome: ObservedOutcome) -> CheckResult {
            CheckResult(
                endpoint: endpoint, pin: pin, observedOutcome: outcome,
                endpointCertificate: delegate.observedCertificate(for: .leaf), warnings: delegate.warnings,
                requestID: requestID, startedAt: startedAt, evaluatedChain: delegate.certificates,
                pinSet: pinSet, matchedPinIDs: delegate.matchedPins.map(\.id)
            )
        }

        do {
            let (_, response) = try await session.data(from: endpoint.url)
            guard let response = response as? HTTPURLResponse else {
                return result(.transportFailure("response was not HTTP"))
            }

            let outcome: ObservedOutcome = endpoint.acceptableStatusCodes.contains(response.statusCode)
                ? .success(statusCode: response.statusCode)
                : .httpFailure(statusCode: response.statusCode)
            return result(outcome)
        } catch {
            if let failure = delegate.systemTrustFailure {
                return result(.systemTrustFailure(failure))
            }
            if let trustFailure = delegate.trustFailure {
                return result(.trustFailure(trustFailure))
            }
            return result(.transportFailure(error.localizedDescription))
        }
    }

    public static func checkAll(_ endpoints: [Endpoint]) async -> [CheckResult] {
        await withTaskGroup(of: (Int, CheckResult).self) { group in
            var checkedURLs = Set<URL>()
            let checks = endpoints.flatMap { endpoint in
                let systemTrustCheck = checkedURLs.insert(endpoint.url).inserted
                    ? [(endpoint, CertificatePin?.none, CertificatePinSet?.none)]
                    : []
                return systemTrustCheck
                    + (endpoint.pinSets.isEmpty
                        ? endpoint.certificates.map { (endpoint, .some($0), CertificatePinSet?.none) }
                        : [])
                    + endpoint.pinSets.map { (endpoint, CertificatePin?.none, .some($0)) }
            }
            for (index, target) in checks.enumerated() {
                group.addTask { (index, await check(target.0, pin: target.1, sessionConfiguration: .ephemeral, pinSet: target.2)) }
            }

            var results: [(Int, CheckResult)] = []
            for await result in group { results.append(result) }
            return results.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }
}
