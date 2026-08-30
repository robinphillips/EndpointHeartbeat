import Foundation

public enum Heartbeat {
    public static func check(_ endpoint: Endpoint) async -> CheckResult {
        await check(endpoint, sessionConfiguration: .ephemeral)
    }

    static func check(
        _ endpoint: Endpoint,
        sessionConfiguration configuration: URLSessionConfiguration
    ) async -> CheckResult {
        let delegate = CertificatePinningDelegate(
            expectedRootHash: endpoint.rootSHA256,
            encoding: endpoint.rootSHA256Encoding
        )
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        do {
            let (_, response) = try await session.data(from: endpoint.url)
            guard let response = response as? HTTPURLResponse else {
                return CheckResult(endpoint: endpoint, observedOutcome: .transportFailure("response was not HTTP"))
            }

            let outcome: ObservedOutcome = endpoint.acceptableStatusCodes.contains(response.statusCode)
                ? .success(statusCode: response.statusCode)
                : .httpFailure(statusCode: response.statusCode)
            return CheckResult(endpoint: endpoint, observedOutcome: outcome)
        } catch {
            if let trustFailure = delegate.trustFailure {
                return CheckResult(endpoint: endpoint, observedOutcome: .trustFailure(trustFailure))
            }
            return CheckResult(endpoint: endpoint, observedOutcome: .transportFailure(error.localizedDescription))
        }
    }

    public static func checkAll(_ endpoints: [Endpoint]) async -> [CheckResult] {
        await withTaskGroup(of: (Int, CheckResult).self) { group in
            for (index, endpoint) in endpoints.enumerated() {
                group.addTask { (index, await check(endpoint)) }
            }

            var results: [(Int, CheckResult)] = []
            for await result in group { results.append(result) }
            return results.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }
}
