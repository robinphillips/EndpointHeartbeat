import Foundation
import Security

public enum CertificateWarning: Equatable, Sendable {
    case expiring(pinID: String, role: CertificateRole, notAfter: Date)

    public var description: String {
        switch self {
        case let .expiring(pinID, role, notAfter):
            "certificate pin \(pinID) (\(role.rawValue)) expires \(ISO8601DateFormatter().string(from: notAfter))"
        }
    }
}

final class CertificatePinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pins: [CertificatePin]
    private let expiryWarningDays: Int
    private let lock = NSLock()
    private var storedTrustFailure: String?
    private var storedWarnings: [CertificateWarning] = []

    init(pins: [CertificatePin], expiryWarningDays: Int) {
        self.pins = pins
        self.expiryWarningDays = expiryWarningDays
    }

    convenience init(expectedRootHash: String, encoding: CertificateHashEncoding) {
        self.init(
            pins: [.init(id: "root", role: .root, sha256: expectedRootHash, encoding: encoding)],
            expiryWarningDays: 30
        )
    }

    var trustFailure: String? { lock.withLock { storedTrustFailure } }

    var warnings: [CertificateWarning] { lock.withLock { storedWarnings } }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        switch evaluate(trust) {
        case let .failure(message):
            fail(message)
            completionHandler(.cancelAuthenticationChallenge, nil)
        case let .success(warnings):
            lock.withLock { storedWarnings = warnings }
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }

    func failureMessage(for trust: SecTrust) -> String? {
        switch evaluate(trust) {
        case let .failure(message): return message
        case let .success(warnings):
            lock.withLock { storedWarnings = warnings }
            return nil
        }
    }

    private func evaluate(_ trust: SecTrust) -> TrustEvaluation {
        let now = SystemClock.now
        SecTrustSetVerifyDate(trust, now as CFDate)
        var evaluationError: CFError?
        guard SecTrustEvaluateWithError(trust, &evaluationError) else {
            return .failure(evaluationError.map(String.init(describing:)) ?? "system trust evaluation failed")
        }

        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {
            return .failure("evaluated certificate chain has no certificates")
        }

        let observed = chain.enumerated().map { index, certificate in
            ObservedCertificate(
                role: certificateRole(at: index, in: chain),
                sha256: CertificateHash.sha256(of: certificate),
                notAfter: certificateValidity(for: certificate).notAfter
            )
        }
        let matches = matchingPins(in: observed, now: now)
        if !matches.active.isEmpty {
            return .success(expiryWarnings(for: observed, matchedPins: matches.active + matches.retiring, now: now))
        }
        if let retired = matches.retired.first {
            return .failure("certificate pin \(retired.id) retired on \(ISO8601DateFormatter().string(from: retired.retireAfter!))")
        }
        guard !matches.retiring.isEmpty else {
            let actual = observed.map { "\($0.role.rawValue) SHA-256 \($0.sha256)" }.joined(separator: "; ")
            return .failure("no configured certificate pin matched: \(actual)")
        }

        return .success(expiryWarnings(for: observed, matchedPins: matches.retiring, now: now))
    }

    private func matchingPins(in observed: [ObservedCertificate], now: Date) -> PinMatches {
        var matches = PinMatches()
        for pin in pins {
            let expectedHash = CertificateHash.normalised(pin.sha256, encoding: pin.encoding)
            guard observed.contains(where: { $0.role == pin.role && $0.sha256 == expectedHash }) else { continue }
            switch pin.state {
            case .active: matches.active.append(pin)
            case .retiring where pin.retireAfter! <= now: matches.retired.append(pin)
            case .retiring: matches.retiring.append(pin)
            }
        }
        return matches
    }

    private func expiryWarnings(
        for observed: [ObservedCertificate],
        matchedPins: [CertificatePin],
        now: Date
    ) -> [CertificateWarning] {
        let threshold = now.addingTimeInterval(TimeInterval(expiryWarningDays * 86_400))
        return observed.compactMap { certificate in
            guard let notAfter = certificate.notAfter, notAfter > now, notAfter <= threshold else { return nil }
            guard let pin = matchedPins.first(where: {
                $0.role == certificate.role
                    && CertificateHash.normalised($0.sha256, encoding: $0.encoding) == certificate.sha256
            }) else { return nil }
            guard pin.state == .active || !hasActiveReplacement(for: pin) else { return nil }
            return .expiring(pinID: pin.id, role: certificate.role, notAfter: notAfter)
        }
    }

    private func hasActiveReplacement(for pin: CertificatePin) -> Bool {
        pins.contains { candidate in
            candidate.role == pin.role && candidate.state == .active
                && CertificateHash.normalised(candidate.sha256, encoding: candidate.encoding)
                    != CertificateHash.normalised(pin.sha256, encoding: pin.encoding)
        }
    }

    private func fail(_ message: String) {
        lock.withLock { storedTrustFailure = message }
    }
}

private enum TrustEvaluation {
    case success([CertificateWarning])
    case failure(String)
}

private struct ObservedCertificate {
    let role: CertificateRole
    let sha256: String
    let notAfter: Date?
}

private struct PinMatches {
    var active: [CertificatePin] = []
    var retiring: [CertificatePin] = []
    var retired: [CertificatePin] = []
}
