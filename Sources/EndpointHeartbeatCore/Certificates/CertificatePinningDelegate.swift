import Foundation
import Security

final class CertificatePinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pins: [CertificatePin]
    private let expiryWarningDays: Int
    private let lock = NSLock()
    private var storedTrustFailure: String?
    private var storedWarnings: [CertificateWarning] = []
    private var storedCertificates: [ObservedCertificate] = []

    init(pins: [CertificatePin], expiryWarningDays: Int) {
        self.pins = pins
        self.expiryWarningDays = expiryWarningDays
    }

    convenience init(expectedRootHash: String) {
        self.init(
            pins: [.init(id: "root", role: .root, spkiSHA256Base64: expectedRootHash)],
            expiryWarningDays: 30
        )
    }

    var trustFailure: String? { lock.withLock { storedTrustFailure } }

    var warnings: [CertificateWarning] { lock.withLock { storedWarnings } }

    func observedCertificate(for role: CertificateRole) -> ObservedCertificate? {
        lock.withLock { storedCertificates.first { $0.role == role } }
    }

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

        let observed = chain.enumerated().compactMap { pair -> ObservedCertificate? in
            let (index, certificate) = pair
            guard let spkiSHA256Base64 = SPKIHash.sha256Base64(of: certificate) else { return nil }
            return ObservedCertificate(
                role: certificateRole(at: index, in: chain),
                spkiSHA256Base64: spkiSHA256Base64,
                notBefore: certificateValidity(for: certificate).notBefore,
                notAfter: certificateValidity(for: certificate).notAfter
            )
        }
        guard observed.count == chain.count else {
            return .failure("could not extract SubjectPublicKeyInfo from evaluated certificate chain")
        }
        lock.withLock { storedCertificates = observed }
        let matches = matchingPins(in: observed, now: now)
        if !matches.active.isEmpty {
            return .success(expiryWarnings(for: observed, matchedPins: matches.active + matches.retiring, now: now))
        }
        if let retired = matches.retired.first {
            return .failure("certificate pin \(retired.id) retired on \(ISO8601DateFormatter().string(from: retired.retireAfter!))")
        }
        guard !matches.retiring.isEmpty else {
            let actual = observedHashes(in: observed).joined(separator: "; ")
            return .failure("no configured certificate pin matched: \(actual)")
        }

        return .success(expiryWarnings(for: observed, matchedPins: matches.retiring, now: now))
    }

    private func matchingPins(in observed: [ObservedCertificate], now: Date) -> PinMatches {
        var matches = PinMatches()
        for pin in pins {
            guard observed.contains(where: { $0.role == pin.role && $0.spkiSHA256Base64 == pin.spkiSHA256Base64 }) else { continue }
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
                    && $0.spkiSHA256Base64 == certificate.spkiSHA256Base64
            }) else { return nil }
            guard pin.state == .active || !hasActiveReplacement(for: pin) else { return nil }
            return .expiring(pinID: pin.id, role: certificate.role, notAfter: notAfter)
        }
    }

    private func hasActiveReplacement(for pin: CertificatePin) -> Bool {
        pins.contains { candidate in
            candidate.role == pin.role && candidate.state == .active
                    && candidate.spkiSHA256Base64 != pin.spkiSHA256Base64
        }
    }

    private func observedHashes(in observed: [ObservedCertificate]) -> [String] {
        var reported = Set<String>()
        return pins.flatMap { pin in
            observed.filter { $0.role == pin.role }.compactMap { certificate in
                let value = "\(pin.role.rawValue) SPKI SHA-256 was \(certificate.spkiSHA256Base64)"
                return reported.insert(value).inserted ? value : nil
            }
        }
    }

    private func fail(_ message: String) {
        lock.withLock { storedTrustFailure = message }
    }
}
