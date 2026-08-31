import Foundation
import Security

final class InspectionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var storedCertificates: [CertificateInfo] = []

    var certificates: [CertificateInfo] {
        lock.withLock { storedCertificates }
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

        guard let values = certificateInfo(for: trust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        lock.withLock { storedCertificates = values }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func certificateInfo(for trust: SecTrust) -> [CertificateInfo]? {
        SecTrustSetVerifyDate(trust, SystemClock.now as CFDate)
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error),
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {
            return nil
        }

        return chain.enumerated().compactMap { pair -> CertificateInfo? in
            let (index, certificate) = pair
            guard let spkiSHA256Base64 = SPKIHash.sha256Base64(of: certificate) else { return nil }
            return CertificateInfo(
                position: index,
                role: certificateRole(at: index, in: chain),
                subject: SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown",
                spkiSHA256Base64: spkiSHA256Base64,
                notBefore: certificateValidity(for: certificate).notBefore,
                notAfter: certificateValidity(for: certificate).notAfter
            )
        }
    }
}
