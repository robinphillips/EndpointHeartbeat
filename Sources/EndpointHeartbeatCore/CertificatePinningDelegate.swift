import Foundation
import Security

final class CertificatePinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let expectedRootHash: String
    private let lock = NSLock()
    private var storedTrustFailure: String?

    init(expectedRootHash: String, encoding: CertificateHashEncoding) {
        self.expectedRootHash = CertificateHash.normalised(expectedRootHash, encoding: encoding)
    }

    var trustFailure: String? {
        lock.withLock { storedTrustFailure }
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

        if let failure = failureMessage(for: trust) {
            fail(failure)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func failureMessage(for trust: SecTrust) -> String? {
        var evaluationError: CFError?
        guard SecTrustEvaluateWithError(trust, &evaluationError) else {
            return evaluationError.map(String.init(describing:)) ?? "system trust evaluation failed"
        }

        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let root = chain.last else {
            return "evaluated certificate chain has no root"
        }

        let actualHash = CertificateHash.sha256(of: root)
        guard actualHash == expectedRootHash else {
            return "root SHA-256 was \(actualHash); expected \(expectedRootHash)"
        }

        return nil
    }

    private func fail(_ message: String) {
        lock.withLock { storedTrustFailure = message }
    }
}
