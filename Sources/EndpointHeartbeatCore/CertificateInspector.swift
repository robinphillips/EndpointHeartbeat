import Foundation
import Security

public struct CertificateInfo: Sendable {
    public let position: Int
    public let subject: String
    public let sha256: String
}

public enum CertificateInspector {
    public static func inspect(_ url: URL) async throws -> [CertificateInfo] {
        let delegate = InspectionDelegate()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        _ = try await session.data(from: url)
        return delegate.certificates
    }
}

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

        return chain.enumerated().map { index, certificate in
            CertificateInfo(
                position: index,
                subject: SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown",
                sha256: CertificateHash.sha256(of: certificate)
            )
        }
    }
}
