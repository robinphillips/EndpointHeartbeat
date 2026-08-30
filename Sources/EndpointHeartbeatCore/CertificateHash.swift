import CryptoKit
import Foundation
import Security

public enum CertificateHash {
    public static func normalised(_ hash: String) -> String {
        hash
            .filter(\.isHexDigit)
            .lowercased()
    }

    static func sha256(of certificate: SecCertificate) -> String {
        sha256(of: SecCertificateCopyData(certificate) as Data)
    }

    static func sha256(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
