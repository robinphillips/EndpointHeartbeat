import CryptoKit
import Foundation
import Security

public enum CertificateHash {
    static func sha256(of certificate: SecCertificate) -> String {
        sha256(of: SecCertificateCopyData(certificate) as Data)
    }

    static func sha256(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return Data(digest).base64EncodedString()
    }

    static func isValid(_ hash: String) -> Bool {
        Data(base64Encoded: hash)?.count == 32
    }
}
