import CryptoKit
import Foundation
import Security

public enum CertificateHash {
    public static func normalised(_ hash: String, encoding: CertificateHashEncoding) -> String {
        guard let bytes = bytes(from: hash, encoding: encoding) else { return "" }
        return hexadecimalString(for: bytes)
    }

    static func sha256(of certificate: SecCertificate) -> String {
        sha256(of: SecCertificateCopyData(certificate) as Data)
    }

    static func sha256(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return hexadecimalString(for: digest)
    }

    static func encoded(_ hash: String, as encoding: CertificateHashEncoding) -> String {
        guard let bytes = bytes(from: hash, encoding: .hexadecimal) else { return "" }
        return switch encoding {
        case .hexadecimal: hexadecimalString(for: bytes)
        case .base64: bytes.base64EncodedString()
        }
    }

    private static func bytes(from hash: String, encoding: CertificateHashEncoding) -> Data? {
        let candidate = hash.trimmingCharacters(in: .whitespacesAndNewlines)

        switch encoding {
        case .hexadecimal:
            return hexadecimalBytes(from: candidate)
        case .base64:
            guard let base64Bytes = Data(base64Encoded: candidate), base64Bytes.count == 32 else {
                return nil
            }
            return base64Bytes
        }
    }

    private static func hexadecimalBytes(from hash: String) -> Data? {
        let components = hash.split(separator: ":", omittingEmptySubsequences: false)
        let compactHash: String

        if components.count == 1 {
            compactHash = hash
        } else {
            guard components.count == 32, components.allSatisfy({ $0.count == 2 }) else {
                return nil
            }
            compactHash = components.joined()
        }

        guard compactHash.utf8.count == 64,
              compactHash.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102)
              }) else {
            return nil
        }

        var bytes = Data()
        bytes.reserveCapacity(32)
        var index = compactHash.startIndex
        while index < compactHash.endIndex {
            let nextIndex = compactHash.index(index, offsetBy: 2)
            bytes.append(UInt8(compactHash[index..<nextIndex], radix: 16)!)
            index = nextIndex
        }
        return bytes
    }

    private static func hexadecimalString<S: Sequence>(for bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
