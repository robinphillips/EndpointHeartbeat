import CryptoKit
import Foundation
import Security

enum SPKIHash {
    static func sha256Base64(of certificate: SecCertificate) -> String? {
        let certificateData = SecCertificateCopyData(certificate) as Data
        guard let subjectPublicKeyInfo = DER.subjectPublicKeyInfo(in: certificateData) else { return nil }
        return sha256Base64(of: subjectPublicKeyInfo)
    }

    static func sha256Base64(of data: Data) -> String {
        Data(SHA256.hash(data: data)).base64EncodedString()
    }

    static func isValidBase64(_ hash: String) -> Bool {
        guard let decoded = Data(base64Encoded: hash), decoded.count == SHA256.Digest.byteCount else {
            return false
        }
        return decoded.base64EncodedString() == hash
    }
}

private enum DER {
    private struct Element {
        let tag: UInt8
        let contentRange: Range<Int>
        let range: Range<Int>
    }

    static func subjectPublicKeyInfo(in certificate: Data) -> Data? {
        guard let certificateElement = element(in: certificate, at: 0),
              certificateElement.tag == 0x30,
              certificateElement.range.upperBound == certificate.count,
              let tbsCertificate = children(of: certificateElement, in: certificate).first,
              tbsCertificate.tag == 0x30 else {
            return nil
        }

        let fields = children(of: tbsCertificate, in: certificate)
        let publicKeyIndex = fields.first?.tag == 0xA0 ? 6 : 5
        guard fields.indices.contains(publicKeyIndex), fields[publicKeyIndex].tag == 0x30 else {
            return nil
        }
        return certificate.subdata(in: fields[publicKeyIndex].range)
    }

    private static func children(of element: Element, in data: Data) -> [Element] {
        var elements: [Element] = []
        var offset = element.contentRange.lowerBound
        while offset < element.contentRange.upperBound {
            guard let child = self.element(in: data, at: offset), child.range.upperBound <= element.contentRange.upperBound else {
                return []
            }
            elements.append(child)
            offset = child.range.upperBound
        }
        return offset == element.contentRange.upperBound ? elements : []
    }

    private static func element(in data: Data, at offset: Int) -> Element? {
        guard data.indices.contains(offset), data.indices.contains(offset + 1) else { return nil }
        let tag = data[offset]
        let lengthByte = data[offset + 1]
        var contentOffset = offset + 2
        let length: Int

        if lengthByte & 0x80 == 0 {
            length = Int(lengthByte)
        } else {
            let byteCount = Int(lengthByte & 0x7F)
            guard byteCount > 0, byteCount <= MemoryLayout<Int>.size,
                  data.count - contentOffset >= byteCount else {
                return nil
            }
            var parsedLength = 0
            for _ in 0..<byteCount {
                let (multiplied, didOverflow) = parsedLength.multipliedReportingOverflow(by: 256)
                let (updated, didAddOverflow) = multiplied.addingReportingOverflow(Int(data[contentOffset]))
                guard !didOverflow, !didAddOverflow else { return nil }
                parsedLength = updated
                contentOffset += 1
            }
            length = parsedLength
        }

        let (endOffset, didOverflow) = contentOffset.addingReportingOverflow(length)
        guard !didOverflow, endOffset <= data.count else { return nil }
        return Element(tag: tag, contentRange: contentOffset..<endOffset, range: offset..<endOffset)
    }
}
