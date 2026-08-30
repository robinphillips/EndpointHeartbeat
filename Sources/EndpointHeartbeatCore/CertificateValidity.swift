import Foundation
import Security

func certificateRole(at position: Int, in chain: [SecCertificate]) -> CertificateRole {
    if position == chain.count - 1 { return .root }
    if position == 0 { return .leaf }
    return .intermediate
}

func certificateValidity(for certificate: SecCertificate) -> (notBefore: Date?, notAfter: Date?) {
    let keys = [kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
    guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any] else {
        return (nil, nil)
    }
    return (
        certificateDate(from: values[kSecOIDX509V1ValidityNotBefore as String]),
        certificateDate(from: values[kSecOIDX509V1ValidityNotAfter as String])
    )
}

private func certificateDate(from value: Any?) -> Date? {
    guard let property = value as? [String: Any], let rawValue = property[kSecPropertyKeyValue as String] else {
        return nil
    }
    if let date = rawValue as? Date { return date }
    guard let referenceInterval = rawValue as? TimeInterval else { return nil }
    return Date(timeIntervalSinceReferenceDate: referenceInterval)
}
