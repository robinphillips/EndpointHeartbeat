import Foundation
import Security

func certificateRole(at position: Int, in chain: [SecCertificate]) -> CertificateRole {
    if position == chain.count - 1 { return .root }
    if position == 0 { return .leaf }
    return .intermediate
}

func certificateValidity(for certificate: SecCertificate) -> (notBefore: Date?, notAfter: Date?) {
    #if os(macOS)
    let keys = [kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
    guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any] else {
        return (nil, nil)
    }
    return (
        certificateDate(from: values[kSecOIDX509V1ValidityNotBefore as String]),
        certificateDate(from: values[kSecOIDX509V1ValidityNotAfter as String])
    )
    #else
    return certificateValidity(in: SecCertificateCopyData(certificate) as Data)
    #endif
}

#if os(macOS)
private func certificateDate(from value: Any?) -> Date? {
    guard let property = value as? [String: Any], let rawValue = property[kSecPropertyKeyValue as String] else {
        return nil
    }
    if let date = rawValue as? Date { return date }
    guard let referenceInterval = rawValue as? TimeInterval else { return nil }
    return Date(timeIntervalSinceReferenceDate: referenceInterval)
}
#endif

func certificateValidity(in certificateData: Data) -> (notBefore: Date?, notAfter: Date?) {
    var certificateReader = DERReader(data: certificateData)
    guard let certificate = certificateReader.readElement(tag: 0x30) else {
        return (nil, nil)
    }

    var certificateContents = DERReader(bytes: certificate.contents)
    guard let tbsCertificate = certificateContents.readElement(tag: 0x30) else {
        return (nil, nil)
    }

    var tbsContents = DERReader(bytes: tbsCertificate.contents)
    if tbsContents.nextTag == 0xA0, tbsContents.readElement(tag: 0xA0) == nil {
        return (nil, nil)
    }
    guard
        tbsContents.readElement(tag: 0x02) != nil,
        tbsContents.readElement(tag: 0x30) != nil,
        tbsContents.readElement(tag: 0x30) != nil,
        let validity = tbsContents.readElement(tag: 0x30)
    else {
        return (nil, nil)
    }

    var validityContents = DERReader(bytes: validity.contents)
    guard
        let notBefore = validityContents.readElement(),
        let notAfter = validityContents.readElement()
    else {
        return (nil, nil)
    }
    return (certificateDate(from: notBefore), certificateDate(from: notAfter))
}

private func certificateDate(from element: DERElement) -> Date? {
    guard element.tag == 0x17 || element.tag == 0x18, let value = String(bytes: element.contents, encoding: .ascii) else {
        return nil
    }

    let expectedLength = element.tag == 0x17 ? 13 : 15
    guard value.count == expectedLength, value.last == "Z" else { return nil }
    let digits = value.dropLast()
    guard digits.allSatisfy(\.isNumber) else { return nil }

    let year: Int?
    let remainder: Substring
    if element.tag == 0x17 {
        year = Int(digits.prefix(2)).map { $0 >= 50 ? 1900 + $0 : 2000 + $0 }
        remainder = digits.dropFirst(2)
    } else {
        year = Int(digits.prefix(4))
        remainder = digits.dropFirst(4)
    }
    guard
        let year,
        let month = Int(remainder.prefix(2)),
        let day = Int(remainder.dropFirst(2).prefix(2)),
        let hour = Int(remainder.dropFirst(4).prefix(2)),
        let minute = Int(remainder.dropFirst(6).prefix(2)),
        let second = Int(remainder.dropFirst(8).prefix(2))
    else {
        return nil
    }

    var components = DateComponents()
    components.calendar = Calendar(identifier: .gregorian)
    components.timeZone = TimeZone(secondsFromGMT: 0)
    components.year = year
    components.month = month
    components.day = day
    components.hour = hour
    components.minute = minute
    components.second = second
    return components.date
}

private struct DERReader {
    private let bytes: [UInt8]
    private(set) var index = 0

    init(data: Data) {
        self.init(bytes: Array(data))
    }

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var nextTag: UInt8? {
        bytes.indices.contains(index) ? bytes[index] : nil
    }

    mutating func readElement(tag expectedTag: UInt8? = nil) -> DERElement? {
        guard let tag = nextByte(), expectedTag == nil || tag == expectedTag, let length = readLength() else {
            return nil
        }
        let endIndex = index + length
        guard endIndex <= bytes.count else { return nil }
        defer { index = endIndex }
        return DERElement(tag: tag, contents: Array(bytes[index..<endIndex]))
    }

    private mutating func nextByte() -> UInt8? {
        guard bytes.indices.contains(index) else { return nil }
        defer { index += 1 }
        return bytes[index]
    }

    private mutating func readLength() -> Int? {
        guard let firstByte = nextByte() else { return nil }
        guard firstByte & 0x80 != 0 else { return Int(firstByte) }

        let byteCount = Int(firstByte & 0x7F)
        guard byteCount > 0, byteCount <= MemoryLayout<Int>.size, bytes.count - index >= byteCount else {
            return nil
        }

        var length = 0
        for _ in 0..<byteCount {
            guard let byte = nextByte() else { return nil }
            length = (length << 8) | Int(byte)
        }
        return length
    }
}

private struct DERElement {
    let tag: UInt8
    let contents: [UInt8]
}
