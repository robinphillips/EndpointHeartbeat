import Foundation

public struct CertificateInfo: Sendable {
    public let position: Int
    public let role: CertificateRole
    public let subject: String
    public let spkiSHA256Base64: String
    public let notBefore: Date?
    public let notAfter: Date?
}
