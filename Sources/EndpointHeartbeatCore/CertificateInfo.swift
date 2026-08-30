import Foundation

public struct CertificateInfo: Sendable {
    public let position: Int
    public let role: CertificateRole
    public let subject: String
    public let sha256: String
    public let notBefore: Date?
    public let notAfter: Date?
}
