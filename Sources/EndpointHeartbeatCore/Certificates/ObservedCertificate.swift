import Foundation

public struct ObservedCertificate: Codable, Sendable {
    public let role: CertificateRole
    public let spkiSHA256Base64: String
    public let notBefore: Date?
    public let notAfter: Date?

    init(
        role: CertificateRole,
        spkiSHA256Base64: String,
        notBefore: Date?,
        notAfter: Date?
    ) {
        self.role = role
        self.spkiSHA256Base64 = spkiSHA256Base64
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}
