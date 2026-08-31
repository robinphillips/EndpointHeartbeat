import Foundation

struct ObservedCertificate {
    let role: CertificateRole
    let spkiSHA256Base64: String
    let notAfter: Date?
}
