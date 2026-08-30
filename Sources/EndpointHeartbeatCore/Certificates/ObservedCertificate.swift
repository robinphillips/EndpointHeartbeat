import Foundation

struct ObservedCertificate {
    let role: CertificateRole
    let sha256: String
    let notAfter: Date?
}
