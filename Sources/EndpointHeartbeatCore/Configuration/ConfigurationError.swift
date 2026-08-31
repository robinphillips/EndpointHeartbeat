public enum ConfigurationError: Error, CustomStringConvertible {
    case empty
    case duplicateName(String)
    case nonHTTPSURL(String)
    case noCertificates(String)
    case duplicateCertificateID(endpoint: String, id: String)
    case invalidHash(endpoint: String, id: String)
    case noActiveCertificate(String)
    case missingRetirementDate(endpoint: String, id: String)
    case invalidExpiryWarningDays(String)
    case noStatusCodes(String)

    public var description: String {
        switch self {
        case .empty: "configuration contains no endpoints"
        case let .duplicateName(name): "endpoint name is duplicated: \(name)"
        case let .nonHTTPSURL(name): "endpoint must use HTTPS: \(name)"
        case let .noCertificates(name): "endpoint has no certificate pins: \(name)"
        case let .duplicateCertificateID(endpoint, id): "certificate pin ID is duplicated for \(endpoint): \(id)"
        case let .invalidHash(endpoint, id): "certificate pin SPKI SHA-256 must be Base64-encoded for \(endpoint): \(id)"
        case let .noActiveCertificate(name): "endpoint has no active certificate pin: \(name)"
        case let .missingRetirementDate(endpoint, id): "retiring certificate pin has no retireAfter date for \(endpoint): \(id)"
        case let .invalidExpiryWarningDays(name): "certificateExpiryWarningDays must not be negative: \(name)"
        case let .noStatusCodes(name): "acceptableStatusCodes is empty: \(name)"
        }
    }
}
