import Foundation

public struct Endpoint: Codable, Sendable {
    public let name: String
    public let url: URL
    public let certificates: [CertificatePin]
    public let expectedOutcome: ExpectedOutcome
    public let acceptableStatusCodes: [Int]
    public let certificateExpiryWarningDays: Int

    public init(
        name: String,
        url: URL,
        certificates: [CertificatePin],
        expectedOutcome: ExpectedOutcome = .success,
        acceptableStatusCodes: [Int] = Array(200..<300),
        certificateExpiryWarningDays: Int = 30
    ) {
        self.name = name
        self.url = url
        self.certificates = certificates
        self.expectedOutcome = expectedOutcome
        self.acceptableStatusCodes = acceptableStatusCodes
        self.certificateExpiryWarningDays = certificateExpiryWarningDays
    }

    private enum CodingKeys: String, CodingKey {
        case name, url, certificates, expectedOutcome, acceptableStatusCodes, certificateExpiryWarningDays
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        url = try values.decode(URL.self, forKey: .url)
        certificates = try values.decode([CertificatePin].self, forKey: .certificates)
        expectedOutcome = try values.decodeIfPresent(ExpectedOutcome.self, forKey: .expectedOutcome) ?? .success
        acceptableStatusCodes = try values.decodeIfPresent([Int].self, forKey: .acceptableStatusCodes) ?? Array(200..<300)
        certificateExpiryWarningDays = try values.decodeIfPresent(Int.self, forKey: .certificateExpiryWarningDays) ?? 30
    }
}
