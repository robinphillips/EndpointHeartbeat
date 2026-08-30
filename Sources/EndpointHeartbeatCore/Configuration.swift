import Foundation

public struct HeartbeatConfiguration: Codable, Sendable {
    public let endpoints: [Endpoint]

    public init(endpoints: [Endpoint]) {
        self.endpoints = endpoints
    }
}

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

    public init(
        name: String,
        url: URL,
        rootSHA256: String,
        rootSHA256Encoding: CertificateHashEncoding = .hexadecimal,
        expectedOutcome: ExpectedOutcome = .success,
        acceptableStatusCodes: [Int] = Array(200..<300)
    ) {
        self.init(
            name: name,
            url: url,
            certificates: [.init(id: "root", role: .root, sha256: rootSHA256, encoding: rootSHA256Encoding)],
            expectedOutcome: expectedOutcome,
            acceptableStatusCodes: acceptableStatusCodes
        )
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

public struct CertificatePin: Codable, Sendable, Equatable {
    public let id: String
    public let role: CertificateRole
    public let sha256: String
    public let encoding: CertificateHashEncoding
    public let state: CertificatePinState
    public let retireAfter: Date?

    public init(
        id: String,
        role: CertificateRole,
        sha256: String,
        encoding: CertificateHashEncoding,
        state: CertificatePinState = .active,
        retireAfter: Date? = nil
    ) {
        self.id = id
        self.role = role
        self.sha256 = sha256
        self.encoding = encoding
        self.state = state
        self.retireAfter = retireAfter
    }

    private enum CodingKeys: String, CodingKey {
        case id, role, sha256, encoding, state, retireAfter
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        role = try values.decode(CertificateRole.self, forKey: .role)
        sha256 = try values.decode(String.self, forKey: .sha256)
        encoding = try values.decode(CertificateHashEncoding.self, forKey: .encoding)
        state = try values.decodeIfPresent(CertificatePinState.self, forKey: .state) ?? .active
        retireAfter = try values.decodeIfPresent(Date.self, forKey: .retireAfter)
    }
}

public enum CertificateRole: String, Codable, Sendable {
    case leaf
    case intermediate
    case root
}

public enum CertificatePinState: String, Codable, Sendable {
    case active
    case retiring
}

public enum ExpectedOutcome: String, Codable, Sendable {
    case success
    case trustFailure
}

public enum CertificateHashEncoding: String, Codable, Sendable {
    case hexadecimal
    case base64
}

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
        case let .invalidHash(endpoint, id): "certificate pin SHA-256 is invalid for \(endpoint): \(id)"
        case let .noActiveCertificate(name): "endpoint has no active certificate pin: \(name)"
        case let .missingRetirementDate(endpoint, id): "retiring certificate pin has no retireAfter date for \(endpoint): \(id)"
        case let .invalidExpiryWarningDays(name): "certificateExpiryWarningDays must not be negative: \(name)"
        case let .noStatusCodes(name): "acceptableStatusCodes is empty: \(name)"
        }
    }
}

public enum ConfigurationLoader {
    public static func load(from fileURL: URL) throws -> HeartbeatConfiguration {
        let data = try Data(contentsOf: fileURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let configuration = try decoder.decode(HeartbeatConfiguration.self, from: data)
        try validate(configuration)
        return configuration
    }

    public static func validate(_ configuration: HeartbeatConfiguration) throws {
        guard !configuration.endpoints.isEmpty else { throw ConfigurationError.empty }

        var names = Set<String>()
        for endpoint in configuration.endpoints {
            guard names.insert(endpoint.name).inserted else {
                throw ConfigurationError.duplicateName(endpoint.name)
            }
            guard endpoint.url.scheme?.lowercased() == "https" else {
                throw ConfigurationError.nonHTTPSURL(endpoint.name)
            }
            guard !endpoint.certificates.isEmpty else { throw ConfigurationError.noCertificates(endpoint.name) }
            guard endpoint.certificateExpiryWarningDays >= 0 else {
                throw ConfigurationError.invalidExpiryWarningDays(endpoint.name)
            }
            guard !endpoint.acceptableStatusCodes.isEmpty else {
                throw ConfigurationError.noStatusCodes(endpoint.name)
            }
            guard endpoint.certificates.contains(where: { $0.state == .active }) else {
                throw ConfigurationError.noActiveCertificate(endpoint.name)
            }

            var ids = Set<String>()
            for certificate in endpoint.certificates {
                guard !certificate.id.isEmpty, ids.insert(certificate.id).inserted else {
                    throw ConfigurationError.duplicateCertificateID(endpoint: endpoint.name, id: certificate.id)
                }
                guard !CertificateHash.normalised(certificate.sha256, encoding: certificate.encoding).isEmpty else {
                    throw ConfigurationError.invalidHash(endpoint: endpoint.name, id: certificate.id)
                }
                guard certificate.state != .retiring || certificate.retireAfter != nil else {
                    throw ConfigurationError.missingRetirementDate(endpoint: endpoint.name, id: certificate.id)
                }
            }
        }
    }
}
