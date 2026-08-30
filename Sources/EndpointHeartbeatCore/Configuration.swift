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
    public let rootSHA256: String
    public let rootSHA256Encoding: CertificateHashEncoding
    public let expectedOutcome: ExpectedOutcome
    public let acceptableStatusCodes: [Int]

    public init(
        name: String,
        url: URL,
        rootSHA256: String,
        rootSHA256Encoding: CertificateHashEncoding = .hexadecimal,
        expectedOutcome: ExpectedOutcome = .success,
        acceptableStatusCodes: [Int] = Array(200..<300)
    ) {
        self.name = name
        self.url = url
        self.rootSHA256 = rootSHA256
        self.rootSHA256Encoding = rootSHA256Encoding
        self.expectedOutcome = expectedOutcome
        self.acceptableStatusCodes = acceptableStatusCodes
    }

    private enum CodingKeys: String, CodingKey {
        case name, url, rootSHA256, rootSHA256Encoding, expectedOutcome, acceptableStatusCodes
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        url = try values.decode(URL.self, forKey: .url)
        rootSHA256 = try values.decode(String.self, forKey: .rootSHA256)
        rootSHA256Encoding = try values.decode(CertificateHashEncoding.self, forKey: .rootSHA256Encoding)
        expectedOutcome = try values.decodeIfPresent(ExpectedOutcome.self, forKey: .expectedOutcome) ?? .success
        acceptableStatusCodes = try values.decodeIfPresent([Int].self, forKey: .acceptableStatusCodes) ?? Array(200..<300)
    }
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
    case invalidHash(String)
    case noStatusCodes(String)

    public var description: String {
        switch self {
        case .empty: "configuration contains no endpoints"
        case let .duplicateName(name): "endpoint name is duplicated: \(name)"
        case let .nonHTTPSURL(name): "endpoint must use HTTPS: \(name)"
        case let .invalidHash(name): "rootSHA256 must be a SHA-256 hash encoded as hexadecimal or Base64: \(name)"
        case let .noStatusCodes(name): "acceptableStatusCodes is empty: \(name)"
        }
    }
}

public enum ConfigurationLoader {
    public static func load(from fileURL: URL) throws -> HeartbeatConfiguration {
        let data = try Data(contentsOf: fileURL)
        let configuration = try JSONDecoder().decode(HeartbeatConfiguration.self, from: data)
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
            guard !CertificateHash.normalised(endpoint.rootSHA256, encoding: endpoint.rootSHA256Encoding).isEmpty else {
                throw ConfigurationError.invalidHash(endpoint.name)
            }
            guard !endpoint.acceptableStatusCodes.isEmpty else {
                throw ConfigurationError.noStatusCodes(endpoint.name)
            }
        }
    }
}
