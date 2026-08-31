import Foundation

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
            guard names.insert(endpoint.name).inserted else { throw ConfigurationError.duplicateName(endpoint.name) }
            guard endpoint.url.scheme?.lowercased() == "https" else { throw ConfigurationError.nonHTTPSURL(endpoint.name) }
            guard !endpoint.certificates.isEmpty else { throw ConfigurationError.noCertificates(endpoint.name) }
            guard endpoint.certificateExpiryWarningDays >= 0 else {
                throw ConfigurationError.invalidExpiryWarningDays(endpoint.name)
            }
            guard !endpoint.acceptableStatusCodes.isEmpty else { throw ConfigurationError.noStatusCodes(endpoint.name) }
            guard endpoint.certificates.contains(where: { $0.state == .active }) else {
                throw ConfigurationError.noActiveCertificate(endpoint.name)
            }

            var ids = Set<String>()
            for certificate in endpoint.certificates {
                guard !certificate.id.isEmpty, ids.insert(certificate.id).inserted else {
                    throw ConfigurationError.duplicateCertificateID(endpoint: endpoint.name, id: certificate.id)
                }
                guard SPKIHash.isValidBase64(certificate.spkiSHA256Base64) else {
                    throw ConfigurationError.invalidHash(endpoint: endpoint.name, id: certificate.id)
                }
                guard certificate.state != .retiring || certificate.retireAfter != nil else {
                    throw ConfigurationError.missingRetirementDate(endpoint: endpoint.name, id: certificate.id)
                }
            }
        }
    }
}
