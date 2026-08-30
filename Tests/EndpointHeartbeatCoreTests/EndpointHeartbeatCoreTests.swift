import Foundation
@testable import EndpointHeartbeatCore
import Security
import Testing

struct EndpointHeartbeatCoreTests {
    @Test("certificate hashes normalize strict hexadecimal and Base64 encodings")
    func normalisesCertificateHashes() {
        let hexadecimal = "aabb" + String(repeating: "01", count: 30)
        let colonSeparated = (["AA", "bb"] + Array(repeating: "01", count: 30)).joined(separator: ":")

        #expect(CertificateHash.normalised(colonSeparated) == hexadecimal)
        #expect(CertificateHash.normalised("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(CertificateHash.normalised("00:11:invalid") == "")
    }

    @Test("certificate data produces a lowercase SHA-256 hash")
    func hashesCertificateData() {
        #expect(CertificateHash.sha256(of: Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test("decoded endpoints receive omitted defaults")
    func suppliesConfigurationDefaults() throws {
        let json = """
        {"endpoints":[{"name":"API","url":"https://example.com","rootSHA256":"\(String(repeating: "0", count: 64))"}]}
        """
        let configuration = try JSONDecoder().decode(HeartbeatConfiguration.self, from: Data(json.utf8))
        #expect(configuration.endpoints[0].expectedOutcome == .success)
        #expect(configuration.endpoints[0].acceptableStatusCodes == Array(200..<300))
    }

    @Test("trust expectations do not accept transport failures")
    func expectedTrustFailureDoesNotHideTransportFailure() {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://example.com")!,
            rootSHA256: String(repeating: "0", count: 64),
            expectedOutcome: .trustFailure
        )
        #expect(CheckResult(endpoint: endpoint, observedOutcome: .trustFailure("mismatch")).passed)
        #expect(!CheckResult(endpoint: endpoint, observedOutcome: .transportFailure("timeout")).passed)
    }

    @Test("duplicate endpoint names are rejected")
    func rejectsDuplicateNames() {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://example.com")!,
            rootSHA256: String(repeating: "0", count: 64)
        )
        #expect(throws: ConfigurationError.self) {
            try ConfigurationLoader.validate(.init(endpoints: [endpoint, endpoint]))
        }
    }

    @Test(arguments: [
        ("http://example.com", ConfigurationError.nonHTTPSURL("API")),
        ("https://example.com", ConfigurationError.invalidHash("API"))
    ])
    func rejectsInvalidEndpointConfiguration(
        urlString: String,
        expectedError: ConfigurationError
    ) {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: urlString)!,
            rootSHA256: urlString.hasPrefix("https") ? "invalid" : String(repeating: "0", count: 64)
        )

        #expect(throws: ConfigurationError.self) {
            try ConfigurationLoader.validate(.init(endpoints: [endpoint]))
        }
        #expect(expectedError.description.isEmpty == false)
    }

    @Test("empty endpoint lists and status code lists are rejected")
    func rejectsEmptyConfigurationValues() {
        #expect(throws: ConfigurationError.self) {
            try ConfigurationLoader.validate(.init(endpoints: []))
        }

        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://example.com")!,
            rootSHA256: String(repeating: "0", count: 64),
            acceptableStatusCodes: []
        )
        #expect(throws: ConfigurationError.self) {
            try ConfigurationLoader.validate(.init(endpoints: [endpoint]))
        }
    }

    @Test(arguments: [
        (ObservedOutcome.success(statusCode: 204), "HTTP 204"),
        (ObservedOutcome.trustFailure("mismatch"), "trust failure: mismatch"),
        (ObservedOutcome.httpFailure(statusCode: 503), "unexpected HTTP 503"),
        (ObservedOutcome.transportFailure("offline"), "transport failure: offline")
    ])
    func describesObservedOutcomes(outcome: ObservedOutcome, description: String) {
        #expect(outcome.description == description)
    }

    @Test("HTTP checks classify accepted, rejected, non-HTTP, and transport responses")
    func classifiesHeartbeatResponses() async {
        let cases: [(String, ObservedOutcome)] = [
            ("https://success.test", .success(statusCode: 204)),
            ("https://failure.test", .httpFailure(statusCode: 503)),
            ("https://nonhttp.test", .transportFailure("response was not HTTP"))
        ]

        for (urlString, expectedOutcome) in cases {
            let result = await Heartbeat.check(endpoint(for: urlString), sessionConfiguration: mockSessionConfiguration())
            #expect(result.observedOutcome == expectedOutcome)
        }

        let transportResult = await Heartbeat.check(
            endpoint(for: "https://transport.test"),
            sessionConfiguration: mockSessionConfiguration()
        )
        if case let .transportFailure(message) = transportResult.observedOutcome {
            #expect(!message.isEmpty)
        } else {
            Issue.record("expected a transport failure")
        }
    }

    @Test("checks complete concurrently and preserve input ordering")
    func checksAllEndpointsInInputOrder() async {
        let endpoints = [endpoint(for: "https://failure.test"), endpoint(for: "https://success.test")]
        let results = await Heartbeat.checkAll(endpoints)

        #expect(results.map(\.endpoint.name) == endpoints.map(\.name))
    }

    @Test("non-server-trust challenges use default handling")
    func delegatesNonTrustChallengesToDefaultHandling() async {
        let delegates: [URLSessionDelegate] = [
            InspectionDelegate(),
            CertificatePinningDelegate(expectedRootHash: String(repeating: "0", count: 64))
        ]
        for delegate in delegates {
            let result = await challengeResult(for: delegate)
            #expect(result.disposition == .performDefaultHandling)
            #expect(result.credential == nil)
        }
    }

    @Test("server-trust challenges accept matching roots and reject mismatches")
    func handlesServerTrustChallenges() async throws {
        let certificate = try testCertificate()
        let trust = try trustedTrust(for: certificate)
        let expectedHash = CertificateHash.sha256(of: certificate)

        let matchingDelegate = CertificatePinningDelegate(expectedRootHash: expectedHash)
        #expect(matchingDelegate.failureMessage(for: trust) == nil)

        let mismatchingDelegate = CertificatePinningDelegate(expectedRootHash: String(repeating: "0", count: 64))
        #expect(mismatchingDelegate.failureMessage(for: trust)?.contains("root SHA-256") == true)
    }

    @Test("inspection delegates retain evaluated certificate metadata")
    func recordsInspectedCertificates() async throws {
        let certificate = try testCertificate()
        let trust = try trustedTrust(for: certificate)
        let delegate = InspectionDelegate()

        let certificates = try #require(delegate.certificateInfo(for: trust))

        #expect(certificates.count == 1)
        #expect(certificates[0].position == 0)
        #expect(certificates[0].subject == "example.com")
        #expect(certificates[0].sha256 == CertificateHash.sha256(of: certificate))
    }

    private func endpoint(for urlString: String) -> Endpoint {
        Endpoint(
            name: urlString,
            url: URL(string: urlString)!,
            rootSHA256: String(repeating: "0", count: 64),
            acceptableStatusCodes: [204]
        )
    }

    private func mockSessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return configuration
    }

    private func challengeResult(for delegate: URLSessionDelegate) async -> ChallengeResult {
        await withCheckedContinuation { continuation in
            let protectionSpace = URLProtectionSpace(
                host: "example.com",
                port: 443,
                protocol: "https",
                realm: nil,
                authenticationMethod: NSURLAuthenticationMethodHTTPBasic
            )
            let challenge = URLAuthenticationChallenge(
                protectionSpace: protectionSpace,
                proposedCredential: nil,
                previousFailureCount: 0,
                failureResponse: nil,
                error: nil,
                sender: ChallengeSender()
            )
            delegate.urlSession!(URLSession.shared, didReceive: challenge) { disposition, credential in
                continuation.resume(returning: ChallengeResult(disposition: disposition, credential: credential))
            }
        }
    }

    private func testCertificate() throws -> SecCertificate {
        let der = try #require(Data(base64Encoded: """
        MIIDDTCCAfWgAwIBAgIUTUsP1h40Bpb4wsJjO/BbMcRWfxIwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYwODMwMDQxNzEzWhcNMjYwODMxMDQxNzEzWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmnrybCYK27d9JlLirElXJjlJJgbtoMcQ8rSMylQi21+Xx6FJH+e3XjwzMH8pBW/aif+u3Wj5HAwWJihXeP6gOfMBrV2qRgKAhGwP/BinnEWcbNLx4FrWjPVUSt8Yv0goCDdGXsJmWXoyvhxLtgOWgy6/ld0pAti0BKPzW7Ekcx7t4U3e1ddsenYG053ljd7qWtytdvoOTo/Iu5rtp0+t6SCKmzez6/YKtKVvlwFIYhRuzK/oZ/oPXrW3BhL/wAAMvvedxQFqgCKoxiaTNGvPqWyPV/AK1m15RR47eLDnCntskRBY7w9ncKZll9hHLTy4iv8EFGESewmi/oaZRXquUCAwEAAaNTMFEwHQYDVR0OBBYEFBAzOImVO4WFRS5xsiMuNBPPom2IMB8GA1UdIwQYMBaAFBAzOImVO4WFRS5xsiMuNBPPom2IMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACVd1/cqJURaM1p/2w+r1OSAg+/WD2ZJDP2QY+KMuijhLcfd653F/t26mUwm3JxSxMk4pfSQFuGkZK9nymr3A3qAP/NImruev8Z8uNVdt/VyF377ve4tT0O34M+YwMhcOSrrmFzmrCqmg6TxoSWtvnJoJ2+ujA5H1gLChjlfjBgr6TdwRbswiSnUOwX5RqgD7SAVncSTrZ4I/CGq0b3v1vAebeHj3BX32Y59I5LARXTrlrC4XsoBdkP4yqDOEIQMUPWFKKYJuWf3l4liiFTNMlhp5wrU91JGJK0+CVHLEDPdecgWNLVosTTy/XkZUJtnLGKnVtweE4v2p2a/GYQX2M0=
        """))
        return try #require(SecCertificateCreateWithData(nil, der as CFData))
    }

    private func trustedTrust(for certificate: SecCertificate) throws -> SecTrust {
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust)
        try #require(status == errSecSuccess)
        let evaluatedTrust = try #require(trust)
        try #require(SecTrustSetAnchorCertificates(evaluatedTrust, [certificate] as CFArray) == errSecSuccess)
        try #require(SecTrustSetAnchorCertificatesOnly(evaluatedTrust, true) == errSecSuccess)
        return evaluatedTrust
    }
}

private struct ChallengeResult: @unchecked Sendable {
    let disposition: URLSession.AuthChallengeDisposition
    let credential: URLCredential?
}

private final class ChallengeSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}

    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}

    func cancel(_ challenge: URLAuthenticationChallenge) {}
}

private final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        switch request.url!.host! {
        case "success.test", "failure.test":
            let statusCode = request.url!.host == "success.test" ? 204 : 503
            let response = HTTPURLResponse(url: request.url!, statusCode: statusCode, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        case "nonhttp.test":
            client?.urlProtocol(self, didReceive: URLResponse(url: request.url!, mimeType: nil, expectedContentLength: 0, textEncodingName: nil), cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        default:
            client?.urlProtocol(self, didFailWithError: NSError(domain: "EndpointHeartbeatCoreTests.MockURLProtocol", code: 1))
        }
    }

    override func stopLoading() {}
}
