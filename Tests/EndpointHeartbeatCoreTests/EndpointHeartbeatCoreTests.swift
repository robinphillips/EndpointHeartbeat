import Foundation
@_spi(TestSupport) @testable import EndpointHeartbeatCore
import Security
import Testing

struct EndpointHeartbeatCoreTests {
    @Test("SPKI hashes require a 32-byte Base64 value")
    func validatesBase64SPKIHashes() {
        #expect(SPKIHash.isValidBase64("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="))
        #expect(!SPKIHash.isValidBase64("00:11:invalid"))
        #expect(!SPKIHash.isValidBase64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
    }

    @Test("SPKI data produces a Base64 SHA-256 hash")
    func hashesSPKIData() {
        #expect(SPKIHash.sha256Base64(of: Data("abc".utf8)) == "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")
    }

    @Test("certificate SPKI hashing matches OpenSSL")
    func hashesCertificateSubjectPublicKeyInfo() throws {
        let certificate = try testCertificate()
        #expect(SPKIHash.sha256Base64(of: certificate) == "OExZh9XLBdCoTDwhT3cJ/9u3L6rgKOK7JrzNCXUcW4Q=")
    }

    @Test("decoded endpoints receive omitted defaults")
    func suppliesConfigurationDefaults() throws {
        let json = """
        {"endpoints":[{"name":"API","url":"https://example.com","certificates":[{"id":"root","role":"root","spkiSHA256Base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}]}
        """
        let configuration = try JSONDecoder().decode(HeartbeatConfiguration.self, from: Data(json.utf8))
        #expect(configuration.endpoints[0].certificates[0].expectedOutcome == .success)
        #expect(configuration.endpoints[0].acceptableStatusCodes == Array(200..<300))
    }

    @Test("decoded endpoints require explicit SPKI Base64 keys")
    func requiresExplicitSPKIBase64Key() throws {
        let json = """
        {"endpoints":[{"name":"API","url":"https://example.com","certificates":[{"id":"root","role":"root","spkiSHA256Base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}]}
        """
        _ = try JSONDecoder().decode(HeartbeatConfiguration.self, from: Data(json.utf8))
    }

    @Test("trust expectations do not accept transport failures")
    func expectedTrustFailureDoesNotHideTransportFailure() {
        let pin = rootPin(expectedOutcome: .trustFailure)
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://example.com")!,
            certificates: [pin]
        )
        #expect(CheckResult(endpoint: endpoint, pin: pin, observedOutcome: .trustFailure("mismatch")).passed)
        #expect(!CheckResult(endpoint: endpoint, pin: pin, observedOutcome: .transportFailure("timeout")).passed)
    }

    @Test("duplicate endpoint names are rejected")
    func rejectsDuplicateNames() {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://example.com")!,
            certificates: [rootPin()]
        )
        #expect(throws: ConfigurationError.self) {
            try ConfigurationLoader.validate(.init(endpoints: [endpoint, endpoint]))
        }
    }

    @Test(arguments: [
        ("http://example.com", ConfigurationError.nonHTTPSURL("API")),
        ("https://example.com", ConfigurationError.invalidHash(endpoint: "API", id: "root"))
    ])
    func rejectsInvalidEndpointConfiguration(
        urlString: String,
        expectedError: ConfigurationError
    ) {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: urlString)!,
            certificates: [rootPin(urlString.hasPrefix("https") ? "invalid" : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
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
            certificates: [rootPin()],
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
            let endpoint = endpoint(for: urlString)
            let result = await Heartbeat.check(
                endpoint,
                pin: endpoint.certificates[0],
                sessionConfiguration: mockSessionConfiguration()
            )
            #expect(result.observedOutcome == expectedOutcome)
        }

        let transportEndpoint = endpoint(for: "https://transport.test")
        let transportResult = await Heartbeat.check(
            transportEndpoint,
            pin: transportEndpoint.certificates[0],
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

    @Test("each pin has an independent expected outcome")
    func checksEachPinIndependently() async {
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://success.test")!,
            certificates: [
                .init(
                    id: "expected-trust-failure",
                    role: .root,
                    spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    expectedOutcome: .trustFailure
                ),
                .init(
                    id: "expected-success",
                    role: .root,
                    spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                )
            ],
            acceptableStatusCodes: [204]
        )

        let results = await Heartbeat.checkAll([endpoint])

        #expect(results.map(\.pin.id) == ["expected-trust-failure", "expected-success"])
        #expect(results.map(\.pin.expectedOutcome) == [.trustFailure, .success])
    }

    @Test("non-server-trust challenges use default handling")
    func delegatesNonTrustChallengesToDefaultHandling() async {
        let delegates: [URLSessionDelegate] = [
            InspectionDelegate(),
            CertificatePinningDelegate(expectedRootHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
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
        let expectedHash = try #require(SPKIHash.sha256Base64(of: certificate))

        await SystemClock.withCurrentDate(Self.validCertificateDate) {
            let matchingDelegate = CertificatePinningDelegate(expectedRootHash: expectedHash)
            #expect(matchingDelegate.failureMessage(for: trust) == nil)

            let mismatchingDelegate = CertificatePinningDelegate(
                expectedRootHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            )
            #expect(mismatchingDelegate.failureMessage(for: trust)?.contains("no configured certificate pin matched") == true)
        }

        await SystemClock.withCurrentDate(Self.expiredCertificateDate) {
            let expiredDelegate = CertificatePinningDelegate(expectedRootHash: expectedHash)
            #expect(expiredDelegate.failureMessage(for: trust) != nil)
        }
    }

    @Test("inspection delegates retain evaluated certificate metadata")
    func recordsInspectedCertificates() async throws {
        let certificate = try testCertificate()
        let trust = try trustedTrust(for: certificate)
        try await SystemClock.withCurrentDate(Self.validCertificateDate) {
            let delegate = InspectionDelegate()
            let certificates = try #require(delegate.certificateInfo(for: trust))

            #expect(certificates.count == 1)
            #expect(certificates[0].position == 0)
            #expect(certificates[0].role == .root)
            #expect(certificates[0].subject == "example.com")
            #expect(certificates[0].spkiSHA256Base64 == SPKIHash.sha256Base64(of: certificate))
            #expect(certificates[0].notAfter != nil)
        }
    }

    @Test("retiring pins require a replacement and retirement date")
    func validatesRotationConfiguration() {
        let retiringPin = CertificatePin(
            id: "old-root",
            role: .root,
            spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            state: .retiring
        )
        let endpoint = Endpoint(
            name: "API",
            url: URL(string: "https://example.com")!,
            certificates: [retiringPin]
        )
        #expect(throws: ConfigurationError.self) {
            try ConfigurationLoader.validate(.init(endpoints: [endpoint]))
        }
    }

    @Test("retiring matching pins silence imminent expiry warnings when replaced")
    func suppressesRetiringCertificateExpiryWarning() async throws {
        let certificate = try testCertificate()
        let hash = try #require(SPKIHash.sha256Base64(of: certificate))
        let delegate = CertificatePinningDelegate(
            pins: [
                .init(
                    id: "old-root",
                    role: .root,
                    spkiSHA256Base64: hash,
                    state: .retiring,
                    retireAfter: Self.validCertificateDate.addingTimeInterval(3_600)
                ),
                .init(
                    id: "new-root",
                    role: .root,
                    spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                )
            ],
            expiryWarningDays: 30
        )
        let trust = try trustedTrust(for: certificate)

        await SystemClock.withCurrentDate(Self.validCertificateDate) {
            #expect(delegate.failureMessage(for: trust) == nil)
            #expect(delegate.warnings.isEmpty)
        }
    }

    @Test("active pins report imminent certificate expiry")
    func reportsCertificateExpiryWarning() async throws {
        let certificate = try testCertificate()
        let delegate = CertificatePinningDelegate(
            pins: [.init(
                id: "current-root",
                role: .root,
                spkiSHA256Base64: try #require(SPKIHash.sha256Base64(of: certificate))
            )],
            expiryWarningDays: 30
        )
        let trust = try trustedTrust(for: certificate)

        await SystemClock.withCurrentDate(Self.validCertificateDate) {
            #expect(delegate.failureMessage(for: trust) == nil)
            #expect(delegate.warnings.count == 1)
        }
    }

    @Test("retiring pins fail after their retirement date")
    func rejectsRetiredCertificatePin() async throws {
        let certificate = try testCertificate()
        let delegate = CertificatePinningDelegate(
            pins: [
                .init(
                    id: "old-root",
                    role: .root,
                    spkiSHA256Base64: try #require(SPKIHash.sha256Base64(of: certificate)),
                    state: .retiring,
                    retireAfter: Self.validCertificateDate.addingTimeInterval(3_600)
                ),
                .init(
                    id: "new-root",
                    role: .root,
                    spkiSHA256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                )
            ],
            expiryWarningDays: 30
        )
        let trust = try trustedTrust(for: certificate)

        await SystemClock.withCurrentDate(Self.validCertificateDate.addingTimeInterval(7_200)) {
            #expect(delegate.failureMessage(for: trust)?.contains("old-root retired") == true)
        }
    }

    private func endpoint(for urlString: String) -> Endpoint {
        Endpoint(
            name: urlString,
            url: URL(string: urlString)!,
            certificates: [rootPin()],
            acceptableStatusCodes: [204]
        )
    }

    private static let validCertificateDate = Date(timeIntervalSince1970: 1_788_091_200)
    private static let expiredCertificateDate = Date(timeIntervalSince1970: 1_788_264_000)

    private func rootPin(
        _ hash: String = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        expectedOutcome: ExpectedOutcome = .success
    ) -> CertificatePin {
        .init(id: "root", role: .root, spkiSHA256Base64: hash, expectedOutcome: expectedOutcome)
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
