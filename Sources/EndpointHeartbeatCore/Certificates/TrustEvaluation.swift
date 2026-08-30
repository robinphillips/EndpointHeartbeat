enum TrustEvaluation {
    case success([CertificateWarning])
    case failure(String)
}
