import Foundation

public enum BandersnatchApi {
    enum ApiError: Error {
        case internalError
        case badResult
        case badInput
    }

    public enum RingDomainSize: UInt32 {
        case domain11 = 11
        case domain12 = 12
        case domain16 = 16
    }
    
    static func isError(_ result: String) -> Bool {
        result == "-1"
    }
    
    public static var memberKeySize: Int { internalGetMemberKeyLength() }
    public static var entropySize: Int { internalGetEntropyLength() }
    
    public static func deriveMemberKey(from entropy: Data) throws -> Data {
        let entropyString = entropy.base64EncodedString()
        
        let result = internalDeriveMemberKey(entropyString).toString()
        
        guard !isError(result) else {
            throw BandersnatchApi.ApiError.internalError
        }
        
        guard let memberKey = Data(base64Encoded: result) else {
            throw BandersnatchApi.ApiError.badResult
        }
        
        return memberKey
    }
    
    public static func createProof(
        from entropy: Data,
        members: [Data],
        message: Data,
        context: Data,
        domainSize: RingDomainSize
    ) throws -> Data {
        let membersBase64 = RustVec<RustString>()

        for member in members {
            membersBase64.push(value: member.base64EncodedString().intoRustString())
        }

        let result = internalCreateProof(
            entropy.base64EncodedString().intoRustString(),
            membersBase64,
            context.base64EncodedString().intoRustString(),
            message.base64EncodedString().intoRustString(),
            domainSize.rawValue
        )
        
        guard !isError(result.toString()) else {
            throw BandersnatchApi.ApiError.internalError
        }
        
        guard let proof = Data(base64Encoded: result.toString()) else {
            throw BandersnatchApi.ApiError.badResult
        }
        
        return proof
    }

    public static func sign(entropy: Data, message: Data) throws -> Data {
        let result = internalSign(
            entropy.base64EncodedString().intoRustString(),
            message.base64EncodedString().intoRustString()
        )

        guard !isError(result.toString()) else {
            throw BandersnatchApi.ApiError.internalError
        }

        guard let signedMessage = Data(base64Encoded: result.toString()) else {
            throw BandersnatchApi.ApiError.badResult
        }

        return signedMessage
    }

    public static func deriveAlias(fromEntropy entropy: Data, context: Data) throws -> Data {
        let entropyString = entropy.base64EncodedString()
        let contextString  = context.base64EncodedString()

        let result = internalDeriveAlias(
            entropyString.intoRustString(),
            contextString.intoRustString()
        ).toString()

        guard !isError(result) else {
            throw BandersnatchApi.ApiError.internalError
        }

        guard let alias = Data(base64Encoded: result) else {
            throw BandersnatchApi.ApiError.badResult
        }

        return alias
    }
}
