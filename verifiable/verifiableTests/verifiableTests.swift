import XCTest
import verifiable

final class verifiableTests: XCTestCase {
    func testDeriveMemberKey() throws {
        let memberKey = try VerifiableApi.deriveMemberKey(from: Data(repeating: 0, count: VerifiableApi.entropySize))
        XCTAssertEqual(memberKey.count, VerifiableApi.memberKeySize)
        
        print("Result: \(memberKey.base64EncodedString())")
    }
    
    func testGenerateProof() throws {
        let members = try (0..<100).map {
            try VerifiableApi.deriveMemberKey(from: Data(repeating: $0, count: VerifiableApi.entropySize))
        }
        
        let firstMemberEntropy = Data(repeating: 0, count: VerifiableApi.entropySize)
        
        measure {
            do {
                let proof = try VerifiableApi.createProof(
                    from: firstMemberEntropy,
                    members: members,
                    message: "hello".data(using: .utf8)!,
                    context: "pop:polkadot.network/mob-rule   ".data(using: .utf8)!
                )
                
                print("Proof: \(proof.base64EncodedString())")
            } catch {
                XCTFail("Error: \(error)")
            }
        }
    }
}
