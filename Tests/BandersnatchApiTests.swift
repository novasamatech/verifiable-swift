import XCTest
import BandersnatchApi

final class verifiableTests: XCTestCase {
    func testDeriveMemberKey() throws {
        let memberKey = try BandersnatchApi.deriveMemberKey(from: Data(repeating: 0, count: BandersnatchApi.entropySize))
        XCTAssertEqual(memberKey.count, BandersnatchApi.memberKeySize)
        
        print("Result: \(memberKey.base64EncodedString())")
    }
    
    func testGenerateProof() throws {
        let members = try (0..<100).map {
            try BandersnatchApi.deriveMemberKey(from: Data(repeating: $0, count: BandersnatchApi.entropySize))
        }
        
        let firstMemberEntropy = Data(repeating: 0, count: BandersnatchApi.entropySize)
        
        measure {
            do {
                let proof = try BandersnatchApi.createProof(
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

    func testSignMessage() {
        do {
            let entropy = Data(repeating: 0, count: BandersnatchApi.entropySize)
            let message = "hello".data(using: .utf8)!
            let result = try BandersnatchApi.sign(entropy: entropy, message: message)

            print("Signed message: \(result.base64EncodedString())")
        } catch {
            XCTFail("Signing message error: \(error)")
        }
    }

    func testDeriveAlias() {
        do {
            let entropy = Data(repeating: 0, count: BandersnatchApi.entropySize)
            let context = "pop:polkadot.network/priv-vouchr".data(using: .utf8)!
            let result = try BandersnatchApi.deriveAlias(fromEntropy: entropy, context: context)

            print("Alias: \(result.base64EncodedString())")
        } catch {
            XCTFail("Derive alias error: \(error)")
        }
    }

}
