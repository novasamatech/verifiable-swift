import UIKit
import BandersnatchApi

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        createProof()
    }

    private func createProof() {
            do {
                let members = try (0..<100).map {
                    try BandersnatchApi.deriveMemberKey(from: Data(repeating: $0, count: BandersnatchApi.entropySize))
                }
                
                let firstMemberEntropy = Data(repeating: 0, count: BandersnatchApi.entropySize)
                
                let start = Date().timeIntervalSince1970
                
                let proof = try BandersnatchApi.createProof(
                    from: firstMemberEntropy,
                    members: members,
                    message: "hello".data(using: .utf8)!,
                    context: "pop:polkadot.network/mob-rule   ".data(using: .utf8)!
                )
                
                print("Proof: \(proof.base64EncodedString())")
                
                let stop = Date().timeIntervalSince1970
                
                print("Time: \(stop - start)s")
            } catch {
                
            }
        }
}

