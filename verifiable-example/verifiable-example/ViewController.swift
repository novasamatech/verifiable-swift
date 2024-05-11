import UIKit
import verifiable

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        createProof()
    }

    private func createProof() {
        do {
            let members = try (0..<100).map {
                try VerifiableApi.deriveMemberKey(from: Data(repeating: $0, count: VerifiableApi.entropySize))
            }
            
            let firstMemberEntropy = Data(repeating: 0, count: VerifiableApi.entropySize)
            
            print("Start: \(Date())")
            
            let proof = try VerifiableApi.createProof(
                from: firstMemberEntropy,
                members: members,
                message: "hello",
                context: "pop:polkadot.network/mob-rule   "
            )
            
            print("Data: \(proof.base64EncodedString())")
            
            print("Stop: \(Date())")
        } catch {
            
        }
    }
}

