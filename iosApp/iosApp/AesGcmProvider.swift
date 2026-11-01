import CryptoKit
import Foundation
import ComposeApp

final class CryptoKitAesGcmProvider: NSObject, NuvioAesGcmProvider {
    private static let tagLength = 16

    func encrypt(key: Data, iv: Data, plaintext: Data) -> Data? {
        guard let nonce = try? AES.GCM.Nonce(data: iv),
              let box = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce)
        else { return nil }
        return box.ciphertext + box.tag
    }

    func decrypt(key: Data, iv: Data, ciphertextAndTag: Data) -> Data? {
        guard ciphertextAndTag.count >= Self.tagLength,
              let nonce = try? AES.GCM.Nonce(data: iv)
        else { return nil }
        let split = ciphertextAndTag.count - Self.tagLength
        let ciphertext = ciphertextAndTag.prefix(split)
        let tag = ciphertextAndTag.suffix(Self.tagLength)
        guard let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        else { return nil }
        return try? AES.GCM.open(box, using: SymmetricKey(data: key))
    }
}

enum NuvioAesGcmRegistration {
    static func register() {
        NuvioAesGcm.shared.register(provider: CryptoKitAesGcmProvider())
    }
}
