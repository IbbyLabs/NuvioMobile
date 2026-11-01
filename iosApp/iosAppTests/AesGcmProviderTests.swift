import XCTest
@testable import Nuvio

final class AesGcmProviderTests: XCTestCase {
    private let provider = CryptoKitAesGcmProvider()

    private struct Vector {
        let key: String
        let iv: String
        let plaintext: String
        let ciphertext: String
        let tag: String
    }

    // NIST GCM spec test cases 1 to 3 (96-bit IV, no additional data).
    private let vectors = [
        Vector(
            key: "00000000000000000000000000000000",
            iv: "000000000000000000000000",
            plaintext: "",
            ciphertext: "",
            tag: "58e2fccefa7e3061367f1d57a4e7455a"
        ),
        Vector(
            key: "00000000000000000000000000000000",
            iv: "000000000000000000000000",
            plaintext: "00000000000000000000000000000000",
            ciphertext: "0388dace60b6a392f328c2b971b2fe78",
            tag: "ab6e47d42cec13bdf53a67b21257bddf"
        ),
        Vector(
            key: "feffe9928665731c6d6a8f9467308308",
            iv: "cafebabefacedbaddecaf888",
            plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            ciphertext: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            tag: "4d5c2af327cd64a62cf35abd2ba6fab4"
        ),
    ]

    func testEncryptMatchesKnownAnswers() throws {
        for v in vectors {
            let out = try XCTUnwrap(provider.encrypt(key: hex(v.key), iv: hex(v.iv), plaintext: hex(v.plaintext)))
            XCTAssertEqual(out, hex(v.ciphertext + v.tag))
        }
    }

    func testDecryptMatchesKnownAnswers() throws {
        for v in vectors {
            let out = try XCTUnwrap(provider.decrypt(key: hex(v.key), iv: hex(v.iv), ciphertextAndTag: hex(v.ciphertext + v.tag)))
            XCTAssertEqual(out, hex(v.plaintext))
        }
    }

    func testDecryptRejectsWrongTag() throws {
        let v = vectors[2]
        var sealed = hex(v.ciphertext + v.tag)
        sealed[sealed.count - 1] ^= 0x01
        XCTAssertNil(provider.decrypt(key: hex(v.key), iv: hex(v.iv), ciphertextAndTag: sealed))
    }

    func testDecryptRejectsTamperedCiphertext() throws {
        let v = vectors[2]
        var sealed = hex(v.ciphertext + v.tag)
        sealed[0] ^= 0x01
        XCTAssertNil(provider.decrypt(key: hex(v.key), iv: hex(v.iv), ciphertextAndTag: sealed))
    }

    func testRoundTripWithLongerIvAndLargerKey() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let iv = Data((0..<16).map { UInt8(255 - $0) })
        let message = Data("round trip message".utf8)
        let sealed = try XCTUnwrap(provider.encrypt(key: key, iv: iv, plaintext: message))
        XCTAssertEqual(sealed.count, message.count + 16)
        XCTAssertEqual(provider.decrypt(key: key, iv: iv, ciphertextAndTag: sealed), message)
    }

    func testRejectsShortIvAndShortInput() {
        let key = Data(count: 16)
        XCTAssertNil(provider.encrypt(key: key, iv: Data(count: 8), plaintext: Data()))
        XCTAssertNil(provider.decrypt(key: key, iv: Data(count: 12), ciphertextAndTag: Data(count: 15)))
    }

    private func hex(_ string: String) -> Data {
        var data = Data()
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            data.append(UInt8(string[index..<next], radix: 16)!)
            index = next
        }
        return data
    }
}
