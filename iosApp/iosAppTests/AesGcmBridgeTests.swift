import XCTest
import ComposeApp
@testable import Nuvio

final class AesGcmBridgeTests: XCTestCase {
    override func setUp() {
        super.setUp()
        NuvioAesGcmRegistration.register()
    }

    func testEncryptThroughKotlinMatchesNistCase3() {
        let sealed = PluginCrypto_iosKt.pluginAesEncrypt(
            mode: "AES-GCM",
            key: kotlinBytes(hex("feffe9928665731c6d6a8f9467308308")),
            iv: kotlinBytes(hex("cafebabefacedbaddecaf888")),
            data: kotlinBytes(hex(plaintext))
        )
        XCTAssertEqual(swiftData(sealed), hex(ciphertext + tag))
    }

    func testDecryptThroughKotlinMatchesNistCase3() {
        let opened = PluginCrypto_iosKt.pluginAesDecrypt(
            mode: "AES-GCM",
            key: kotlinBytes(hex("feffe9928665731c6d6a8f9467308308")),
            iv: kotlinBytes(hex("cafebabefacedbaddecaf888")),
            data: kotlinBytes(hex(ciphertext + tag))
        )
        XCTAssertEqual(swiftData(opened), hex(plaintext))
    }

    func testEmptyPlaintextThroughKotlinMatchesNistCase1() {
        let key = kotlinBytes(Data(count: 16))
        let iv = kotlinBytes(Data(count: 12))
        let sealed = PluginCrypto_iosKt.pluginAesEncrypt(mode: "AES-GCM", key: key, iv: iv, data: kotlinBytes(Data()))
        XCTAssertEqual(swiftData(sealed), hex("58e2fccefa7e3061367f1d57a4e7455a"))
        let opened = PluginCrypto_iosKt.pluginAesDecrypt(mode: "AES-GCM", key: key, iv: iv, data: sealed)
        XCTAssertEqual(opened.size, 0)
    }

    func testRoundTripThroughKotlin() {
        let key = kotlinBytes(Data((0..<32).map { UInt8($0) }))
        let iv = kotlinBytes(Data((0..<12).map { UInt8(100 + $0) }))
        let message = Data("bridge round trip".utf8)
        let sealed = PluginCrypto_iosKt.pluginAesEncrypt(mode: "AES-GCM", key: key, iv: iv, data: kotlinBytes(message))
        XCTAssertEqual(Int(sealed.size), message.count + 16)
        let opened = PluginCrypto_iosKt.pluginAesDecrypt(mode: "AES-GCM", key: key, iv: iv, data: sealed)
        XCTAssertEqual(swiftData(opened), message)
    }

    private let plaintext = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    private let ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
    private let tag = "4d5c2af327cd64a62cf35abd2ba6fab4"

    private func kotlinBytes(_ data: Data) -> KotlinByteArray {
        let array = KotlinByteArray(size: Int32(data.count))
        for (index, byte) in data.enumerated() {
            array.set(index: Int32(index), value: Int8(bitPattern: byte))
        }
        return array
    }

    private func swiftData(_ array: KotlinByteArray) -> Data {
        Data((0..<array.size).map { UInt8(bitPattern: array.get(index: $0)) })
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
