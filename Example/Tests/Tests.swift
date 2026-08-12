import XCTest
import TronCore

class Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // This is an example of a functional test case.
        XCTAssert(true, "Pass")
    }

    func testBIP39Validates15And21WordMnemonics() {
        for entropyLength in [20, 28] {
            let entropy = Data(repeating: 0, count: entropyLength)
            var mnemonic = [CChar](repeating: 0, count: 240)
            let generated = mnemonic.withUnsafeMutableBufferPointer { mnemonicBuffer in
                entropy.withUnsafeBytes { entropyBuffer in
                    guard let baseAddress = entropyBuffer.baseAddress else {
                        return false
                    }
                    mnemonic_from_data(
                        baseAddress.assumingMemoryBound(to: UInt8.self),
                        Int32(entropyLength),
                        mnemonicBuffer.baseAddress,
                        Int32(mnemonicBuffer.count)
                    ) != nil
                }
            }

            XCTAssertTrue(generated)
            XCTAssertEqual(String(cString: mnemonic).split(separator: " ").count, entropyLength * 3 / 4)
            XCTAssertEqual(mnemonic_check(mnemonic), 1)
        }
    }

    /// secp256k1 group order, the first scalar that is no longer a usable private key.
    private static let curveOrder = Data([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ])

    func testEthereumCryptoRejectsInvalidInputs() {
        let digest = Data(repeating: 0, count: 32)
        let privateKey = Data(repeating: 1, count: 32)

        XCTAssertTrue(EthereumCrypto.getPublicKey(from: Data(count: 31)).isEmpty)
        XCTAssertTrue(EthereumCrypto.sign(hash: Data(count: 31), privateKey: privateKey).isEmpty)
        XCTAssertTrue(EthereumCrypto.sign(hash: digest, privateKey: Data(count: 31)).isEmpty)
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 63), message: digest, publicKey: Data(count: 65)))
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 65), message: Data(count: 31), publicKey: Data(count: 65)))
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 65), message: digest, publicKey: Data(count: 64)))
        // Well-formed 0x04 prefix, so this one reaches ecdsa_validate_pubkey and fails there.
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 65), message: digest, publicKey: Data([0x04]) + Data(count: 64)))

        // Correct length, but outside 0 < k < order, where the curve code only has an assert().
        for outOfRange in [Data(count: 32), Tests.curveOrder, Data(repeating: 0xff, count: 32)] {
            XCTAssertTrue(EthereumCrypto.getPublicKey(from: outOfRange).isEmpty)
            XCTAssertTrue(EthereumCrypto.sign(hash: digest, privateKey: outOfRange).isEmpty)
        }

        var belowOrder = Tests.curveOrder
        belowOrder[31] -= 1
        XCTAssertEqual(EthereumCrypto.getPublicKey(from: belowOrder).count, 65)
    }

    func testEthereumCryptoSignVerifyRoundTrip() {
        var privateKey = Data(repeating: 0, count: 32)
        privateKey[31] = 1
        let digest = EthereumCrypto.hash(Data("tron".utf8))

        let publicKey = EthereumCrypto.getPublicKey(from: privateKey)
        let signature = EthereumCrypto.sign(hash: digest, privateKey: privateKey)

        XCTAssertEqual(digest.count, 32)
        XCTAssertEqual(publicKey.count, 65)
        XCTAssertEqual(signature.count, 65)
        XCTAssertTrue(EthereumCrypto.verify(signature: signature, message: digest, publicKey: publicKey))

        // The recovery byte is optional, so bare R || S has to verify as well.
        XCTAssertTrue(EthereumCrypto.verify(signature: Data(signature.prefix(64)), message: digest, publicKey: publicKey))

        // Same key in compressed form, the other branch accepted by the public key check.
        var compressed = Data([0x02 | (publicKey[64] & 0x01)])
        compressed.append(publicKey[1..<33])
        XCTAssertTrue(EthereumCrypto.verify(signature: signature, message: digest, publicKey: compressed))

        // Prefix and length must agree: 0x04 on a 33-byte buffer would make ecdsa_read_pubkey
        // read pub_key[33..64], past the end. The mirror case is rejected for symmetry.
        XCTAssertFalse(EthereumCrypto.verify(signature: signature, message: digest, publicKey: Data([0x04]) + publicKey[1..<33]))
        XCTAssertFalse(EthereumCrypto.verify(signature: signature, message: digest, publicKey: Data([0x02]) + publicKey[1..<65]))

        var tampered = signature
        tampered[0] ^= 0x01
        XCTAssertFalse(EthereumCrypto.verify(signature: tampered, message: digest, publicKey: publicKey))
        XCTAssertFalse(EthereumCrypto.verify(signature: signature, message: EthereumCrypto.hash(Data("tronn".utf8)), publicKey: publicKey))
    }

    func testEthereumCryptoConcurrentSigningIsStable() {
        var privateKey = Data(repeating: 0, count: 32)
        privateKey[31] = 1
        let digest = Data(repeating: 1, count: 32)
        let expected = EthereumCrypto.sign(hash: digest, privateKey: privateKey)
        let lock = NSLock()
        var signatures = [Data]()

        DispatchQueue.concurrentPerform(iterations: 32) { _ in
            let signature = EthereumCrypto.sign(hash: digest, privateKey: privateKey)
            lock.lock()
            signatures.append(signature)
            lock.unlock()
        }

        XCTAssertEqual(expected.count, 65)
        XCTAssertEqual(signatures.count, 32)
        for signature in signatures {
            XCTAssertEqual(signature, expected)
        }
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
