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
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 64), message: digest, publicKey: Data(count: 65)))
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 65), message: Data(count: 31), publicKey: Data(count: 65)))
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 65), message: digest, publicKey: Data(count: 64)))
        XCTAssertFalse(EthereumCrypto.verify(signature: Data(count: 65), message: digest, publicKey: Data(count: 65)))

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

        // Same key in compressed form, the other branch accepted by the public key check.
        var compressed = Data([0x02 | (publicKey[64] & 0x01)])
        compressed.append(publicKey[1..<33])
        XCTAssertTrue(EthereumCrypto.verify(signature: signature, message: digest, publicKey: compressed))

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
