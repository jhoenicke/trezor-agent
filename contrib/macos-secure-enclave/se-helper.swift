// Secure Enclave helper for trezor-agent's GPG subkeys (macOS only).
//
// Build:  swiftc -O -o se-helper se-helper.swift
//
// Usage:
//   se-helper generate-signing  KEYFILE [--no-user-presence]
//       Create a new P-256 signing key inside the Secure Enclave.
//   se-helper import-decryption KEYFILE [--no-user-presence]
//       Read a 32-byte X25519 secret (hex) from stdin and store it wrapped
//       (ECIES: P-256 ECDH + HKDF-SHA256 + AES-256-GCM) by a new Secure
//       Enclave key-agreement key.
//   se-helper sign KEYFILE   < digest (hex)       > r||s (hex)
//   se-helper ecdh KEYFILE   < X25519 peer (hex)  > shared secret (hex)
//
// KEYFILE is a JSON file holding the Secure Enclave key blob, which is only
// usable by the Secure Enclave of the Mac that created it, together with the
// public key (so that public key lookups need no user interaction).

import CryptoKit
import Foundation
import Security

struct HelperError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Pre-computed digest, passed to the Secure Enclave as-is.
struct RawDigest: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    func makeIterator() -> IndexingIterator<[UInt8]> { bytes.makeIterator() }

    var description: String { hex(Data(bytes)) }
}

let wrapInfo = Data("trezor-agent se-helper decryption key v1".utf8)

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func unhex(_ string: String) throws -> Data {
    let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
    guard s.count % 2 == 0 else { throw HelperError("odd-length hex input") }
    var data = Data(capacity: s.count / 2)
    var index = s.startIndex
    while index < s.endIndex {
        let next = s.index(index, offsetBy: 2)
        guard let byte = UInt8(s[index..<next], radix: 16) else {
            throw HelperError("invalid hex input")
        }
        data.append(byte)
        index = next
    }
    return data
}

func readStdinHex() throws -> Data {
    try unhex(String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self))
}

func accessControl(userPresence: Bool) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if userPresence {
        flags.insert(.userPresence)  // Touch ID, Apple Watch or login password
    }
    var error: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
    else {
        throw error!.takeRetainedValue() as Error
    }
    return ac
}

func writeKeyFile(_ path: String, _ object: [String: String]) throws {
    let url = URL(fileURLWithPath: path)
    guard !FileManager.default.fileExists(atPath: path) else {
        throw HelperError("\(path) already exists")
    }
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    guard FileManager.default.createFile(
        atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600])
    else {
        throw HelperError("cannot create \(path)")
    }
}

func readKeyFile(_ path: String, type: String) throws -> [String: String] {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: String],
          object["type"] == type
    else {
        throw HelperError("\(path) is not a \(type) key file")
    }
    return object
}

func field(_ object: [String: String], _ name: String) throws -> Data {
    guard let value = object[name], let data = Data(base64Encoded: value) else {
        throw HelperError("missing field \(name)")
    }
    return data
}

func wrappingKey(shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey,
                 recipient: P256.KeyAgreement.PublicKey) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeral.x963Representation + recipient.x963Representation,
        sharedInfo: wrapInfo,
        outputByteCount: 32)
}

func generateSigning(path: String, userPresence: Bool) throws {
    let key = try SecureEnclave.P256.Signing.PrivateKey(
        accessControl: try accessControl(userPresence: userPresence))
    let pub = key.publicKey.x963Representation
    try writeKeyFile(path, [
        "type": "signing",
        "key": key.dataRepresentation.base64EncodedString(),
        "public": hex(pub),
    ])
    print(hex(pub))
}

func importDecryption(path: String, userPresence: Bool) throws {
    let secret = try readStdinHex()
    guard secret.count == 32 else { throw HelperError("expected 32-byte X25519 secret") }
    let x25519 = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)

    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        accessControl: try accessControl(userPresence: userPresence))
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
    let symKey = wrappingKey(shared: shared, ephemeral: ephemeral.publicKey,
                             recipient: seKey.publicKey)
    let sealed = try AES.GCM.seal(secret, using: symKey, authenticating: wrapInfo)

    let pub = x25519.publicKey.rawRepresentation
    try writeKeyFile(path, [
        "type": "decryption",
        "key": seKey.dataRepresentation.base64EncodedString(),
        "ephemeral": ephemeral.publicKey.x963Representation.base64EncodedString(),
        "sealed": sealed.combined!.base64EncodedString(),
        "public": hex(pub),
    ])
    print(hex(pub))
}

func sign(path: String) throws {
    let object = try readKeyFile(path, type: "signing")
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try field(object, "key"))
    let digest = try readStdinHex()
    guard digest.count == RawDigest.byteCount else { throw HelperError("expected 32-byte digest") }
    let signature = try key.signature(for: RawDigest(bytes: [UInt8](digest)))
    print(hex(signature.rawRepresentation))
}

func ecdh(path: String) throws {
    let object = try readKeyFile(path, type: "decryption")
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: try field(object, "key"))
    let ephemeral = try P256.KeyAgreement.PublicKey(
        x963Representation: try field(object, "ephemeral"))
    let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: try readStdinHex())

    // This is where the Secure Enclave asks for user presence.
    let shared = try seKey.sharedSecretFromKeyAgreement(with: ephemeral)
    let symKey = wrappingKey(shared: shared, ephemeral: ephemeral, recipient: seKey.publicKey)
    let box = try AES.GCM.SealedBox(combined: try field(object, "sealed"))
    let secret = try AES.GCM.open(box, using: symKey, authenticating: wrapInfo)

    let x25519 = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
    let result = try x25519.sharedSecretFromKeyAgreement(with: peer)
    print(hex(result.withUnsafeBytes { Data($0) }))
}

func main() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    guard args.count >= 2 else {
        throw HelperError("usage: se-helper generate-signing|import-decryption|sign|ecdh KEYFILE")
    }
    guard SecureEnclave.isAvailable else { throw HelperError("Secure Enclave is not available") }
    let userPresence = !args.contains("--no-user-presence")
    switch args[0] {
    case "generate-signing": try generateSigning(path: args[1], userPresence: userPresence)
    case "import-decryption": try importDecryption(path: args[1], userPresence: userPresence)
    case "sign": try sign(path: args[1])
    case "ecdh": try ecdh(path: args[1])
    default: throw HelperError("unknown command \(args[0])")
    }
}

do {
    try main()
} catch {
    FileHandle.standardError.write(Data("se-helper: \(error)\n".utf8))
    exit(1)
}
