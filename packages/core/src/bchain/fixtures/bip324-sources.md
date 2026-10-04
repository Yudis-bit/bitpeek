BIP-324 CSV fixtures are copied verbatim from the Bitcoin BIPs repository:

- [SwiftEC decoding vectors](https://github.com/bitcoin/bips/blob/master/bip-0324/ellswift_decode_test_vectors.csv)
- [SwiftEC inverse vectors](https://github.com/bitcoin/bips/blob/master/bip-0324/xswiftec_inv_test_vectors.csv)
- [Packet encoding vectors](https://github.com/bitcoin/bips/blob/master/bip-0324/packet_encoding_test_vectors.csv)

Retrieved 2026-10-04. The tests consume the published exceptional-field inputs,
all eight inverse branches, encoding-bound ECDH, network-specific HKDF labels,
directional keys, garbage terminators, ratchets and maximum uint24 packet size.
The reference algorithm also follows Bitcoin Core's MIT-licensed test framework
in `test/functional/test_framework/crypto/ellswift.py` and `bip324_cipher.py`.
