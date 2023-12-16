# CipherNaut embedded key vault

## What is CipherNaut?

CipherNaut is a key vault that can be embedded in .NET applications.

CipherNaut protects keys at rest against extraction by malicious actors. It does not protect against extraction from a
running process. If you need to protect against extraction from a running process, you should use a hardware security
module (HSM).

## How do I use it?

CipherNaut stores keys in a database. Key references are loaded using a Key Reference, or name. This reference is
unique per key, and is used to load the key from the database.

Keys are unwrapped at time of use using CipherNaut's `UnwrapKey` method. This method takes a key reference and a PIV
token, and returns the unwrapped key material. The PIV token must already be unlocked, or the operation will fail.

Adding a key to CipherNaut is done via the `AddKey` method. This method takes a key reference, and a public key.

## How does it work?

CipherNaut uses LiteDB, a NoSQL database, to store keys securely when not in use. User authentication is handled via
PIV-compatible smart cards with a key pair in the "Key Management" slot. The public key is stored in CipherNaut, and the
key pair is kept on the smart card.

For an EC public key, CipherNaut generates a temporary EC key for key agreement. The resulting shared secret is then
hashed via SHA-256 to create a 256-bit Key Encryption Key (KEK). The KEK is used to wrap the key material using RFC 5649
AES Key Wrap with Padding, and stored in the database alongside the temporary EC public key.