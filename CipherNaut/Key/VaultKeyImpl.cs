using LiteDB;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CipherNaut.Key;

/// <summary>
/// Represents a vault key.
/// </summary>
internal class VaultKeyImpl : IVaultKey
{
    [BsonIgnore]
    public SecureRandom Random { get; } = new();
    
    public required string KeyReference { get; init; }
    
    [BsonIgnore]
    public required ECPublicKeyParameters PublicKey { get; init; }

    public byte[] WrappedKeyMaterial { get; internal set; } = Array.Empty<byte>();
    
    public void Wrap(byte[] keyMaterial)
    {
        var kekBytes = new byte[256 / 8];
        
        // Generate an ephemeral EC key pair
        var ephemeralEcKeyPair = IVaultKey.GenerateEphemeralEcKey(Random);
        
        // Perform key agreement
        var ecKeyAgreement = new ECDHBasicAgreement();
        ecKeyAgreement.Init(ephemeralEcKeyPair.Private);
        var sharedSecret = ecKeyAgreement.CalculateAgreement(PublicKey).ToByteArrayUnsigned();
        
        // Derive a key encryption key with bouncy castle using SHA-256 of the shared secret
        var shaDigestEngine = new Sha256Digest();
        shaDigestEngine.BlockUpdate(sharedSecret, 0, sharedSecret.Length);
        shaDigestEngine.DoFinal(kekBytes, 0);
        
        // Wrap the key material using bounds castle's AES key wrap implementation
        var aesKeyWrapEngine = new AesWrapEngine();
        aesKeyWrapEngine.Init(true, new KeyParameter(kekBytes));
        WrappedKeyMaterial = aesKeyWrapEngine.Wrap(keyMaterial, 0, keyMaterial.Length);
    }
}