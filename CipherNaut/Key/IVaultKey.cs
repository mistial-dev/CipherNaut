using CipherNaut.Piv;
using JetBrains.Annotations;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CipherNaut.Key;

[PublicAPI]
public interface IVaultKey
{
    internal const string CurveName = "secp256r1";
    
    public string KeyReference { get; init; }
    
    public byte[] WrappedKeyMaterial { get; }
    
    public void Wrap(byte[] keyMaterial);
    
    public byte[] Unwrap(IPivCard pivCard);

    /// <summary>
    /// Generates an ephemeral EC key to use for key agreement.  Uses the secp256r1 curve.
    /// </summary>
    /// <returns></returns>
    public static AsymmetricCipherKeyPair GenerateEphemeralEcKey(SecureRandom? random = null)
    {
        // Generate a random number generator if one is not provided.
        random ??= new SecureRandom();
        
        // Generate the key pair.
        var ecParameters = SecNamedCurves.GetByName(CurveName);
        var ecDomainParameters = new ECDomainParameters(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H, ecParameters.GetSeed());
        var ecKeyPairGenerator = new ECKeyPairGenerator();
        ecKeyPairGenerator.Init(new ECKeyGenerationParameters(ecDomainParameters, random));
        return ecKeyPairGenerator.GenerateKeyPair();
    }
    
    /// <summary>
    /// Performs key agreement between the provided private and public keys.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="publicKey"></param>
    /// <returns></returns>
    public static byte[] EcKeyAgreement (ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey) {
        var ecKeyAgreement = new ECDHWithKdfBasicAgreement(NistObjectIdentifiers.IdAes256Wrap.Id,
            new ECDHKekGenerator(new Sha256Digest()));
        ecKeyAgreement.Init(privateKey);
        return ecKeyAgreement.CalculateAgreement(publicKey).ToByteArrayUnsigned();
    }

    /// <summary>
    /// Wraps the provided key material using the provided shared secret.
    /// </summary>
    /// <param name="keyEncryptionKey"></param>
    /// <param name="keyMaterial"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public static byte[] AesKeyWrapping(byte[] keyEncryptionKey, byte[] keyMaterial)
    {
        var aesKeyWrapEngine = new AesWrapEngine();
        var padding = new Pkcs7Padding();

        // We are using AES 128, so the block size will be 256 bits
        const int blockSize = 128 / 8;
        var paddingSize = blockSize - (keyMaterial.Length % blockSize);
        
        // Add a full padding block if required
        if (paddingSize == 0)
        {
            paddingSize = blockSize;
        }

        // Pad the input to the block size using PKCS7 padding
        var paddedBlock = new byte[paddingSize + keyMaterial.Length];
        Array.Copy(keyMaterial, paddedBlock, keyMaterial.Length);
        padding.AddPadding(paddedBlock, keyMaterial.Length);
        
        // Wrap the key material using bounds castle's AES key wrap implementation
        aesKeyWrapEngine.Init(true, new KeyParameter(keyEncryptionKey));
        var wrapped = aesKeyWrapEngine.Wrap(paddedBlock, 0, paddedBlock.Length);
        
        if (wrapped == null || wrapped.Length == 0)
        {
            throw new InvalidOperationException("Wrapped key material is empty or null.");
        }
        
        return wrapped;
    }

    /// <summary>
    /// Performs AES key unwrapping using the provided key encryption key and wrapped key material.
    /// </summary>
    /// <param name="keyEncryptionKey"></param>
    /// <param name="wrappedKeyMaterial"></param>
    /// <returns></returns>
    public static byte[] AesKeyUnwrapping(byte[] keyEncryptionKey, byte[] wrappedKeyMaterial)
    {
        // Unwrap the key material using bounds castle's AES key wrap implementation
        var aesKeyWrapEngine = new AesWrapEngine();
        aesKeyWrapEngine.Init(false, new KeyParameter(keyEncryptionKey));
        var unwrapped = aesKeyWrapEngine.Unwrap(wrappedKeyMaterial, 0, wrappedKeyMaterial.Length);
        
        // Remove the padding from the unwrapped key material
        var padding = new Pkcs7Padding();
        var paddingLength = padding.PadCount(unwrapped);
        var unwrappedKeyMaterial = new byte[unwrapped.Length - paddingLength];
        Array.Copy(unwrapped, unwrappedKeyMaterial, unwrappedKeyMaterial.Length);
        return unwrappedKeyMaterial;
    }
}