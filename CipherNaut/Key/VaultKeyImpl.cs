using CipherNaut.Piv;
using LiteDB;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CipherNaut.Key;

/// <summary>
/// Represents a vault key.
/// </summary>
internal class VaultKeyImpl : IVaultKey
{
    [BsonIgnore] public SecureRandom Random { get; } = new();

    public required string KeyReference { get; init; }

    [BsonIgnore] public required ECPublicKeyParameters? VaultPublicKey { get; init; }

    /// <summary>
    /// Ephemeral public key used for key agreement.
    /// </summary>
    [BsonIgnore]
    public ECPublicKeyParameters? EphemeralPublicKey { get; private set; }

    /// <summary>
    /// Stores the wrapped key material.
    /// </summary>
    public byte[] WrappedKeyMaterial { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Wraps key material using the vault public key.
    /// </summary>
    /// <param name="keyMaterial">Key to be wrapped</param>
    /// <returns></returns>
    public void Wrap(byte[] keyMaterial)
    {
        // Generate an ephemeral EC key pair
        var ephemeralEcKeyPair = IVaultKey.GenerateEphemeralEcKey(Random);
        EphemeralPublicKey = (ECPublicKeyParameters)ephemeralEcKeyPair.Public;

        // Perform key agreement
        var keyEncryptionKey =
            IVaultKey.EcKeyAgreement((ECPrivateKeyParameters)ephemeralEcKeyPair.Private, VaultPublicKey);

        // Wrap the key material
        WrappedKeyMaterial = IVaultKey.AesKeyWrapping(keyEncryptionKey, keyMaterial);
    }

    /// <summary>
    /// Unwrap a key using a PIV card
    /// </summary>
    /// <param name="pivCard">PIV Card for unwrapping</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public byte[] Unwrap(IPivCard pivCard)
    {
        if (WrappedKeyMaterial == null || WrappedKeyMaterial.Length == 0)
            throw new InvalidOperationException("Key material is empty or null.");

        if (pivCard.IsLocked) throw new InvalidOperationException("PIV card must be unlocked before use.");

        // Perform key agreement between the PIV card and the ephemeral EC key pair
        var keyEncryptionKey = pivCard.KeyAgreement(EphemeralPublicKey ??
                                                    throw new InvalidOperationException(
                                                        "Ephemeral public key is null."));

        // Unwrap the key material
        return IVaultKey.AesKeyUnwrapping(keyEncryptionKey, WrappedKeyMaterial);
    }
}