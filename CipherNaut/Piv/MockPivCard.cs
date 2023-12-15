using CipherNaut.Key;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace CipherNaut.Piv;

public sealed class MockPivCard : IPivCard
{
    /// <summary>
    /// Mock key to use for testing.
    /// </summary>
    public required AsymmetricCipherKeyPair MockKey { get; init; }

    /// <summary>
    /// True if the card is locked.
    /// </summary>
    public bool IsLocked => false;
    
    /// <inheritdoc />
    public bool UnlockCard(byte[] pin) => true;

    /// <inheritdoc />
    public ECPublicKeyParameters PublicKeyParameters => (ECPublicKeyParameters)MockKey.Public;
    
    /// <summary>
    /// Perform EC Key Agreement
    /// </summary>
    /// <param name="publicKeyParameters"></param>
    /// <returns></returns>
    public byte[] KeyAgreement(ECPublicKeyParameters publicKeyParameters)
    {
        return IVaultKey.EcKeyAgreement((ECPrivateKeyParameters)MockKey.Private, publicKeyParameters);
    }
}