using Org.BouncyCastle.Crypto.Parameters;

namespace CipherNaut.Piv;

public interface IPivCard
{
    /// <summary>
    /// Returns true if the card is locked.
    /// </summary>
    public bool IsLocked { get; }

    /// <summary>
    /// Unlocks the card with the given PIN.
    /// </summary>
    /// <param name="pin">PIN to unlock the card with</param>
    /// <returns></returns>
    public bool UnlockCard(byte[] pin);

    /// <summary>
    /// Returns the public key parameters for the card.
    /// </summary>
    public ECPublicKeyParameters PublicKeyParameters { get; }

    /// <summary>
    /// Performs a key agreement with the given public key parameters.
    /// </summary>
    /// <param name="publicKeyParameters">Public key to perform key agreement with</param>
    /// <returns>Shared Secret as a byte array</returns>
    public byte[] KeyAgreement(ECPublicKeyParameters? publicKeyParameters);
}