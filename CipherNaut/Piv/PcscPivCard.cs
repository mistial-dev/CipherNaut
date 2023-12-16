using Org.BouncyCastle.Crypto.Parameters;
using WSCT.Wrapper.Desktop.Core;

namespace CipherNaut.Piv;

public class PcscPivCard : IPivCard
{
    public PcscPivCard(CardChannel cardChannel)
    {
        this.CardChannel = cardChannel;
    }

    /// <summary>
    /// Card channel to communicate with the card/yubikey.
    /// </summary>
    private CardChannel CardChannel { get; set; }

    /// <summary>
    /// Public key parameters of the card.
    /// </summary>
    public ECPublicKeyParameters PublicKeyParameters {
        get
        {
            throw new NotImplementedException();
        } }
    
    /// <summary>
    /// True if the card is locked, false otherwise.
    /// </summary>
    public bool IsLocked { get; } = true;

    /// <summary>
    /// Unlock the card with the given pin.
    /// </summary>
    /// <param name="pin"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public bool UnlockCard(byte[] pin)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Perform a key agreement with the given public key parameters.
    /// </summary>
    /// <param name="publicKeyParameters"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public byte[] KeyAgreement(ECPublicKeyParameters? publicKeyParameters)
    {
        throw new NotImplementedException();
    }
}