using JetBrains.Annotations;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
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
}