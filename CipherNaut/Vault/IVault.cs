using System.IO.Abstractions;
using CipherNaut.Key;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Parameters;

namespace CipherNaut.Vault;

[PublicAPI]
public interface IVault : IDisposable
{
    /// <summary>
    /// Filesystem for the vault
    /// </summary>
    public IFileSystem FileSystem { init; }

    /// <summary>
    /// Gets a key from the vault
    /// </summary>
    /// <param name="keyReference"></param>
    /// <returns></returns>
    public IVaultKey Get(string keyReference);

    /// <summary>
    /// Creates a new key in the vault
    /// </summary>
    /// <param name="keyReference">Reference for the key</param>
    /// <param name="keyMaterial">Key Material</param>
    /// <returns></returns>
    public IVaultKey Create(string keyReference, byte[] keyMaterial);

    /// <summary>
    /// Public key for the vault
    /// </summary>
    ECPublicKeyParameters? PublicKey { get; }
}