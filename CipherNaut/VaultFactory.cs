using System.IO.Abstractions;
using CipherNaut.Vault;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Parameters;

namespace CipherNaut;

public static class VaultFactory
{
    [PublicAPI]
    public static IVault Create(string fileName, ECPublicKeyParameters? publicKey = null)
    {
        var filesystem = new FileSystem();
        var vault = new VaultImpl()
        {
            FileSystem = filesystem,
            FileName = fileName,
            PublicKey = publicKey
        };
        vault.Initialize();
        return vault;
    }

    [PublicAPI]
    public static IVault Create(IFileSystem filesystem, string fileName, ECPublicKeyParameters? publicKey = null)
    {
        var vault = new VaultImpl()
        {
            FileSystem = filesystem,
            FileName = fileName,
            PublicKey = publicKey
        };
        vault.Initialize();

        return vault;
    }
}