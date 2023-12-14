using System.IO.Abstractions;
using CipherNaut.Key;

namespace CipherNaut.Interfaces;

public interface IVault : IDisposable
{
    public IFileSystem FileSystem { init;  }
    
    public IVaultKey Get (string keyReference);

    public IVaultKey Create(string keyReference, byte[] keyMaterial);
}