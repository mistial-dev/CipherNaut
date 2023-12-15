using System.IO.Abstractions;
using CipherNaut.Key;
using LiteDB;
using LiteDB.Engine;
using Org.BouncyCastle.Crypto.Parameters;

namespace CipherNaut.Vault;

internal class VaultImpl : IVault
{
    /// <summary>
    /// Holds the file system implementation.
    /// </summary>
    public required IFileSystem FileSystem { get; init; } = new FileSystem();

    /// <summary>
    /// Stores the name of the database file.
    /// </summary>
    public string FileName { get; init; } = "ciphernaut.litedb";
    
    /// <summary>
    /// Memory stream that holds the contents of the vault database.
    /// </summary>
    private readonly MemoryStream _memoryStream;
    
    /// <summary>
    /// Public key used for wrapping and unwrapping keys in the vault.
    /// </summary>
    public required ECPublicKeyParameters PublicKey { get; init; }
    
    /// <summary>
    /// Vault database instance.
    /// </summary>
    private readonly ILiteDatabase _db;

    /// <summary>
    /// Initializes a new instance of the VaultImpl class with the provided file system implementation and file name.
    /// </summary>
    internal VaultImpl ()
    {
        // Create a memory stream to hold the contents of the database.
        _memoryStream = new MemoryStream();
        
        // If the file exists, load it into the memory stream.
        if (FileSystem.File.Exists(FileName))
        {
            using var fileStream = FileSystem.File.OpenRead(FileName);
            fileStream.CopyTo(_memoryStream);
            _memoryStream.Position = 0;
            _db = new LiteDatabase(_memoryStream);
        }
        else
        {
            // Initialize the database.
            _db = new LiteDatabase(_memoryStream);
            _db.Rebuild(new RebuildOptions { Collation = new Collation("en-US/IgnoreCase") });
            _db.GetCollection<IVaultKey>("keys").EnsureIndex(x => x.KeyReference, true);
        }
        
        // Create the database and set up the collections and indexes.
    }

    /// <summary>
    /// Disposes of the VaultImpl instance.
    /// </summary>
    public void Dispose()
    {
        // Clean up the database instance.
        _db.Dispose();

        // Write the contents of the memory stream to the file.
        using var fileStream = FileSystem.File.Create(FileName);
        _memoryStream.Position = 0;
        _memoryStream.CopyTo(fileStream);
        _memoryStream.Dispose();
    }

    /// <summary>
    /// Gets the vault key for the specified key reference.
    /// </summary>
    /// <param name="keyReference">Key Reference for the Database</param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public IVaultKey Get(string keyReference)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Creates a new key with the specified key reference and key material.
    /// </summary>
    /// <param name="keyReference"></param>
    /// <param name="keyMaterial"></param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <returns></returns>
    public IVaultKey Create(string keyReference, byte[] keyMaterial)
    {
        var key = new VaultKeyImpl()
        {
            KeyReference = keyReference,
            VaultPublicKey = PublicKey,
        };
        key.Wrap(keyMaterial);
        KeyCollection.Insert(key);
        return key;
    }

    /// <summary>
    /// Returns the key collection.
    /// </summary>
    private ILiteCollection<IVaultKey> KeyCollection => _db.GetCollection<IVaultKey>("keys");
}