using System.IO.Abstractions;
using CipherNaut.Key;
using JetBrains.Annotations;
using LiteDB;
using LiteDB.Engine;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;

namespace CipherNaut.Vault;

internal class VaultImpl : IVault
{
    /// <summary>
    /// Holds the file system implementation.
    /// </summary>
    public required IFileSystem FileSystem { get; init; }

    /// <summary>
    /// Stores the name of the database file.
    /// </summary>
    public required string FileName { get; init; }

    /// <summary>
    /// Public key used for wrapping and unwrapping keys in the vault.
    /// </summary>
    public required ECPublicKeyParameters? PublicKey { get; set; }

    /// <summary>
    /// Vault database instance.
    /// </summary>
    private ILiteDatabase? _db;
    
    /// <summary>
    /// Initializes a new instance of the VaultImpl class with the provided file system implementation and file name.
    /// </summary>
    [PublicAPI]
    internal void Initialize ()
    {
        var memoryStream = new MemoryStream();

        // If the file exists, load it into the memory stream.
        if (FileSystem.File.Exists(FileName))
        {
            // Parse the file into an ASN.1 sequence.
            using var fileStream = FileSystem.File.OpenRead(FileName);
            using var tmpStream = new MemoryStream();
            // Read the file into a temporary memory stream.
            fileStream.CopyTo(tmpStream);
            tmpStream.Position = 0;
            var outerSequence = (DerSequence)Asn1Object.FromStream(tmpStream);
            var publicKeyBytes = ((DerOctetString)outerSequence[0]).GetOctets();
            var dbBytes = ((DerOctetString)outerSequence[1]).GetOctets();
                
            // Write the public key
            var curve = SecNamedCurves.GetByName("secp256r1");
            var publicKeyPoint = curve.Curve.DecodePoint(publicKeyBytes);
            PublicKey = new ECPublicKeyParameters("ECDSA", publicKeyPoint, SecObjectIdentifiers.SecP256r1);
                
            // Write the database to the memory stream.
            memoryStream.Write(dbBytes, 0, dbBytes.Length);
            memoryStream.Position = 0;
            _db = new LiteDatabase(memoryStream);
        }
        else
        {
            // Initialize the database.
            _db = new LiteDatabase(memoryStream);
            _db.Rebuild(new RebuildOptions { Collation = new Collation("en-US/IgnoreCase") });
            _db.GetCollection<IVaultKey>("keys").EnsureIndex(x => x.KeyReference, true);
        }
    }

    /// <summary>
    /// Disposes of the VaultImpl instance.
    /// </summary>
    public void Dispose()
    {
        // Clean up the database instance.
        _db?.Dispose();

        // Create a file stream to write the data to the file system.
        using var fileStream = FileSystem.File.Create(FileName);
        
        // Write the contents of the memory stream to the buffer.
        using var memoryStream = new MemoryStream();
        var dbBytes = new byte[memoryStream.Length];
        var copiedByes = memoryStream.Read(dbBytes, 0, dbBytes.Length);
        if (copiedByes != dbBytes.Length)
            throw new IOException("Failed to copy memory stream to buffer.");
        
        // Export the public key
        var publicKeyBytes = PublicKey.Q.GetEncoded();

        // Build an ASN.1 sequence containing the EC public key and the buffer
        var sequence = new DerSequence(
            new DerOctetString(publicKeyBytes),
            new DerOctetString(dbBytes));
        
        // Write the ASN.1 sequence to the file stream.
        var asn1Bytes = sequence.GetDerEncoded();
        fileStream.Write(asn1Bytes, 0, asn1Bytes.Length);
        
        // Clean up
        fileStream.Flush();
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
            VaultPublicKey = PublicKey
        };
        key.Wrap(keyMaterial);
        KeyCollection.Insert(key);
        return key;
    }

    /// <summary>
    /// Returns the key collection.
    /// </summary>
    private ILiteCollection<IVaultKey> KeyCollection
    {
        get
        {
            if (_db != null)
            {
                return _db.GetCollection<IVaultKey>("keys");
            }

            throw new InvalidOperationException("The database has not been initialized.");
        }
    }
}