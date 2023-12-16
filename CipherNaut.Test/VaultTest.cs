using System.IO.Abstractions;
using System.IO.Abstractions.TestingHelpers;
using CipherNaut.Key;
using CipherNaut.Piv;
using CipherNaut.Vault;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace CipherNaut.Test;

public class VaultTest
{
    /// <summary>
    /// Test AES-128 key
    /// </summary>
    private readonly byte[] _testAes128Key =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    /// <summary>
    /// Test AES-256 key
    /// </summary>
    private readonly byte[] _testAes256Key =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F
    };

    /// <summary>
    /// Odd length test key
    /// </summary>
    private readonly byte[] _testOddLengthKey = {
        0x00, 0x01, 0x02, 0x03
    };

    /// <summary>
    /// Key reference for the test AES-128 key
    /// </summary>
    private const string TestAes128KeyReference = "test-aes128";

    /// <summary>
    /// Key reference for the test AES-256 key
    /// </summary>
    private const string TestAes256KeyReference = "test-aes256";

    /// <summary>
    /// Key reference for the odd length test key
    /// </summary>
    private const string TestOddLengthKeyReference = "test-odd-length";

    /// <summary>
    /// Mock filesystem
    /// </summary>
    private IFileSystem? _fileSystem;

    /// <summary>
    /// Public key for the vault
    /// </summary>
    private ECPublicKeyParameters? _publicKey;

    /// <summary>
    /// Vault instance
    /// </summary>
    private IVault? _vault;

    /// <summary>
    /// Mock PIV card
    /// </summary>
    private IPivCard? _pivCard;

    // Path to the public and private key file
    private const string VaultKeyFile = @"c:\keys\testkey1-prime256v1.pem";
    private const string TestKeyFile = @"c:\keys\testkey2-prime256v1.pem";

    /// <summary>
    /// Set up the test environment
    /// </summary>
    [SetUp]
    public void Setup()
    {
        // Virtual filesystem contains the public key but does not contain the vault database yet
        _fileSystem = new MockFileSystem(
            new Dictionary<string, MockFileData>
            {
                // Populate the filesystem with the test data.
                { VaultKeyFile, new MockFileData(File.ReadAllText("data/testkey1-prime256v1.pem")) },
                { TestKeyFile, new MockFileData(File.ReadAllText("data/testkey2-prime256v1.pem")) }
            });

        // Read the test key and create a mock PIV card.
        var pemReader = new PemReader(new StringReader(_fileSystem.File.ReadAllText(VaultKeyFile)));
        var ecKeyParameters = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        _pivCard = new MockPivCard
        {
            MockKey = ecKeyParameters
        };
        _publicKey = _pivCard.PublicKeyParameters;

        // Instantiate the vault.
        _vault = VaultFactory.Create(_fileSystem, "ciphernaut.db", _publicKey);
    }

    /// <summary>
    /// Test key agreement
    /// </summary>
    [Test]
    public void TestKeyAgreement()
    {
        // Read the test keys from the filesystem
        var pemReader = new PemReader(new StringReader(_fileSystem!.File.ReadAllText(VaultKeyFile)));
        var firstKey = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        pemReader = new PemReader(new StringReader(_fileSystem.File.ReadAllText(TestKeyFile)));
        var secondKey = (AsymmetricCipherKeyPair)pemReader.ReadObject();

        // Extract the public and private keys from the key pairs
        var firstPrivateKey = (ECPrivateKeyParameters)firstKey.Private;
        var firstPublicKey = (ECPublicKeyParameters)firstKey.Public;
        var secondPrivateKey = (ECPrivateKeyParameters)secondKey.Private;
        var secondPublicKey = (ECPublicKeyParameters)secondKey.Public;

        // Perform key agreement
        var firstSharedSecret = IVaultKey.EcKeyAgreement(firstPrivateKey, secondPublicKey);
        var secondSharedSecret = IVaultKey.EcKeyAgreement(secondPrivateKey, firstPublicKey);

        // Compare the shared secrets
        Assert.That(firstSharedSecret, Is.EqualTo(secondSharedSecret));
    }

    /// <summary>
    /// Test key wrapping
    /// </summary>
    [Test]
    public void TestKeyWrapping()
    {
        // Wrap the test key and store it in the vault.
        var testKey1 = _vault!.Create(TestAes128KeyReference, _testAes128Key);
        var testKey2 = _vault!.Create(TestAes256KeyReference, _testAes256Key);
        var testKey3 = _vault!.Create(TestOddLengthKeyReference, _testOddLengthKey);

        // Retrieve the keys from the vault.
        var retrievedKey = testKey1.Unwrap(_pivCard!);
        var retrievedKey2 = testKey2.Unwrap(_pivCard!);
        var retrievedKey3 = testKey3.Unwrap(_pivCard!);

        // Compare the retrieved keys to the original keys.
        Assert.Multiple(() =>
        {
            Assert.That(retrievedKey, Is.EqualTo(_testAes128Key));
            Assert.That(retrievedKey2, Is.EqualTo(_testAes256Key));
            Assert.That(retrievedKey3, Is.EqualTo(_testOddLengthKey));
        });
    }

    /// <summary>
    /// Ensure that the vault saves the public key when it is created, and that it is restored when the vault is reloaded.
    /// </summary>
    [Test]
    public void TestKeyRetention()
    {
        // Create a new vault
        var mockFileSystem = new MockFileSystem(new Dictionary<string, MockFileData>());

        var vault = VaultFactory.Create(mockFileSystem, "ciphernaut.db", _publicKey);
        vault.Dispose();
        vault = VaultFactory.Create(mockFileSystem, "ciphernaut.db");

        // Ensure that the vault contains the public key
        Assert.That(vault.PublicKey!.Q.GetEncoded(), Is.EqualTo(_publicKey!.Q.GetEncoded()));
    }
}