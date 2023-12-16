using CipherNaut;
using CipherNaut.Key;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

// Create the vault if needed
var vaultFolderName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ciphernaut");
if (!Directory.Exists(vaultFolderName)) Directory.CreateDirectory(vaultFolderName);

var ephemeralKeyPair = IVaultKey.GenerateEphemeralEcKey();
var ephemeralPublicKey = (ECPublicKeyParameters)ephemeralKeyPair.Public;

var vaultFileName = Path.Combine(vaultFolderName, "ciphernaut.litedb");

using var vault = VaultFactory.Create(vaultFileName, ephemeralPublicKey);
// Test key is a sha256 hash of the string "This is a test"
var testInput = "This is a test"u8.ToArray();
var testKeyHash = new Sha256Digest();
var testKey = new byte[testKeyHash.GetDigestSize()];
testKeyHash.BlockUpdate(testInput, 0, testInput.Length);
testKeyHash.DoFinal(testKey, 0);

vault.Create("test", testKey);