using System.IO.Abstractions;
using System.Threading.Channels;
using CipherNaut.Piv;
using Spectre.Console;
using WSCT.Wrapper.Desktop.Core;

var fileSystem = new FileSystem();
var vaultFolderName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ciphernaut");
var vaultFileName = Path.Combine(vaultFolderName, "ciphernaut.db");

// Load the PIV card to get the public key parameters.
var context = new CardContext();
context.Establish();
context.ListReaders("YubiKey");
var allReaders = context.Readers;

// Prompt the user to select a reader.
var readerIndex = 0;
switch (allReaders.Length)
{
    case 0:
        Console.WriteLine("No readers found.");
        return;
    case 1:
        readerIndex = 0;
        break;
    default:
    {
        // Prompt the user to select a reader.
        var reader = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .AddChoices(allReaders)
                .Title("Select a reader")
        );
        readerIndex = Array.IndexOf(allReaders, reader);
        break;
    }
}

// Connect to the reader.
var readerName = allReaders[readerIndex];
var channel = new CardChannel(context, readerName);

// Create the PIV card.
var pivCard = new PcscPivCard(channel);
var publicKeyParameters = pivCard.PublicKeyParameters;
