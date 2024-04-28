using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using System.IO;
using System;


internal class Program
{
    private static void Main(string[] args)
    {
        try
        {
            Console.WriteLine("Input User");
            var username = Console.ReadLine();
            Console.WriteLine("Input Password");
            var password = Console.ReadLine();

            // Get additional entropy from environment variable
            string? additionalEntropyStr = Environment.GetEnvironmentVariable("ADDITIONAL_ENTROPY");

            if (string.IsNullOrWhiteSpace(additionalEntropyStr))
            {
                throw new Exception("Environment variable ADDITIONAL_ENTROPY is not set or empty. Aborting.");
            }

            // Convert entropy to byte array
            byte[] additionalEntropy = ConvertStringToByteArray(additionalEntropyStr);

            // Create JSON object
            var credentials = new { Username = username, Password = password };
            string json = JsonConvert.SerializeObject(credentials);

            // Encrypt the data using DataProtectionScope.CurrentUser. The result can be decrypted
            // only by the same current user.
            var encryptedData = EncryptData(json, additionalEntropy);

            // Console.WriteLine(encryptedData.ToString());
            WiteToConfigFile(encryptedData);
            // return null;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("Data was not encrypted. An error occurred.");
            Console.BackgroundColor = ConsoleColor.Red;
            Console.WriteLine(e.ToString());
        }


    }

    static byte[] EncryptData(string data, byte[] entropy)
    {
        try
        {
            // Encrypt the data using DataProtectionScope.CurrentUser. The result can be decrypted
            // only by the same current user.
#pragma warning disable CA1416 // Validate platform compatibility
            return ProtectedData.Protect(Encoding.UTF8.GetBytes(data), entropy, DataProtectionScope.CurrentUser);
#pragma warning restore CA1416 // Validate platform compatibility
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("Data was not encrypted. An error occurred.");
            Console.WriteLine(e.ToString());
            throw;
        }
    }

    static byte[] ConvertStringToByteArray(string str)
    {
        string[] byteStrings = str.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        byte[] byteArray = new byte[byteStrings.Length];
        for (int i = 0; i < byteStrings.Length; i++)
        {
            if (!byte.TryParse(byteStrings[i], out byteArray[i]))
            {
                throw new Exception($"Error parsing byte at index {i}: {byteStrings[i]} is not a valid byte.");
            }
        }
        return byteArray;
    }

    static void WiteToConfigFile(byte[] configurationData)
    {
        if (configurationData != null)
        {
            // Write encrypted data to JSON file
            File.WriteAllBytes("encrypted_credentials.json", configurationData);
            Console.WriteLine("Encrypted credentials have been written to 'encrypted_credentials.json'");
        }
        else
        {
            throw new Exception("Encryption failed.");
        }
    }
}