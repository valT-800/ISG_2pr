using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Uzd_N2
{
    class Repository
    {

        public static string CBCEncryptStringToBytes(string plainText, string password)
        {
            //transform key to bytes
            var Key = GetKey(password);

            Aes aes = Aes.Create();
            
            // Set key and IV
            byte[] aesKey = new byte[32];
            
                Array.Copy(Key, 0, aesKey, 0, 32);
                aes.Key = Key;
                aes.Key = aesKey;
                aes.GenerateIV();

                aes.Mode = CipherMode.CBC;

                // Instantiate a new MemoryStream object to contain the encrypted bytes
                MemoryStream memoryStream = new MemoryStream();

                // Instantiate a new encryptor from our Aes object
                ICryptoTransform aesEncryptor = aes.CreateEncryptor();

                // Instantiate a new CryptoStream object to process the data and write it to the 
                // memory stream
                CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);

                // Convert the plainText string into a byte array
                byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);

                // Encrypt the input plaintext string
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);

                // Complete the encryption process
                cryptoStream.FlushFinalBlock();

                // Convert the encrypted data from a MemoryStream to a byte array
                byte[] cipherBytes = memoryStream.ToArray();

                // Close both the MemoryStream and the CryptoStream
                memoryStream.Close();
                cryptoStream.Close();

                // Convert the encrypted byte array to a base64 encoded string
                string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);

                // Return the encrypted data as a string
                return cipherText;
            }

        public static string CBCDecryptStringFromBytes(string cipherText, string password)
        {
            string plainText = String.Empty;
            
            var Key = GetKey(password);
 
            // Create an Aes object 
            // with the specified key and IV. 
            Aes aes = Aes.Create();

            byte[] IV = new byte[aes.BlockSize / 8];

            aes.Mode = CipherMode.CBC;

            // Set key and IV
            byte[] aesKey = new byte[32];
            Array.Copy(Key, 0, aesKey, 0, 32);
            aes.Key = aesKey;
            aes.IV = IV;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesDecryptor = aes.CreateDecryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            // Will contain decrypted plaintext

            try
            {
                // Convert the ciphertext string into a byte array
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                // Decrypt the input ciphertext string
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);

                // Complete the decryption process
                cryptoStream.FlushFinalBlock();

                // Convert the decrypted data from a MemoryStream to a byte array
                byte[] plainBytes = memoryStream.ToArray();

                // Convert the decrypted byte array to string
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                // Close both the MemoryStream and the CryptoStream
                memoryStream.Close();
                cryptoStream.Close();
            }

            // Return the decrypted data as a string
            return plainText;

        }
        public static string ECBEncryptStringToBytes(string plainText, string password)
        {
            //transform key to bytes
            var Key = GetKey(password);

            Aes aes = Aes.Create();

            // Set key
            byte[] aesKey = new byte[32];

            Array.Copy(Key, 0, aesKey, 0, 32);
            aes.Key = Key;
            aes.Key = aesKey;

            aes.Mode = CipherMode.ECB;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesEncryptor = aes.CreateEncryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);

            // Convert the plainText string into a byte array
            byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);

            // Encrypt the input plaintext string
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);

            // Complete the encryption process
            cryptoStream.FlushFinalBlock();

            // Convert the encrypted data from a MemoryStream to a byte array
            byte[] cipherBytes = memoryStream.ToArray();

            // Close both the MemoryStream and the CryptoStream
            memoryStream.Close();
            cryptoStream.Close();

            // Convert the encrypted byte array to a base64 encoded string
            string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);

            // Return the encrypted data as a string
            return cipherText;
        }

        public static string ECBDecryptStringFromBytes(string cipherText, string password)
        {
            string plainText = String.Empty;

            var Key = GetKey(password);

            // Create an Aes object 
            // with the specified key and IV. 
            Aes aes = Aes.Create();

            aes.Mode = CipherMode.ECB;

            // Set key and IV
            byte[] aesKey = new byte[32];
            Array.Copy(Key, 0, aesKey, 0, 32);
            aes.Key = aesKey;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesDecryptor = aes.CreateDecryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            // Will contain decrypted plaintext

            try
            {
                // Convert the ciphertext string into a byte array
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                // Decrypt the input ciphertext string
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);

                // Complete the decryption process
                cryptoStream.FlushFinalBlock();

                // Convert the decrypted data from a MemoryStream to a byte array
                byte[] plainBytes = memoryStream.ToArray();

                // Convert the decrypted byte array to string
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                // Close both the MemoryStream and the CryptoStream
                memoryStream.Close();
                cryptoStream.Close();
            }

            // Return the decrypted data as a string
            return plainText;

        }
        private static byte[] GetKey(string password)
        {
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            return key;
        }
    }
}
