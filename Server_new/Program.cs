using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.ComponentModel;
using System.Runtime.Remoting.Messaging;
namespace Server_new
{
    internal class Program
    {
        static Dictionary<Socket, string> clientSockets = new Dictionary<Socket, string>();




        static string EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] iv)
        {
            // Проверяем аргументы
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length != 32)
                throw new ArgumentException("Ключ должен быть 256-битным!");
            if (iv == null || iv.Length != 16)
                throw new ArgumentException("Вектор инициализации должен быть 128-битным!");

            byte[] encrypted;

            // Создаем экземпляр алгоритма AES
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Создаем шифрующий поток
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Создаем поток памяти
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Создаем шифрующий поток на основе потока памяти
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        // Преобразуем строку в байтовый массив
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

                        // Записываем зашифрованные данные в поток памяти
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        csEncrypt.FlushFinalBlock();

                        // Получаем зашифрованные байты из потока памяти
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Возвращаем зашифрованные байты в виде base64-строки
            return Convert.ToBase64String(encrypted);
        }






        /*static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC; // Режим CBC
                aesAlg.Padding = PaddingMode.PKCS7; // Заполнение PKCS7
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }*/

        static string DecryptStringFromBytes_Aes(string cipherText, byte[] key, byte[] iv)
        {

            // Проверяем аргументы
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length != 32)
                throw new ArgumentException("Ключ должен быть 256-битным!");
            if (iv == null || iv.Length != 16)
                throw new ArgumentException("Вектор инициализации должен быть 128-битным!");

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            string plaintext = null;

            // Создаем экземпляр алгоритма AES
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Создаем дешифрующий поток
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Создаем поток памяти
                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    // Создаем дешифрующий поток на основе потока памяти
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Создаем буфер для хранения расшифрованных байтов
                        byte[] plainBytes = new byte[cipherBytes.Length];

                        // Читаем расшифрованные байты из потока в буфер
                        int decryptedByteCount = csDecrypt.Read(plainBytes, 0, plainBytes.Length);

                        // Преобразуем расшифрованные байты в строку
                        plaintext = Encoding.UTF8.GetString(plainBytes, 0, decryptedByteCount);
                    }
                }
            }

            return plaintext;
        }

        /*static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC; // Режим CBC
                aesAlg.Padding = PaddingMode.PKCS7; // Заполнение PKCS7
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;

        }*/


        static void Main(string[] args)
        {

            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
            //string publicKey = rsa.ToXmlString(false);
            //string privateKey = rsa.ToXmlString(true);

            // Создаем сокет для прослушивания входящих соединений
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Any, 8080);
            serverSocket.Bind(serverEndPoint);
            serverSocket.Listen(10);

            Console.WriteLine("Сервер запущен, ожидание подключений...");

            Aes myAes = Aes.Create();

            byte[] Key = myAes.Key;
            byte[] IV = myAes.IV;

            while (true)
            {
                // Ожидаем подключения нового клиента
                Socket clientSocket = serverSocket.Accept();
                


                // получаем никнейм клиента
                byte[] nickname_buffer = new byte[1024];
                int nickname_received = clientSocket.Receive(nickname_buffer);
                string nickname = Encoding.UTF8.GetString(nickname_buffer, 0, nickname_received);

                //получаем открытый ключ клиета
                byte[] Client_publicKey_buffer = new byte[1024];
                int Client_publicKey_received = clientSocket.Receive(Client_publicKey_buffer);

                //string Client_publicKey = Encoding.UTF8.GetString(Client_publicKey_buffer, 0, Client_publicKey_received);
                //UnicodeEncoding ByteConverter = new UnicodeEncoding();
                //string Client_publicKey = ByteConverter.GetBytes(Client_publicKey_buffer, 0, Client_publicKey_received);

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

                rsa.ImportCspBlob(Client_publicKey_buffer);
                
                // шфруем AES ключ с помощью RSA и отпраляем клиенту
                byte[] encrypted_key_Data = rsa.Encrypt(Key, false);
                
                clientSocket.Send(encrypted_key_Data);


                byte[] encrypted_IV_Data = rsa.Encrypt(IV, false);

                clientSocket.Send(encrypted_IV_Data);

                // Добавляем клиента в список подключенных
                clientSockets[clientSocket] = (nickname + "(" + clientSocket.RemoteEndPoint.ToString() + ")");


                Console.WriteLine($"Новое подключение: {(clientSockets[clientSocket])}");

                // Запускаем новый поток для обработки сообщений от клиента
                Thread thread = new Thread(() => HandleClient(clientSocket, Key, IV));
                thread.Start();
            }

        }

        static void HandleClient(Socket clientSocket, byte[] Key, byte[] IV)
        {
            byte[] buffer = new byte[1024];
            int bytesReceived;

            while (true)
            {
                /*try
                {
                    // Получаем сообщение от клиента
                    bytesReceived = clientSocket.Receive(buffer);
                    if (bytesReceived == 0)
                        break;

                    //string recieve_message = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                    string decrypt_message = DecryptStringFromBytes_Aes(buffer, Key, IV);
                    


                    


                    // Распечатываем сообщение в консоль
                    string message = (clientSockets[clientSocket]) + ":" + " " + decrypt_message;
                    //Console.WriteLine(message);

                    // Отправляем сообщение всем подключенным клиентам
                    BroadcastMessage(message, Key, IV);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при обработке клиента: {ex.Message}");
                    RemoveClient(clientSocket);
                    break;
                }*/


                // Получаем сообщение от клиента
                bytesReceived = clientSocket.Receive(buffer);
                if (bytesReceived == 0)
                    break;
                //byte[] data = new byte[bytesReceived];
                string recieve_message = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                string decrypt_message = DecryptStringFromBytes_Aes(recieve_message, Key, IV);






                // Распечатываем сообщение в консоль
                string message = (clientSockets[clientSocket]) + ":" + " " + decrypt_message;
                Console.WriteLine(message);

                

                // Отправляем сообщение всем подключенным клиентам
                BroadcastMessage(message, Key, IV);


            }

            // Закрываем соединение с клиентом
            RemoveClient(clientSocket);
        }

        static void BroadcastMessage(string message, byte[] Key, byte[] IV)
        {
            //byte[] data = Encoding.UTF8.GetBytes(message);
            string encrypt_message = EncryptStringToBytes_Aes(message, Key, IV);
            byte[] data = Encoding.UTF8.GetBytes(encrypt_message);
            foreach (var pair in clientSockets)
            {
                try
                {
                    byte[] buffer = new byte[1024];
                    buffer = data;

                    string recieve_message = Encoding.UTF8.GetString(buffer);
                    //byte[] recieve_message_bytes = Encoding.UTF8.GetBytes(recieve_message);
                    string decrypt_recieve_message = DecryptStringFromBytes_Aes(recieve_message, Key, IV);
                    Console.WriteLine(decrypt_recieve_message);

                    pair.Key.Send(data);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка при отправке сообщения клиенту {pair.Value}: {ex.Message}");
                    RemoveClient(pair.Key);
                }
            }
        }
        
        static void RemoveClient(Socket clientSocket)
        {
            if (clientSockets.ContainsKey(clientSocket))
            {
                Console.WriteLine($"Отключен пользоватль: {clientSockets[clientSocket]}");
                clientSockets.Remove(clientSocket);
                clientSocket.Shutdown(SocketShutdown.Both);
                clientSocket.Close();
            }
        } 

    }
}
