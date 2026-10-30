using System;
using System.IO;
using System.Threading.Tasks;

namespace Lab1
{
    public static class DesDemo
    {
        /* Демонстрация DES: перебирает режимы и размеры сообщений,
           шифрует и восстанавливает массивы, затем сравнивает байты.
           Используется ключ DES длиной 8 байтов.
           При сборке Samples копируется рядом с программой. Шифртекст
           и восстановленные файлы записываются в Output, исходники не меняются.
           Для краткости демонстрация использует PKCS7; все набивки проверяет SelfTests.
           */
        public static async Task Run()
        {
            int[] keySizes = { 8 };
            int[] lengths = { 0, 1, 7, 8, 9, 100 };
            string folder = AppContext.BaseDirectory;
            string[] files = Directory.GetFiles(Path.Combine(folder, "Samples"));
            string outputFolder = Path.Combine(folder, "Output");
            Directory.CreateDirectory(outputFolder);

            foreach (int keySize in keySizes)
            {
                Console.WriteLine("Des: ключ " + keySize * 8 + " битов");

                foreach (CipherMode mode in Enum.GetValues(typeof(CipherMode)))
                {
                    byte[] key = CreateRandomBytes(keySize);
                    byte[] iv = CreateRandomBytes(8);
                    iv[iv.Length - 1] |= 1;
                    SymmetricCipherContext context = new SymmetricCipherContext(
                        new Des(), key, mode, PaddingMode.PKCS7, iv);

                    foreach (int length in lengths)
                    {
                        byte[] data = CreateRandomBytes(length);
                        byte[] encrypted = await context.EncryptAsync(data);
                        byte[] restored = await context.DecryptAsync(encrypted);
                        if (!Utils.Equal(data, restored))
                            throw new Exception("Не восстановлен массив Des.");
                        Console.WriteLine("  " + mode + ": " + length + " байтов -> " + encrypted.Length + ", OK");
                    }

                    foreach (string file in files)
                    {
                        string input = file;
                        string output = Path.Combine(outputFolder, "Des" + keySize * 8 + "_" + mode + "_" + Path.GetFileName(file));
                        await context.EncryptAsync(input, output + ".enc");
                        await context.DecryptAsync(output + ".enc", output);
                        byte[] original = await File.ReadAllBytesAsync(input);
                        byte[] restored = await File.ReadAllBytesAsync(output);
                        if (!Utils.Equal(original, restored))
                            throw new Exception("Не восстановлен файл " + file);
                    }

                    Console.WriteLine("  " + mode + ": файлов восстановлено " + files.Length + ", OK");
                }
            }

            Console.WriteLine("Результаты: " + outputFolder);
        }


        private static byte[] CreateRandomBytes(int length)
        {
            byte[] result = new byte[length];
            Random.Shared.NextBytes(result);
            return result;
        }
    }
}
