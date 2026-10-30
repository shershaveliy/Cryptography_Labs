using System;
using System.IO;
using System.Threading.Tasks;

namespace Lab1
{
    public static class DealDemo
    {
        /* Демонстрация DEAL: перебирает режимы и размеры сообщений,
           шифрует и восстанавливает массивы, затем сравнивает байты.
           Перебираются ключи DEAL длиной 16, 24 и 32 байта.
           При сборке Samples копируется рядом с программой. Шифртекст
           и восстановленные файлы записываются в Output, исходники не меняются.
           Для краткости демонстрация использует PKCS7; все набивки проверяет SelfTests.
            */
        public static async Task Run()
        {
            int[] keySizes = { 16, 24, 32 };
            int[] lengths = { 0, 1, 15, 16, 17, 100 };
            string folder = AppContext.BaseDirectory;
            string[] files = Directory.GetFiles(Path.Combine(folder, "Samples"));
            string outputFolder = Path.Combine(folder, "Output");
            Directory.CreateDirectory(outputFolder);

            foreach (int keySize in keySizes)
            {
                Console.WriteLine("Deal: ключ " + keySize * 8 + " битов");

                foreach (CipherMode mode in Enum.GetValues(typeof(CipherMode)))
                {
                    byte[] key = CreateRandomBytes(keySize);
                    byte[] iv = CreateRandomBytes(16);
                    iv[iv.Length - 1] |= 1;
                    SymmetricCipherContext context = new SymmetricCipherContext(
                        new Deal(), key, mode, PaddingMode.PKCS7, iv);

                    foreach (int length in lengths)
                    {
                        byte[] data = CreateRandomBytes(length);
                        byte[] encrypted = await context.EncryptAsync(data);
                        byte[] restored = await context.DecryptAsync(encrypted);
                        if (!Utils.Equal(data, restored))
                            throw new Exception("Не восстановлен массив Deal.");
                        Console.WriteLine("  " + mode + ": " + length + " байтов -> " + encrypted.Length + ", OK");
                    }

                    foreach (string file in files)
                    {
                        string input = file;
                        string output = Path.Combine(outputFolder, "Deal" + keySize * 8 + "_" + mode + "_" + Path.GetFileName(file));
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

        /* Создаёт массив нужной длины и заполняет случайными байтами.
           Используется только для ключей демонстрации;
           */
        private static byte[] CreateRandomBytes(int length)
        {
            byte[] result = new byte[length];
            Random.Shared.NextBytes(result);
            return result;
        }
    }
}
