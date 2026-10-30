using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Lab1
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            try
            {
                await Run(args);
            }
            catch (Exception error)
            {
                Console.WriteLine("Ошибка: " + error.Message);
                Environment.ExitCode = 1;
            }
        }

        private static async Task Run(string[] args)
        {
            string command;

            if (args.Length == 0)
            {
                Console.WriteLine("1 — SelfTests (");
                Console.WriteLine("2 — демонстрация DES и DEAL на массивах и файлах");
                Console.WriteLine("3 — обработать свой файл");
                command = Console.ReadLine();
            }
            else
            {
                command = args[0];
            }

            if (command == "1" || command == "test")
            {
                await SelfTests.Run();
            }
            else if (command == "2" || command == "demo")
            {
                await DesDemo.Run();
                await DealDemo.Run();
            }
            else if (command == "3")
            {
                await InteractiveFile();
            }
            else if (command == "file")
            {
                if (args.Length != 9)
                    throw new ArgumentException(
                        "file encrypt|decrypt DES|DEAL MODE PADDING KEY_HEX IV_HEX|- INPUT OUTPUT");

                await ProcessFile(args[1], args[2], args[3], args[4],
                    args[5], args[6], args[7], args[8]);
            }
            else
            {
                throw new ArgumentException("Выберите 1, 2, 3 или команду test, demo, file.");
            }
        }

        /* Для ECB вместо IV вводится «-».*/
        private static async Task InteractiveFile()
        {
            Console.Write("Действие (encrypt/decrypt): ");
            string action = Console.ReadLine();
            Console.Write("Алгоритм (DES/DEAL): ");
            string algorithm = Console.ReadLine();
            Console.Write("Режим (ECB/CBC/PCBC/CFB/OFB/CTR/RandomDelta): ");
            string mode = Console.ReadLine();
            Console.Write("Набивка (Zeros/AnsiX923/PKCS7/ISO10126): ");
            string padding = Console.ReadLine();
            Console.Write("Ключ HEX: ");
            string key = Console.ReadLine();
            Console.Write("IV HEX (для ECB введите -): ");
            string iv = Console.ReadLine();
            Console.Write("Путь исходного файла: ");
            string input = Console.ReadLine().Trim('"');
            Console.Write("Путь результата: ");
            string output = Console.ReadLine().Trim('"');
            await ProcessFile(action, algorithm, mode, padding, key, iv, input, output);
        }

        private static async Task ProcessFile(
            string action, string algorithm,
            string modeText, string paddingText,
            string keyHex, string ivHex,
            string input, string output)
        {
            ISymmetricCipher cipher;
            if (algorithm.ToUpperInvariant() == "DES")
            {
                cipher = new Des();
            }
            else if (algorithm.ToUpperInvariant() == "DEAL")
            {
                cipher = new Deal();
            }
            else
            {
                throw new ArgumentException("Алгоритм: DES или DEAL.");
            }

            CipherMode mode = (CipherMode)Enum.Parse(typeof(CipherMode), modeText, true);
            PaddingMode padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), paddingText, true);
            byte[] iv = null;
            if (ivHex != "-")
            {
                iv = Utils.Hex(ivHex);
            }

            byte[] key = Utils.Hex(keyHex);
            SymmetricCipherContext context = new SymmetricCipherContext(cipher, key, mode, padding, iv);
            if (action.ToLowerInvariant() == "encrypt")
            {
                await context.EncryptAsync(input, output);
            }
            else if (action.ToLowerInvariant() == "decrypt")
            {
                await context.DecryptAsync(input, output);
            }
            else
            {
                throw new ArgumentException("Действие: encrypt или decrypt.");
            }

            Console.WriteLine("Готово: " + Path.GetFullPath(output));
        }
    }
}
