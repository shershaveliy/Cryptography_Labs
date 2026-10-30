using System;
using System.IO;
using System.Threading.Tasks;

namespace Lab1
{
    public static class SelfTests
    {
        private static int checks;

        public static void Check(bool condition, string message)
        {
            if (!condition)
            {
                throw new Exception("Не пройдена проверка: " + message);
            }

            checks++;
        }

        public static ISymmetricCipher NewCipher(int keySize)
        {
            if (keySize == 8)
            {
                return new Des();
            }

            return new Deal();
        }

        /* Запускает проверки без NUnit и других тестовых пакетов.
           Сначала проверяются перестановки, известный шифртекст DES, его раундовые
           ключи, CBC и шесть примеров DEAL. Затем обычные вложенные циклы перебирают
           4 длины ключа, 7 режимов, 4 набивки и 6 размеров сообщения около границ блока.
           Сравниваются восстановленные данные и неизменность исходного массива.
           Для файлов отдельно проверяются настоящие нули на конце с набивкой Zeros,
           для массивов — перегрузки с готовым выходным буфером. Последняя проверка
           должна отклонить неправильную PKCS7. Временные файлы удаляются в finally.
           Первая ошибка останавливает запуск; при успехе выводится число проверок. */
        public static async Task Run()
        {
            checks = 0;
            byte[] b = { 0x92 };
            int[] first = { 0, 1, 2, 3 };
            int[] one = { 1, 2, 3, 4 };
            BitIndexDirection most = BitIndexDirection.MostToLeastSignificant;
            BitIndexDirection least = BitIndexDirection.LeastToMostSignificant;

            byte[] result = BitPermutation.Permute(b, first, most, BitIndexBase.Zero);
            Check(Utils.Hex(result) == "90", "MSB с нуля и неполный байт");
            result = BitPermutation.Permute(b, first, least, BitIndexBase.Zero);
            Check(Utils.Hex(result) == "02", "LSB с нуля и неполный байт");
            result = BitPermutation.Permute(b, one, most, BitIndexBase.One);
            Check(Utils.Hex(result) == "90", "MSB с единицы");
            result = BitPermutation.Permute(b, one, least, BitIndexBase.One);
            Check(Utils.Hex(result) == "02", "LSB с единицы");

            result = BitPermutation.Permute(new byte[0], new int[0], most, BitIndexBase.One);
            Check(result.Length == 0, "Пустая таблица");
            int[] repeats = { 1, 1, 1, 2, 2, 2, 3, 3 };
            result = BitPermutation.Permute(new byte[] { 0xA0 }, repeats, most, BitIndexBase.One);
            Check(Utils.Hex(result) == "E3", "Повторы P-блока");
            int[] acrossBytes = { 16, 1, 10, 7, 4, 13, 8, 11 };
            result = BitPermutation.Permute(new byte[] { 0xB2, 0x65 }, acrossBytes, most, BitIndexBase.One);
            Check(Utils.Hex(result) == "F9", "Граница входных байтов");

            bool rejected = false;
            try
            {
                BitPermutation.Permute(b, new int[] { 9 }, most, BitIndexBase.One);
            }
            catch (ArgumentException)
            {
                rejected = true;
            }

            Check(rejected, "Неверный номер бита отклонён");
            Des des = new Des();
            des.SetKey(Utils.Hex("133457799BBCDFF1"));
            byte[] plain = Utils.Hex("0123456789ABCDEF");
            byte[] encrypted = des.Encrypt(plain);
            Check(Utils.Hex(encrypted) == "85E813540F0AB405", "Контрольный вектор DES");
            Check(Utils.Equal(des.Decrypt(encrypted), plain), "Обращение контрольного блока DES");
            byte[][] roundKeys = new DesKeyExpansion().ExpandKey(Utils.Hex("133457799BBCDFF1"));
            Check(Utils.Hex(roundKeys[0]) == "1B02EFFC7072", "Первый раундовый ключ DES");
            Check(Utils.Hex(roundKeys[15]) == "CB3D8B0E17F5", "Последний раундовый ключ DES");
            SymmetricCipherContext cbc = new SymmetricCipherContext(
                new Des(), Utils.Hex("0123456789ABCDEF"), CipherMode.CBC,
                PaddingMode.PKCS7, Utils.Hex("1234567890ABCDEF"));
            byte[] cbcData = Utils.Hex("4E6F77206973207468652074696D6520666F7220616C6C20");
            byte[] cbcResult = await cbc.EncryptAsync(cbcData);
            string expectedCbc = "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6";
            Check(Utils.Hex(Utils.Part(cbcResult, 0, 24)) == expectedCbc, "Контрольный CBC-DES");
            DealVectors.Run();
            Random random = new Random(12345);
            int[] keySizes = new int[] { 8, 16, 24, 32 };
            string temporary = Path.Combine(Path.GetTempPath(), "CryptoLab-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temporary);
            try
            {
                for (int k = 0; k < keySizes.Length; k++)
                {
                    byte[] key = new byte[keySizes[k]];
                    random.NextBytes(key);
                    int size = 16;
                    if (key.Length == 8)
                    {
                        size = 8;
                    }

                    byte[] iv = new byte[size];
                    random.NextBytes(iv);
                    iv[size - 1] = (byte)(iv[size - 1] | 1);
                    int[] lengths = new int[] { 0, 1, size - 1, size, size + 1, 2 * size + 3 };
                    for (int m = 0; m < 7; m++)
                    {
                        for (int p = 0; p < 4; p++)
                        {
                            SymmetricCipherContext context = new SymmetricCipherContext(
                                NewCipher(key.Length), key, (CipherMode)m, (PaddingMode)p, iv);
                            for (int l = 0; l < lengths.Length; l++)
                            {
                                byte[] data = new byte[lengths[l]];
                                random.NextBytes(data);
                                if (data.Length > 0)
                                {
                                    data[data.Length - 1] = 0;
                                }

                                byte[] copy = (byte[])data.Clone();
                                byte[] enc = await context.EncryptAsync(data);
                                byte[] dec = await context.DecryptAsync(enc, data.Length);
                                Check(Utils.Equal(data, dec), "Восстановление: key=" + key.Length
                                    + ", mode=" + m + ", pad=" + p + ", len=" + data.Length);
                                Check(Utils.Equal(data, copy), "Вход не изменился");
                            }
                        }

                        SymmetricCipherContext files = new SymmetricCipherContext(
                            NewCipher(key.Length), key, (CipherMode)m, PaddingMode.Zeros, iv);
                        byte[] fileData = new byte[] { 1, 2, 0, 0, 0, 0, 0, 0, 0 };
                        string source = Path.Combine(temporary, "source.bin");
                        string locked = Path.Combine(temporary, "locked.bin");
                        string restored = Path.Combine(temporary, "restored.bin");
                        File.WriteAllBytes(source, fileData);
                        await files.EncryptAsync(source, locked);
                        await files.DecryptAsync(locked, restored);
                        Check(Utils.Equal(File.ReadAllBytes(restored), fileData), "Файлы и конечные нули");
                    }

                    SymmetricCipherContext buffers = new SymmetricCipherContext(
                        NewCipher(key.Length), key, CipherMode.ECB, PaddingMode.PKCS7);
                    byte[] input = new byte[] { 1, 2, 3 };
                    byte[] output = new byte[buffers.GetEncryptedLength(input.Length)];
                    byte[] back = new byte[input.Length];
                    await buffers.EncryptAsync(input, output);
                    await buffers.DecryptAsync(output, back);
                    Check(Utils.Equal(input, back), "Перегрузки с выходным массивом");
                }

                rejected = false;
                try
                {
                    SymmetricCipherContext invalid = new SymmetricCipherContext(new Des(), new byte[8], CipherMode.ECB, PaddingMode.PKCS7);
                    Des raw = new Des();
                    raw.SetKey(new byte[8]);
                    await invalid.DecryptAsync(raw.Encrypt(new byte[8]));
                }
                catch (ArgumentException)
                {
                    rejected = true;
                }

                Check(rejected, "Некорректная PKCS7 отклонена");
            }
            finally
            {
                Directory.Delete(temporary, true);
            }

            Console.WriteLine("Пройдено проверок: " + checks);
        }
    }
}
