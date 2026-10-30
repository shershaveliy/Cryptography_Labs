using System;
using System.IO;
using System.Numerics;
using System.Threading.Tasks;
// 2.4
namespace Lab1
{
    public enum CipherMode
    {
        ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
    }

    public enum PaddingMode
    {
        Zeros, AnsiX923, PKCS7, ISO10126
    }

    public class SymmetricCipherContext
    {
        private ISymmetricCipher cipher;//Шифр одного блока
        private CipherMode mode;
        private PaddingMode padding;
        private byte[] iv;//копия вектора инициализации
        private BigInteger delta;

        public SymmetricCipherContext(
            ISymmetricCipher cipher, byte[] key, CipherMode mode, PaddingMode padding,
            byte[] iv = null, params object[] modeArgs)
        {
            if (cipher == null)
                throw new ArgumentNullException(nameof(cipher));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (cipher.BlockSize < 1 || cipher.BlockSize > 255)
                throw new ArgumentException("Неверный размер блока.");
            if ((int)mode < 0 || (int)mode > 6)
                throw new ArgumentException("Неизвестный режим.");
            if ((int)padding < 0 || (int)padding > 3)
                throw new ArgumentException("Неизвестная набивка.");

            this.cipher = cipher;
            this.mode = mode;
            this.padding = padding;
            this.iv = new byte[cipher.BlockSize];

            if (mode != CipherMode.ECB)
            {
                if (iv == null || iv.Length != cipher.BlockSize)
                    throw new ArgumentException("IV должен иметь размер одного блока.");
                this.iv = (byte[])iv.Clone();
            }

            if (modeArgs == null)
                modeArgs = new object[0];

            if (mode == CipherMode.RandomDelta)
            {
                if (cipher.BlockSize % 2 != 0)
                    throw new ArgumentException("Для RandomDelta размер блока должен быть чётным.");

                int half = cipher.BlockSize / 2;//Первая половина seed, вторая delta
                byte[] step = new byte[half];
                Array.Copy(this.iv, half, step, 0, half);
                delta = new BigInteger(step, isUnsigned: true, isBigEndian: true);

                //в modeArgs можно передать шаг отдельно, если он есть, то перезапивыаем delta
                if (modeArgs.Length > 1)
                    throw new ArgumentException("Для RandomDelta передайте не более одного шага.");
                if (modeArgs.Length == 1)
                {
                    if (!(modeArgs[0] is BigInteger))
                        throw new ArgumentException("Дополнительный шаг должен иметь тип BigInteger.");
                    delta = (BigInteger)modeArgs[0];
                }

                BigInteger limit = BigInteger.One << (half * 8); //значения младшей половины от 0 до 2^h-1
                if (delta <= 0 || delta >= limit || delta.IsEven)
                    throw new ArgumentException("Шаг должен быть положительным, нечётным и помещаться в половину блока.");
            }
            else if (modeArgs.Length != 0)
                throw new ArgumentException("Отдельный шаг используется только в RandomDelta.");

            cipher.SetKey(key); //Подготовка раундовых ключей
        }

        public Task<byte[]> EncryptAsync(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            return Task.Run(() => Encrypt(data));
        }

        public Task<byte[]> DecryptAsync(byte[] data, int originalLength = -1)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            return Task.Run(() => Decrypt(data, originalLength));
        }

        public async Task EncryptAsync(byte[] data, byte[] result)
        {
            byte[] encrypted = await EncryptAsync(data);
            if (result == null || result.Length != encrypted.Length)
                throw new ArgumentException("Неверный размер массива результата.");
            Array.Copy(encrypted, result, result.Length);
        }

        public async Task DecryptAsync(byte[] data, byte[] result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));
            byte[] decrypted = await DecryptAsync(data, result.Length);
            if (decrypted.Length != result.Length)
                throw new ArgumentException("Неверный размер массива результата.");
            Array.Copy(decrypted, result, result.Length);
        }

        public int GetEncryptedLength(int length)
        {
            if (length < 0)
                throw new ArgumentException("Неверная длина.");
            int count = cipher.BlockSize - length % cipher.BlockSize;
            if (padding == PaddingMode.Zeros && count == cipher.BlockSize)//Zeros не добавляет целый лишний блок
                count = 0;
            return checked(length + count);
        }

        private byte[] Encrypt(byte[] data)
        {
            byte[] padded = ApplyPadding(data);
            return TransformBlocks(padded, false);
        }

        private byte[] Decrypt(byte[] data, int originalLength)
        {
            if (data.Length % cipher.BlockSize != 0)
                throw new ArgumentException("Размер шифртекста должен быть кратен размеру блока.");
            byte[] decrypted = TransformBlocks(data, true);
            return RemovePadding(decrypted, originalLength); //убираем набивку в конце сообщения
        }

        //режимы обработки послед блоков
        private byte[] TransformBlocks(byte[] data, bool decrypt)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    if (decrypt) return DecryptECB(data);
                    return EncryptECB(data);
                case CipherMode.CBC:
                    if (decrypt) return DecryptCBC(data);
                    return EncryptCBC(data);
                case CipherMode.PCBC:
                    if (decrypt) return DecryptPCBC(data);
                    return EncryptPCBC(data);
                case CipherMode.CFB:
                    if (decrypt) return DecryptCFB(data);
                    return EncryptCFB(data);
                case CipherMode.OFB:
                    return CryptOFB(data);
                case CipherMode.CTR:
                    return CryptCTR(data);
                case CipherMode.RandomDelta:
                    return CryptRandomDelta(data);
                default:
                    throw new ArgumentException("Неизвестный режим.");
            }
        }

        private byte[] EncryptECB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex => //блоки можно шифровать одновременно
            {
                int offset = blockIndex * cipher.BlockSize; //Начало текущего блока в массиве
                byte[] block = GetBlock(data, offset); //копирование блока данных
                byte[] encrypted = cipher.Encrypt(block); //выполнение DES или DEAL
                WriteBlock(result, encrypted, offset); //Записываем только свой участок результата
            });

            return result;
        }

        private byte[] DecryptECB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;
                byte[] block = GetBlock(data, offset);
                byte[] decrypted = cipher.Decrypt(block);
                WriteBlock(result, decrypted, offset);
            });

            return result;
        }


        private byte[] EncryptCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previous = iv;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] block = GetBlock(data, offset);
                byte[] encrypted = cipher.Encrypt(Utils.Xor(block, previous));
                WriteBlock(result, encrypted, offset);
                previous = encrypted;
            }

            return result;
        }

        private byte[] DecryptCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;
                byte[] previous = iv;
                if (blockIndex > 0)
                    previous = GetBlock(data, offset - cipher.BlockSize); //C_(i-1)
                byte[] block = GetBlock(data, offset); //C_i.
                byte[] decrypted = Utils.Xor(cipher.Decrypt(block), previous); //D(C_i) XOR C_(i-1)
                WriteBlock(result, decrypted, offset);
            });

            return result;
        }


        private byte[] EncryptPCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previousPlain = new byte[cipher.BlockSize];
            byte[] previousEncrypted = iv;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] block = GetBlock(data, offset);
                byte[] mixed = Utils.Xor(Utils.Xor(block, previousPlain), previousEncrypted);
                byte[] encrypted = cipher.Encrypt(mixed);
                WriteBlock(result, encrypted, offset);
                previousPlain = block;
                previousEncrypted = encrypted;
            }

            return result;
        }

        private byte[] DecryptPCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previousPlain = new byte[cipher.BlockSize];
            byte[] previousEncrypted = iv;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] block = GetBlock(data, offset);
                byte[] decrypted = cipher.Decrypt(block);
                byte[] plain = Utils.Xor(Utils.Xor(decrypted, previousPlain), previousEncrypted);
                WriteBlock(result, plain, offset);
                previousPlain = plain;
                previousEncrypted = block;
            }

            return result;
        }

        private byte[] EncryptCFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previous = iv;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                byte[] block = GetBlock(data, offset);
                byte[] encrypted = Utils.Xor(block, cipher.Encrypt(previous));
                WriteBlock(result, encrypted, offset);
                previous = encrypted;
            }

            return result;
        }

        private byte[] DecryptCFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;
                byte[] previous = iv;
                if (blockIndex > 0)
                    previous = GetBlock(data, offset - cipher.BlockSize);
                byte[] block = GetBlock(data, offset);
                byte[] plain = Utils.Xor(block, cipher.Encrypt(previous));
                WriteBlock(result, plain, offset);
            });

            return result;
        }

        private byte[] CryptOFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] gamma = iv;

            for (int offset = 0; offset < data.Length; offset += cipher.BlockSize)
            {
                gamma = cipher.Encrypt(gamma);
                byte[] block = GetBlock(data, offset);
                byte[] output = Utils.Xor(block, gamma);
                WriteBlock(result, output, offset);
            }

            return result;
        }

        private byte[] CryptCTR(byte[] data)
        {
            byte[] result = new byte[data.Length];
            int blockCount = data.Length / cipher.BlockSize;

            Parallel.For(0, blockCount, blockIndex =>
            {
                int offset = blockIndex * cipher.BlockSize;
                byte[] counter = CreateCounter(blockIndex);
                byte[] block = GetBlock(data, offset);
                byte[] output = Utils.Xor(block, cipher.Encrypt(counter));
                WriteBlock(result, output, offset);
            });

            return result;
        }

        // Random Delta Ti = seed || (i * delta mod 2^h).
        private byte[] CryptRandomDelta(byte[] data)
        {
            byte[] result = new byte[data.Length];
            int size = cipher.BlockSize;
            int half = size / 2;
            int blockCount = data.Length / size;
            BigInteger modulo = BigInteger.One << (half * 8);

            Parallel.For(0, blockCount, blockIndex =>
            {
                BigInteger value = blockIndex * delta % modulo;
                byte[] number = value.ToByteArray(isUnsigned: true, isBigEndian: true); //байты младшей половины
                byte[] counter = new byte[size];
                Array.Copy(iv, 0, counter, 0, half); //сохраняем seed неизменным
                Array.Copy(number, 0, counter, size - number.Length, number.Length); //выравниваем число вправо

                int offset = blockIndex * size;
                byte[] block = GetBlock(data, offset);
                byte[] output = Utils.Xor(block, cipher.Encrypt(counter));
                WriteBlock(result, output, offset);
            });

            return result;
        }

        private byte[] CreateCounter(long blockIndex)
        {
            byte[] counter = (byte[])iv.Clone();
            long carry = blockIndex;

            for (int i = counter.Length - 1; i >= 0 && carry > 0; i--) 
            {
                long sum = counter[i] + (carry & 255);
                counter[i] = (byte)(sum & 255);
                carry = (carry >> 8) + (sum >> 8);
            }

            return counter;
        }

        //Добивки
        private byte[] ApplyPadding(byte[] data)
        {
            int paddingSize = GetEncryptedLength(data.Length) - data.Length;//число добавляемых байтов
            byte[] result = new byte[data.Length + paddingSize];
            Array.Copy(data, result, data.Length);
            if (paddingSize == 0)
                return result;

            switch (padding){
                case PaddingMode.Zeros:
                    break;
                case PaddingMode.AnsiX923:
                    result[result.Length - 1] = (byte)paddingSize;
                    break;
                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < result.Length; i++)
                        result[i] = (byte)paddingSize;
                    break;
                case PaddingMode.ISO10126:
                    Random random = new Random();
                    for (int i = data.Length; i < result.Length - 1; i++)
                        result[i] = (byte)random.Next(256);
                    result[result.Length - 1] = (byte)paddingSize;
                    break;
            }

            return result;
        }

        private byte[] RemovePadding(byte[] data, int originalLength)
        {
            if (originalLength < -1)
                throw new ArgumentException("Неверная исходная длина.");
            if (padding != PaddingMode.Zeros && data.Length == 0)
                throw new ArgumentException("Отсутствует блок с набивкой.");

            int count; //число байтов, которые надо удалить с конца
            if (padding == PaddingMode.Zeros)
            {
                if (originalLength < 0 || originalLength > data.Length)
                    throw new ArgumentException("Для Zeros передайте исходную длину сообщения.");
                count = data.Length - originalLength;
                if (count >= cipher.BlockSize)
                    throw new ArgumentException("Неверная длина Zeros-набивки.");
                for (int i = originalLength; i < data.Length; i++)
                    if (data[i] != 0)
                        throw new ArgumentException("Повреждена Zeros-набивка.");
            }
            else
            {
                count = data[data.Length - 1]; //остальные набивки хранят длину в последнем байте
                if (count < 1 || count > cipher.BlockSize || count > data.Length)
                    throw new ArgumentException("Неверная длина набивки.");

                for (int i = data.Length - count; i < data.Length; i++)
                {
                    if (padding == PaddingMode.PKCS7 && data[i] != count)
                        throw new ArgumentException("Повреждена PKCS7-набивка.");
                    if (padding == PaddingMode.AnsiX923 && i < data.Length - 1 && data[i] != 0)
                        throw new ArgumentException("Повреждена ANSI X.923-набивка.");
                }
            }

            int length = data.Length - count;
            if (originalLength >= 0 && originalLength != length)
                throw new ArgumentException("Длина сообщения не совпала с ожидаемой.");
            byte[] result = new byte[length];
            Array.Copy(data, result, length);
            return result;
        }

        public async Task EncryptAsync(string inputPath, string outputPath)
        {
            if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Пути исходного файла и результата должны различаться.");
            byte[] data = await File.ReadAllBytesAsync(inputPath);
            byte[] encrypted = await EncryptAsync(data);
            byte[] result = new byte[12 + encrypted.Length]; // Заголовок из 12 байтов и затем шифртекст
            result[0] = 67; // ASCII C.
            result[1] = 76; // ASCII L.
            result[2] = 66; // ASCII B.
            result[3] = 49; // ASCII 1: вместе получается метка CLB1.
            Array.Copy(Utils.ToBytes((ulong)data.Length, 8), 0, result, 4, 8); //Сохраняем исходную длину
            Array.Copy(encrypted, 0, result, 12, encrypted.Length); // Дописываем зашифрованные данные
            await File.WriteAllBytesAsync(outputPath, result);
        }

        public async Task DecryptAsync(string inputPath, string outputPath)
        {
            if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase)) // Не заменяем исходный шифртекст.
                throw new ArgumentException("Пути исходного файла и результата должны различаться.");
            byte[] file = await File.ReadAllBytesAsync(inputPath);
            if (file.Length < 12 || file[0] != 67 || file[1] != 76 || file[2] != 66 || file[3] != 49)
                throw new ArgumentException("Это не файл формата CLB1.");

            byte[] lengthBytes = new byte[8];
            Array.Copy(file, 4, lengthBytes, 0, 8);
            ulong length = Utils.ToUInt64(lengthBytes);
            if (length > int.MaxValue)
                throw new ArgumentException("Файл слишком велик для массива.");

            byte[] encrypted = new byte[file.Length - 12];
            Array.Copy(file, 12, encrypted, 0, encrypted.Length);
            byte[] data = await DecryptAsync(encrypted, (int)length);
            await File.WriteAllBytesAsync(outputPath, data);
        }

        //Копирование блока
        private byte[] GetBlock(byte[] data, int offset)
        {
            byte[] block = new byte[cipher.BlockSize];
            Array.Copy(data, offset, block, 0, block.Length);
            return block;
        }

        private void WriteBlock(byte[] result, byte[] block, int offset)
        {
            Array.Copy(block, 0, result, offset, block.Length);
        }
    }
}
