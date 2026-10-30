// Блок DEAL равен 16 байтам
// Исходный ключ 16/24/32 байта внешних раундов  6/6/8

using System;

namespace Lab1
{
    public class DesRoundAdapter : IRoundEncryptor
    {
        public byte[] Encrypt(byte[] block, byte[] roundKey)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));
            if (roundKey == null)
                throw new ArgumentNullException(nameof(roundKey));

            Des des = new Des();
            des.SetKey(roundKey);
            return des.Encrypt(block);
        }
    }

    public class DealKeyExpansion : IKeyExpansion
    {
        //Фиксир ключ для DES
        private static readonly byte[] KeyScheduleDesKey =
        {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
        };
        //Константы генерации раундовых ключей
        private static readonly byte[][] Constants =
        {
            new byte[]
            {
                0x80, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            },

            new byte[]
            {
                0x40, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            },

            new byte[]
            {
                0x20, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            },

            new byte[]
            {
                0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            }
        };

        public byte[][] ExpandKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Ключ DEAL должен иметь длину 16, 24 или 32 байта.");

            int keyPartCount = key.Length / 8;

            int roundCount = 6; // Для ключей 128 и192 бита шесть внешних раундов
            if (key.Length == 32)
                roundCount = 8; //Для ключа 256 - восемь

            byte[][] keyParts = SplitKey(key);

            byte[][] roundKeys = new byte[roundCount][];

            Des des = new Des();

            des.SetKey(KeyScheduleDesKey); // делим ключ на куски по 8 байт

            for (int i = 0; i < roundCount; i++){
                byte[] val = (byte[])keyParts[i % keyPartCount].Clone();
                if (i > 0) // на первой итерации ключа нет
                {
                    XorInPlace(val, roundKeys[i - 1]); //смеш с пред рез
                }

                if (i >= keyPartCount)
                {
                    XorInPlace(val, Constants[i - keyPartCount]); // смешивание с константой
                }

                roundKeys[i] = des.Encrypt(val);
            }

            return roundKeys;
        }

        private byte[][] SplitKey(byte[] key){
            int partCount = key.Length / 8;
            byte[][] res = new byte[partCount][];
            for (int i = 0; i < partCount; i++){
                res[i] = new byte[8];

                Array.Copy(key, i * 8, res[i], 0, 8);
            }
            return res;
        }

        private void XorInPlace(byte[] dest, byte[] other)
        {
            if (dest.Length != other.Length)
                throw new ArgumentException("Размеры блоков должны совпадать");

            for (int i = 0; i < dest.Length; i++)
            {
                dest[i] ^= other[i];
            }
        }
    }

    public class Deal : ISymmetricCipher
    {
        private readonly FeistelNetwork feistel;

        public int BlockSize { get { return 16; } }
        public Deal()
        {
            feistel = new FeistelNetwork(new DealKeyExpansion(), new DesRoundAdapter(), BlockSize);
        }

        public void SetKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException("Ключ deal должен быть 16, 24 или 32 байта");
            }

            feistel.SetKey(key);
        }

        public byte[] Encrypt(byte[] block)
        {
            ValidateBlock(block);

            byte[] res = feistel.Encrypt(block);

            return Utils.SwapHalves(res);
        }

        public byte[] Decrypt(byte[] block)
        {
            ValidateBlock(block); 

            byte[] swapped = Utils.SwapHalves(block);
            return feistel.Decrypt(swapped);
        }

        private void ValidateBlock(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (block.Length != BlockSize)
                throw new ArgumentException("Deal работает с блоками размером 16 байт.");
        }
    }
}
