using System;

namespace Lab1
{
    public class DesKeyExpansion : IKeyExpansion
    {
        // PC-1
        private static readonly int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };

        // PC-2
        private static readonly int[] PC2 =
        {
            14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        private static readonly int[] Shifts =
        {
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
        };

        private const ulong Mask28 = (1 << 28) - 1;//половинка ключа

        public byte[][] ExpandKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 8)
                throw new ArgumentException(
                    "Ключ DES должен иметь размер 8 байт.", nameof(key));

            byte[] key56 = BitPermutation.Permute(
                key, PC1, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);

            ulong keyValue = Utils.ToUInt64(key56);

            ulong c = (keyValue >> 28) & Mask28; //C
            ulong d = keyValue & Mask28; //D

            byte[][] roundKeys = new byte[16][];

            for (int round = 0; round < 16; round++)
            {
                c = RotateLeft28(c, Shifts[round]);
                d = RotateLeft28(d, Shifts[round]);

                ulong combined = (c << 28) | d;

                byte[] combinedBytes = Utils.ToBytes(combined, 7);

                roundKeys[round] = BitPermutation.Permute(
                    combinedBytes, PC2, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);
            }

            return roundKeys;
        }

        private ulong RotateLeft28(ulong value, int shift)
        {
            return ((value << shift) | (value >> (28 - shift))) & Mask28;
        }
    }

    public class DesRoundFunction : IRoundEncryptor
    {
        private static readonly int[] Expansion =
        {
            32, 1, 2, 3, 4, 5,
             4, 5, 6, 7, 8, 9,
             8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        private static readonly int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
             1, 15, 23, 26,
             5, 18, 31, 10,
             2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };

        private static readonly int[,,] SBoxes =
        {
            {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                {  0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                {  4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            },
            {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                {  3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                {  0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            },
            {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                {  1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },
            {
                {  7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                {  3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            {
                {  2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                {  4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },
            {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                {  9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                {  4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },
            {
                {  4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                {  1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                {  6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },
            {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                {  1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                {  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                {  2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
        };

        private const ulong Mask6 = (1 << 6) - 1; //111111
        private const int Mask4 = (1 << 4) - 1; // 1111

        public byte[] Encrypt(byte[] block, byte[] roundKey)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (roundKey == null)
                throw new ArgumentNullException(nameof(roundKey));

            if (block.Length != 4)
                throw new ArgumentException("Раундовая функция des принимает 4 байта.");

            if (roundKey.Length != 6)
                throw new ArgumentException("Раундовый ключ des должен быть 6 байт");

            byte[] expanded = BitPermutation.Permute(
                block, Expansion, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);

            for (int i = 0; i < expanded.Length; i++)
            {
                expanded[i] ^= roundKey[i]; //xor
            }

            byte[] afterSBoxes = ApplySBoxes(expanded);
            return BitPermutation.Permute(
                afterSBoxes, P, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);
        }

        private byte[] ApplySBoxes(byte[] val)
        {
            ulong input = Utils.ToUInt64(val);
            uint output = 0;

            for (int box = 0; box < 8; box++)
            {
                int shift = 42 - 6 * box;
                int sixBits = (int)((input >> shift) & Mask6);
                int row = ((sixBits >> 4) & 2) | (sixBits & 1);
                int column = (sixBits >> 1) & Mask4;
                int sValue = SBoxes[box, row, column];
                output <<= 4; //сдвигаем чтоб вставить новые 4 битп
                output |= (uint)sValue;
            }

            return Utils.ToBytes(output, 4);
        }
    }

    public class Des : ISymmetricCipher
    {
        private static readonly int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        private static readonly int[] IPInverse =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        private readonly FeistelNetwork feistel;

        public int BlockSize { get { return 8; } }//64 бита - блок DES

        public Des()
        {
            feistel = new FeistelNetwork(new DesKeyExpansion(), new DesRoundFunction(), BlockSize);
        }

        public void SetKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 8)
                throw new ArgumentException("Ключ des должен быть 8 байт.");

            feistel.SetKey(key);
        }

        public byte[] Encrypt(byte[] block)
        {
            ValidateBlock(block);

            byte[] afterIP = BitPermutation.Permute(
                block, IP, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);

            byte[] afterFeistel = feistel.Encrypt(afterIP); 

            return BitPermutation.Permute(
                afterFeistel, IPInverse, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);
        }

        public byte[] Decrypt(byte[] block)
        {
            ValidateBlock(block);

            byte[] afterIP = BitPermutation.Permute(
                block, IP, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);

            byte[] afterFeistel = feistel.Decrypt(afterIP);

            return BitPermutation.Permute(
                afterFeistel, IPInverse, BitIndexDirection.MostToLeastSignificant, BitIndexBase.One);
        }

        private void ValidateBlock(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (block.Length != BlockSize)
                throw new ArgumentException("des работает с блоками размером 8 байт.");
        }
    }
}
