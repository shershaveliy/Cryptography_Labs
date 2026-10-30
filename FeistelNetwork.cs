using System;

namespace Lab1
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private IKeyExpansion keyExpansion;
        private IRoundEncryptor roundFunction;

        private byte[][] roundKeys;

        public int BlockSize { get; }

        public FeistelNetwork(IKeyExpansion keyExpansion, IRoundEncryptor roundFunction, int blockSize)
        {
            if (keyExpansion == null)
                throw new ArgumentNullException(nameof(keyExpansion));

            if (roundFunction == null)
                throw new ArgumentNullException(nameof(roundFunction));

            if (blockSize <= 0 || blockSize % 2 != 0)
                throw new ArgumentException("Размер блока должен быть положительным и четным.", nameof(blockSize));

            this.keyExpansion = keyExpansion;
            this.roundFunction = roundFunction;
            BlockSize = blockSize;
        }

        public void SetKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            roundKeys = keyExpansion.ExpandKey(key);

            if (roundKeys == null || roundKeys.Length == 0)
                throw new InvalidOperationException("Генератор ключей не создал ни одного раундового ключа");
        }

        public byte[] Encrypt(byte[] block)
        {
            return ProcessBlock(block, decrypt: false);
        }

        public byte[] Decrypt(byte[] block)
        {
            return ProcessBlock(block, decrypt: true);
        }

        private byte[] ProcessBlock(byte[] block, bool decrypt)
        {
            ValidateBlock(block);

            if (roundKeys == null)
                throw new InvalidOperationException("Перед шифрованием надо установить ключ.");

            int halfSize = BlockSize / 2;

            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];

            Array.Copy(block, 0, left, 0, halfSize); //L_0
            Array.Copy(block, halfSize, right, 0, halfSize); //R_0

            for (int round = 0; round < roundKeys.Length; round++)
            {
                int keyIdx = round;
                if (decrypt)
                    keyIdx = roundKeys.Length - 1 - round;

                byte[] fres = roundFunction.Encrypt(right, roundKeys[keyIdx]);

                byte[] newRight = Utils.Xor(left, fres); //новая правая часть
                left = right; //новая левая часть
                right = newRight;
            }

            byte[] res = new byte[BlockSize];

            Array.Copy(right, 0, res, 0, halfSize); 
            Array.Copy(left, 0, res, halfSize, halfSize);

            return res;
        }

        private void ValidateBlock(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (block.Length != BlockSize)
            {
                throw new ArgumentException($"Размер блока должен быть равен {BlockSize} байт.");
            }
        }
    }
}
