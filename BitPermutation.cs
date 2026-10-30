using System;

namespace Lab1
{
    public enum BitIndexDirection
    {
        LeastToMostSignificant,//От конца до начала
        MostToLeastSignificant //От начала до конца
    }

    public enum BitIndexBase
    {
        Zero = 0,
        One = 1
    }

    public static class BitPermutation{

        public static byte[] Permute( byte[] value, int[] pBlock, BitIndexDirection direction, BitIndexBase indexBase){

            if (value == null)
                throw new ArgumentNullException(nameof(value));
            if (pBlock == null)
                throw new ArgumentNullException(nameof(pBlock));
            if (indexBase != BitIndexBase.Zero && indexBase != BitIndexBase.One)
                throw new ArgumentException("Начальный номер должен быть 0 или 1.");
            if (direction != BitIndexDirection.LeastToMostSignificant &&
                direction != BitIndexDirection.MostToLeastSignificant)
                throw new ArgumentException("Неизвестное направление нумерации.");

            //Кол-во выходных байтов
            int byteCount = pBlock.Length / 8;
            if (pBlock.Length % 8 != 0)
                byteCount++;

            byte[] result = new byte[byteCount];
            int bitCount = checked(value.Length * 8);

            //На каждой итерации один бит
            for (int i = 0; i < pBlock.Length; i++){
                if (pBlock[i] < (int)indexBase)
                    throw new ArgumentOutOfRangeException(nameof(pBlock));

                int sourceIndex = pBlock[i] - (int)indexBase;
                if (sourceIndex >= bitCount)
                    throw new ArgumentOutOfRangeException(nameof(pBlock));

                bool bit = GetBit(value, sourceIndex, direction);
                SetBit(result, i, direction, bit);
            }

            return result;
        }

        private static bool GetBit(byte[] value, int index, BitIndexDirection direction)
        {
            int byteIndex; //байт, в котором лежит нужный бит
            byte mask;
            GetBitPosition(value.Length, index, direction, out byteIndex, out mask);
            return (value[byteIndex] & mask) != 0;
        }

        private static void SetBit(byte[] value, int index, BitIndexDirection direction, bool bit)
        {
            int byteIndex;
            byte mask;
            GetBitPosition(value.Length, index, direction, out byteIndex, out mask);

            if (bit)
                value[byteIndex] |= mask;
            else
                value[byteIndex] &= (byte)~mask;
        }

        private static void GetBitPosition (int byteCount, int index, BitIndexDirection direction, out int byteIndex, out byte mask)
        {
            byteIndex = index / 8;
            int bitIndex = index % 8;

            if (direction == BitIndexDirection.MostToLeastSignificant)
                bitIndex = 7 - bitIndex;
            else
                byteIndex = byteCount - 1 - byteIndex;

            mask = (byte)(1 << bitIndex); //Пр: 3 даст маску 00001000
        }
    }
}
