using System;

namespace Lab1
{
    public static class Utils
    {
        // Выполняет побитовый xor двух массивов одинаковой длины
        public static byte[] Xor(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                throw new ArgumentException("Размеры массивов должны совпадать");
            }

            byte[] res = new byte[first.Length];

            for (int i = 0; i < first.Length; i++)
            {
                res[i] = (byte)(first[i] ^ second[i]);
            }

            return res;
        }

        // Собирает число ulong из байтов старший байт идёт первым
        public static ulong ToUInt64(byte[] bytes)
        {
            ulong res = 0;

            foreach (byte b in bytes)
            {
                res <<= 8;
                res |= b;
            }

            return res;
        }

        private const ulong ByteMask = (1 << 8) - 1;

        // Записывает число в массив заданного размера
        public static byte[] ToBytes(ulong value, int size)
        {
            byte[] res = new byte[size];

            for (int i = size - 1; i >= 0; i--)
            {
                res[i] = (byte)(value & ByteMask);
                value >>= 8;
            }

            return res;
        }

        // Меняет местами две равные половины блока
        public static byte[] SwapHalves(byte[] block)
        {
            int halfSize = block.Length / 2;
            byte[] result = new byte[block.Length];

            Array.Copy(block, halfSize, result, 0, halfSize);
            Array.Copy(block, 0, result, halfSize, halfSize);

            return result;
        }

        //Копирует count байтов массива, начиная с позиции offset
        public static byte[] Part(byte[] data, int offset, int count)
        {
            byte[] result = new byte[count];
            Array.Copy(data, offset, result, 0, count);

            return result;
        }

        //Преобразует hexx в массив байтов
        public static byte[] Hex(string text)
        {
            text = text.Replace(" ", "");

            if (text.Length % 2 != 0)
                throw new ArgumentException("HEX-строка должна иметь чётную длину.");

            byte[] result = new byte[text.Length / 2];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
            }

            return result;
        }

        //Преобразует массив байтов в hex
        public static string Hex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }

        //возвращает true, если длины и все байты двух массивов совпадают
        public static bool Equal(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
                return false;

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                    return false;
            }

            return true;
        }
    }
}