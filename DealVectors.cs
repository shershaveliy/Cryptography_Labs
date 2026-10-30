namespace Lab1
{
    public static class DealVectors
    {
        public static void Run()
        {
            string[] keys =
            {
                "00000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F",
                "000000000000000000000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
            };

            string[] blocks =
            {
                "00000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F",
                "00000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F",
                "00000000000000000000000000000000",
                "000102030405060708090A0B0C0D0E0F"
            };

            string[] expected =
            {
                "02CC32F106F4328737C38426079AC9DE",
                "35A63657D179538CA9DE13BE8B9E8548",
                "DEB301210266750E265B0482A5D2181D",
                "F8C3C3A1969757657863117944EF2979",
                "614F67C16AA5EC51F0137A90D2268B14",
                "1E39D733E214CE2875E4BF7C21C89EE6"
            };

            for (int i = 0; i < keys.Length; i++)
            {
                Deal cipher = new Deal();
                cipher.SetKey(Utils.Hex(keys[i]));

                byte[] plain = Utils.Hex(blocks[i]);
                byte[] encrypted = cipher.Encrypt(plain);
                byte[] restored = cipher.Decrypt(Utils.Hex(expected[i]));

                SelfTests.Check(Utils.Hex(encrypted) == expected[i], "DEAL: шифрование, пример " + (i + 1));
                SelfTests.Check(Utils.Equal(restored, plain), "DEAL: расшифрование, пример " + (i + 1));
            }
        }
    }
}
