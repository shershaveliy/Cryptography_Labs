using System;
// 2.1, 2.2,2.3
namespace Lab1 {
    public interface IKeyExpansion
    {
        byte[][] ExpandKey(byte[] key);
    }

    public interface IRoundEncryptor{
        byte[] Encrypt(byte[] block, byte[] roundKey);
    }

    public interface ISymmetricCipher{
        int BlockSize { get; }
        void SetKey(byte[] key);
        byte[] Encrypt(byte[] block);
        byte[] Decrypt(byte[] block);
    }
}
