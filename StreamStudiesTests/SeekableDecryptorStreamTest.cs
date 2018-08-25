namespace StreamStudiesTests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using NUnit.Framework;
    using StreamStudies;

    [TestFixture()]
    public class SeekableDecryptorStreamTest
    {
        private static readonly int BlockSize = 128;
        private readonly byte[] InitVecor = Enumerable.Repeat<Byte>(0x00, BlockSize / 8).ToArray();
        private readonly byte[] Key = Enumerable.Repeat<Byte>(0xff, BlockSize / 8).ToArray();

        [Test()]
        public void DecryptAllFromBeginning()
        {
            var expectedPlainText = this.GetPlainText(4 * BlockSize);
            Byte[] cypherText;
            using (var algorithm = this.GetSymmetricAlgorithm())
            {
                cypherText = this.GetCypherText(expectedPlainText, algorithm);
            }

            using (var encryptedBaseStream = new MemoryStream(cypherText))
            using (var algorithm = this.GetSymmetricAlgorithm())
            using (var decryptedStream = new SeekableDecryptorStream(
                encryptedBaseStream,
                algorithm))
            using (var reader = new BinaryReader(decryptedStream))
            {
                var actualPlainText = reader.ReadBytes(expectedPlainText.Length);
                CollectionAssert.AreEqual(expectedPlainText, actualPlainText);
            }
        }

        private SymmetricAlgorithm GetSymmetricAlgorithm()
        {
            var algorithm = new AesManaged()
            {
                Mode = CipherMode.CBC,
                BlockSize = BlockSize,
                IV = InitVecor,
                Key = Key,
            };

            return algorithm;
        }

        private Byte[] GetCypherText(Byte[] plainText, SymmetricAlgorithm algorithm)
        {
            using (var memoryStream = new MemoryStream(plainText.Length))
            {
                using (var cryptoStream = new CryptoStream(
                    memoryStream,
                    algorithm.CreateEncryptor(),
                    CryptoStreamMode.Write))
                using (var writer = new BinaryWriter(cryptoStream))
                {
                    writer.Write(plainText);
                }

                return memoryStream.ToArray();
            }
        }

        private Byte[] GetPlainText(Int32 size)
        {
            Assert.GreaterOrEqual(size, 0);
            Assert.IsTrue(size % 2 == 0, $"{nameof(size)} must be a multiple of 2.");

            var sampleData = new Byte[size];
            for (Int32 i = 0, c = 0; i < size; c++)
            {
                sampleData[i++] = (Byte)c;
                sampleData[i++] = (Byte)(c >> 8);
            }

            return sampleData;
        }
    }
}
