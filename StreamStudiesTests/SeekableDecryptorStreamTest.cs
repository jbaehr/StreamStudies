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
        private static readonly int BlockSizeInBits = 128;
        private static readonly int BlockSizeInBytes = BlockSizeInBits / 8;
        private readonly byte[] InitVecor = Enumerable.Repeat<Byte>(0x00, BlockSizeInBytes).ToArray();
        private readonly byte[] Key = Enumerable.Repeat<Byte>(0xff, BlockSizeInBytes).ToArray();

        [Test()]
        public void DecryptAllFromBeginning()
        {
            var expectedPlainText = this.GetPlainText(4 * BlockSizeInBytes);
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

        [Test()]
        public void DecryptMiddleBlock()
        {
            var plainText = this.GetPlainText(5 * BlockSizeInBytes);
            Byte[] cypherText;
            using (var algorithm = this.GetSymmetricAlgorithm())
            {
                cypherText = this.GetCypherText(plainText, algorithm);
            }

            using (var encryptedBaseStream = new MemoryStream(cypherText))
            using (var algorithm = this.GetSymmetricAlgorithm())
            using (var decryptedStream = new SeekableDecryptorStream(
                encryptedBaseStream,
                algorithm))
            using (var reader = new BinaryReader(decryptedStream))
            {
                var offset = 2 * BlockSizeInBytes;
                var length = BlockSizeInBytes;
                var expected = new ArraySegment<Byte>(plainText, offset, length);
                decryptedStream.Position = offset;
                var actual = reader.ReadBytes(length);
                CollectionAssert.AreEqual(expected, actual);
            }
        }

        private SymmetricAlgorithm GetSymmetricAlgorithm()
        {
            var algorithm = new AesManaged()
            {
                Mode = CipherMode.CBC,
                BlockSize = BlockSizeInBits,
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
            Assert.GreaterOrEqual(256, size);

            var sampleData = new Byte[size];
            for (Int32 i = 0; i < size; i++)
            {
                sampleData[i] = (Byte)i;
            }

            return sampleData;
        }
    }
}
