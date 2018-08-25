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
        [Test()]
        public void DecryptAllFromBeginning()
        {
            using (var t = new TestBed(4 * TestBed.BlockSizeInBytes))
            {
                var expectedPlainText = t.PlainText;
                var actualPlainText = t.DecryptedReader.ReadBytes(expectedPlainText.Length);
                CollectionAssert.AreEqual(expectedPlainText, actualPlainText);
            }
        }

        [Test()]
        public void DecryptMiddleBlock()
        {
            using (var t = new TestBed(5 * TestBed.BlockSizeInBytes))
            {
                var offset = 2 * TestBed.BlockSizeInBytes;
                var length = TestBed.BlockSizeInBytes;
                var expected = new ArraySegment<Byte>(t.PlainText, offset, length);

                t.DecryptedStream.Position = offset;

                var actual = t.DecryptedReader.ReadBytes(length);
                CollectionAssert.AreEqual(expected, actual);
            }
        }

        [Test()]
        public void DecryptMiddlePartialBlocks()
        {
            using (var t = new TestBed(5 * TestBed.BlockSizeInBytes))
            {
                var offset = (Int32)(2.5 * TestBed.BlockSizeInBytes);
                var length = TestBed.BlockSizeInBytes;
                var expected = new ArraySegment<Byte>(t.PlainText, offset, length);

                t.DecryptedStream.Position = offset;

                var actual = t.DecryptedReader.ReadBytes(length);
                CollectionAssert.AreEqual(expected, actual);
            }
        }

        [Test()]
        public void DecryptAdvancesPosition()
        {
            using (var t = new TestBed(4))
            {
                t.DecryptedStream.ReadByte();
                t.DecryptedStream.ReadByte();
                t.DecryptedStream.ReadByte();

                Assert.AreEqual(3, t.DecryptedStream.Position);
            }
        }

        [Test()]
        public void PositionRoundTrips()
        {
            using (var t = new TestBed(50))
            {
                t.DecryptedStream.Position = 20;
                Assert.AreEqual(20, t.DecryptedStream.Position);
            }
        }

        [Test()]
        public void SeekIntoFirstBlock()
        {
            using (var t = new TestBed(2 * TestBed.BlockSizeInBytes))
            {
                var somewhereInFirstBlock = (Int32)(0.5 * TestBed.BlockSizeInBytes);
                t.DecryptedStream.Position = somewhereInFirstBlock;
                Assert.AreEqual(t.PlainText[somewhereInFirstBlock], t.DecryptedStream.ReadByte());
            }
        }

        private class TestBed : IDisposable
        {
            private static readonly int BlockSizeInBits = 128;
            public static readonly int BlockSizeInBytes = BlockSizeInBits / 8;
            private readonly byte[] InitVecor = Enumerable.Repeat<Byte>(0x00, BlockSizeInBytes).ToArray();
            private readonly byte[] Key = Enumerable.Repeat<Byte>(0xff, BlockSizeInBytes).ToArray();

            private readonly SymmetricAlgorithm decryptorAlgorithm;

            public TestBed(Int32 numberOfSampleBytes)
            {
                this.PlainText = this.GetPlainText(numberOfSampleBytes);
                using (var algorithm = this.GetSymmetricAlgorithm())
                {
                    this.CypherText = this.GetCypherText(this.PlainText, algorithm);
                }

                this.EncryptedBaseStream = new MemoryStream(this.CypherText);
                this.decryptorAlgorithm = this.GetSymmetricAlgorithm();
                this.DecryptedStream = new SeekableDecryptorStream(
                    this.EncryptedBaseStream,
                    this.decryptorAlgorithm);
                this.DecryptedReader = new BinaryReader(this.DecryptedStream);
            }

            public Byte[] PlainText { get; }
            public Byte[] CypherText { get; }

            public MemoryStream EncryptedBaseStream { get; }

            public SeekableDecryptorStream DecryptedStream { get; }
            public BinaryReader DecryptedReader { get; }

            public void Dispose()
            {
                // disposing the reader disposes all the rest recursively 
                this.DecryptedReader.Dispose();
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
}
