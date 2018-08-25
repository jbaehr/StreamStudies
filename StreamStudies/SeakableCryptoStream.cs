using System;
using System.IO;
using System.Security.Cryptography;

namespace StreamStudies
{
    public class SeakableCryptoStream : Stream
    {
        private readonly Stream encryptedBaseStream;
        private readonly SymmetricAlgorithm algorithm;
        private CryptoStream currentCryptoStream;

        public SeakableCryptoStream(Stream encryptedBaseStream, SymmetricAlgorithm algorithm)
        {
            this.encryptedBaseStream = encryptedBaseStream;
            this.algorithm = algorithm;
            this.currentCryptoStream = new CryptoStream(
                encryptedBaseStream,
                algorithm.CreateDecryptor(),
                CryptoStreamMode.Read);
        }

        public override bool CanRead => this.currentCryptoStream.CanRead;

        public override bool CanSeek => this.currentCryptoStream.CanSeek;

        public override bool CanWrite => this.currentCryptoStream.CanWrite;

        public override long Length => this.currentCryptoStream.Length;

        public override long Position
        {
            get => this.currentCryptoStream.Position;
            set => this.currentCryptoStream.Position = value;
        }

        public override void Flush()
        {
            this.currentCryptoStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return this.currentCryptoStream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return this.currentCryptoStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            this.currentCryptoStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.currentCryptoStream.Write(buffer, offset, count);
        }
    }
}
