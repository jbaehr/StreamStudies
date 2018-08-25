﻿using System;
using System.IO;
using System.Security.Cryptography;

namespace StreamStudies
{
    /// <summary>
    /// A crypto stream with random read access.
    /// </summary>
    public class SeekableDecryptorStream : Stream
    {
        private readonly Stream encryptedBaseStream;
        private readonly SymmetricAlgorithm algorithm;
        private CryptoStream currentCryptoStream;
        private long position;
        private int blockSizeInBytes;

        public SeekableDecryptorStream(Stream encryptedBaseStream, SymmetricAlgorithm algorithm)
        {
            this.encryptedBaseStream = encryptedBaseStream;
            this.algorithm = algorithm;
            this.currentCryptoStream = new CryptoStream(
                encryptedBaseStream,
                algorithm.CreateDecryptor(),
                CryptoStreamMode.Read);
            this.position = 0;
            this.blockSizeInBytes = algorithm.BlockSize / 8;
        }

        public override bool CanRead => this.currentCryptoStream.CanRead;

        public override bool CanSeek => this.currentCryptoStream.CanSeek;

        public override bool CanWrite => this.currentCryptoStream.CanWrite;

        public override long Length => this.currentCryptoStream.Length;

        public override long Position
        {
            get => this.position;
            set => this.position = this.SetPosition(value);
        }

        public override void Flush()
        {
            this.currentCryptoStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var bytesRead = this.currentCryptoStream.Read(buffer, offset, count);
            this.position += bytesRead;
            return bytesRead;
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

        private long SetPosition(long newPosition)
        {
            var wantedBlock = newPosition / this.blockSizeInBytes;
            this.algorithm.IV = this.GetIv(wantedBlock);
            var blockBoundary = wantedBlock * this.blockSizeInBytes;
            this.encryptedBaseStream.Position = blockBoundary;
            this.currentCryptoStream = new CryptoStream(
                this.encryptedBaseStream,
                this.algorithm.CreateDecryptor(),
                CryptoStreamMode.Read);

            // we can be sure that this read succeeds completely as we read less then a block
            var bytesToDiscard = new Byte[newPosition - blockBoundary];
            this.currentCryptoStream.Read(bytesToDiscard, 0, bytesToDiscard.Length);

            return newPosition;
        }

        private byte[] GetIv(long wantedBlock)
        {
            // ChypherMode.CBC uses the cypher text of the prevous block as as IV.
            var ivPosition = (wantedBlock - 1) * this.blockSizeInBytes;
            this.encryptedBaseStream.Position = ivPosition;
            using (var reader = new BinaryReader(
                this.encryptedBaseStream,
                System.Text.Encoding.UTF8,
                leaveOpen: true))
            {
                return reader.ReadBytes(this.blockSizeInBytes);
            }
        }
    }
}
