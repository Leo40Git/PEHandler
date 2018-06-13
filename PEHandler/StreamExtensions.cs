using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEHandler
{
    /// <summary>
    /// Extension to the Stream class to add methods for reading and writing shorts, integers and longs easily.
    /// </summary>
    public static class StreamExtensions
    {
        /// <summary>
        /// Reads a short from the current stream.
        /// </summary>
        /// <param name="src">stream to read from</param>
        /// <returns>short from stream</returns>
        public static ushort ReadShort(this Stream src)
        {
            byte[] numBuf = new byte[2];
            src.Read(numBuf, 0, 2);
            return BitConverter.ToUInt16(numBuf, 0);
        }

        /// <summary>
        /// Reads an integer from the current stream.
        /// </summary>
        /// <param name="src">stream to read from</param>
        /// <returns>integer from stream</returns>
        public static uint ReadInt(this Stream src)
        {
            byte[] numBuf = new byte[4];
            src.Read(numBuf, 0, 4);
            return BitConverter.ToUInt32(numBuf, 0);
        }

        /// <summary>
        /// Reads a long from the current stream.
        /// </summary>
        /// <param name="src">stream to read from</param>
        /// <returns>long from stream</returns>
        public static ulong ReadLong(this Stream src)
        {
            byte[] numBuf = new byte[8];
            src.Read(numBuf, 0, 8);
            return BitConverter.ToUInt64(numBuf, 0);
        }

        /// <summary>
        /// Writes a short to the current stream.
        /// </summary>
        /// <param name="src">stream to write to</param>
        /// <param name="value">value to write</param>
        public static void WriteShort(this Stream src, ushort value)
        {
            byte[] numBuf = BitConverter.GetBytes(value);
            src.Write(numBuf, 0, numBuf.Length);
        }

        /// <summary>
        /// Writes an integer to the current stream.
        /// </summary>
        /// <param name="src">stream to write to</param>
        /// <param name="value">value to write</param>
        public static void WriteInt(this Stream src, uint value)
        {
            byte[] numBuf = BitConverter.GetBytes(value);
            src.Write(numBuf, 0, numBuf.Length);
        }

        /// <summary>
        /// Writes a long to the current stream.
        /// </summary>
        /// <param name="src">stream to write to</param>
        /// <param name="value">value to write</param>
        public static void WriteLong(this Stream src, ulong value)
        {
            byte[] numBuf = BitConverter.GetBytes(value);
            src.Write(numBuf, 0, numBuf.Length);
        }
    }
}