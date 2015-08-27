using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace cmatasano
{
    class Util
    {
        private static byte HexToByte(string text)
        {
            return byte.Parse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        public static byte[] HexToBytes(string hexText)
        {
            var bytes = new List<byte>();
            for (var i = 0; i < hexText.Length; i += 2)
            {
                var vs = HexToByte(hexText.Substring(i, 2));
                bytes.Add(vs);
            }

            return bytes.ToArray();
        }

        internal static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            
            foreach (var b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
