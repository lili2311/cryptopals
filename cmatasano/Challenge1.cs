using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;

namespace cmatasano
{
    class Challenge1
    {
        public string BytesToBase64(byte[] bytes)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < bytes.Length; i += 3)
            {
                byte b0 = bytes[i];
                if (i + 2 < bytes.Length)
                {
                    var chars = BytesToBase64Chars(bytes[i], bytes[i + 1], bytes[i + 2]);
                    sb.Append(chars);
                }
                else if (i + 1 < bytes.Length)
                {
                    var chars = BytesToBase64Chars(bytes[i], bytes[i + 1]);
                    sb.Append(chars);
                }
                else
                {
                    var chars = BytesToBase64Chars(bytes[i]);
                    sb.Append(chars);
                }
            }

            return sb.ToString();
        }

        private char[] BytesToBase64Chars(byte a, byte b, byte c)
        {
            char[] lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".ToArray();

            byte i0 = (byte)(a >> 2);
            byte i1 = (byte)((a << 4 | b >> 4) & 0x3F);
            byte i2 = (byte)((b << 2 | c >> 6) & 0x3F);
            byte i3 = (byte)(c & 0x3F);

            return new[] { lookup[i0], lookup[i1], lookup[i2], lookup[i3] };
        }

        private char[] BytesToBase64Chars(byte a, byte b)
        {
            char[] lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".ToArray();

            byte i0 = (byte)(a >> 2);
            byte i1 = (byte)((a << 4 | b >> 4) & 0x3F);
            byte i2 = (byte)((b << 2 | 0x0 >> 6) & 0x3F);

            return new[] { lookup[i0], lookup[i1], lookup[i2], '=' };
        }

        private char[] BytesToBase64Chars(byte a)
        {
            char[] lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".ToArray();

            byte i0 = (byte)(a >> 2);
            byte i1 = (byte)((a << 4 | 0x0 >> 4) & 0x3F);

            return new[] { lookup[i0], lookup[i1], '=', '=' };
        }
    }
}
