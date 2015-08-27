using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace cmatasano
{
    class Challenge2
    {
        public byte [] Xor(byte[] a, byte[] b)
        {
            var results = new byte[a.Length];
            for (var i = 0; i < a.Length; i++)
            {
                results[i] = (byte)(a[i] ^ b[i]);
            }

            return results;
        }
    }
}
