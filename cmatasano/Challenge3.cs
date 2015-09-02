using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace cmatasano
{
    class Challenge3
    {
        public string BreakXor()
        {
            byte [] bestBytes = null;
            int bestScore = int.MinValue;

            var hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            var bytes = Util.HexToBytes(hex);

            for (var j = 0; j < 256; j++)
            {
                var keyByte = (byte)j;
                var keyBytes = new byte [256];
                for(var i = 0; i < keyBytes.Length; i++)
                {
                    keyBytes[i] = keyByte;
                }

                var result = new Challenge2().Xor(bytes, keyBytes);
                var score = Score(result);
                if (j == 0)
                {
                    bestBytes = result;
                    bestScore = score;
                }
                else if (score > bestScore)
                {
                    bestBytes = result;
                    bestScore = score;
                }
            }

            var resultText = new string(bestBytes.Select(x => (char)x).ToArray());
            return resultText;
        }

        private int Score(byte[] bytes)
        {
            var total = 0;

            foreach (var b in bytes)
            {
                
                if (b == '\r' || b == '\n' || b == ',' || b == '.' || b == '?' || b == ' ')
                {
                    continue;
                }

                if (b < ' ')
                {
                    return -1000;
                }

                if (b > 'z')
                {
                    return -1000;
                }

                if (b >= '0' || b <= '9')
                {
                    continue;
                }

                if (b > '~')
                {
                    total -= 100;
                    continue;
                }

                if (b == 'a' || b == 'A' ||
                    b == 69 || b == 101 ||
                    b == 73 || b == 105 ||
                    b == 79 || b == 111 ||
                    b == 85 || b == 117)
                {
                    total += 1;
                    continue;
                }

                total += 1;
            }

            return total;
        }
    }
}
