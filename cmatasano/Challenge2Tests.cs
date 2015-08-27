using Shouldly;

namespace cmatasano
{
    class Challenge2Tests
    {
        public void WebTest()
        {
            var hex0 = "1c0111001f010100061a024b53535009181c";
            var hex1 = "686974207468652062756c6c277320657965";
            var expectedHex = "746865206b696420646f6e277420706c6179";

            var challenge = new Challenge2();
            var result = Util.ToHex(challenge.Xor(Util.HexToBytes(hex0), Util.HexToBytes(hex1)));

            result.ShouldBe(expectedHex);
        }
    }
}
