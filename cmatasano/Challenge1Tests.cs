using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Shouldly;

namespace cmatasano
{
    class Challenge1Tests
    {
        public void WebsiteTest()
        {
            var challenge = new Challenge1();

            var hexText = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

            var bytes = Util.HexToBytes(hexText);
            var base64Text = challenge.BytesToBase64(bytes);
            var expectedBase64Text = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            expectedBase64Text.ShouldBe(base64Text);
        }

        public void ThreeByteTest()
        {
            var challenge = new Challenge1();

            var hexText = "49276d";
            var bytes = Util.HexToBytes(hexText);
            var base64Text = challenge.BytesToBase64(bytes);
            var expectedBase64Text = "SSdt";

            base64Text.ShouldBe(expectedBase64Text);
        }

        public void TwoByteTest()
        {
            var challenge = new Challenge1();

            var hexText = "4927";
            var bytes = Util.HexToBytes(hexText);
            var base64Text = challenge.BytesToBase64(bytes);
            var expectedBase64Text = "SSc=";

            base64Text.ShouldBe(expectedBase64Text);
        }


        public void OneByteTest()
        {
            var challenge = new Challenge1();

            var hexText = "49";
            var bytes = Util.HexToBytes(hexText);
            var base64Text = challenge.BytesToBase64(bytes);
            var expectedBase64Text = "SQ==";

            base64Text.ShouldBe(expectedBase64Text);
        }
    }
}
