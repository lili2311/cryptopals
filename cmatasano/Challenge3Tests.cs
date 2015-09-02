using Shouldly;

namespace cmatasano
{
    class Challenge3Tests
    {
        public void WebTest()
        {
            var challenge = new Challenge3();
            var result = challenge.BreakXor();

            result.ShouldBe("Cooking MC's like a pound of bacon");
        }
    }
}
