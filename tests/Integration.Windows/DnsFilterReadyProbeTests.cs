using System.Buffers.Binary;
using System.Text;
using DistractionFirewall.Enforcement.Windows.Dns;

namespace DistractionFirewall.Integration.Windows.Tests;

public sealed class DnsFilterReadyProbeTests
{
    private const ushort TransactionId = 0x4A31;
    private const string Token =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string ExpectedTxt =
        "02e96d8cf4bc8e7e06e4d1e7997190957e36a21e208c22250f7221ef58b7326a";

    [Fact]
    public void HashContractIncludesDomainSeparatorNullAndTokenBytes()
    {
        Assert.Equal(ExpectedTxt, LeaseBoundDnsFilterReadyProbe.ComputeExpectedTxt(Token));
    }

    [Fact]
    public void ExactAuthoritativeTtlZeroTxtResponseIsAccepted()
    {
        var response = CreateResponse(ExpectedTxt);

        Assert.True(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            response,
            TransactionId,
            ExpectedTxt));
    }

    [Fact]
    public void ExistingOrSpoofedDnsListenerResponsesAreRejected()
    {
        var wrongTransaction = CreateResponse(ExpectedTxt);
        wrongTransaction[1] ^= 1;
        var notAuthoritative = CreateResponse(ExpectedTxt);
        notAuthoritative[2] &= 0xFB;
        var nonzeroTtl = CreateResponse(ExpectedTxt);
        var questionLength = LeaseBoundDnsFilterReadyProbe.CreateQuery(TransactionId).Length - 12;
        nonzeroTtl[12 + questionLength + 9] = 1;
        var wrongToken = CreateResponse(new string('0', 64));
        var changedQuestion = CreateResponse(ExpectedTxt);
        changedQuestion[13] = (byte)'x';
        var trailingData = CreateResponse(ExpectedTxt).Concat(new byte[] { 0 }).ToArray();

        Assert.False(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            wrongTransaction,
            TransactionId,
            ExpectedTxt));
        Assert.False(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            notAuthoritative,
            TransactionId,
            ExpectedTxt));
        Assert.False(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            nonzeroTtl,
            TransactionId,
            ExpectedTxt));
        Assert.False(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            wrongToken,
            TransactionId,
            ExpectedTxt));
        Assert.False(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            changedQuestion,
            TransactionId,
            ExpectedTxt));
        Assert.False(LeaseBoundDnsFilterReadyProbe.IsExpectedResponse(
            trailingData,
            TransactionId,
            ExpectedTxt));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ABCDEF")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void ReadyTokenMustBeExactlyLowerHex32Bytes(string value)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            DnsFilterTaskDefinitionBuilder.ValidateReadyToken(value));
    }

    private static byte[] CreateResponse(string txt)
    {
        var query = LeaseBoundDnsFilterReadyProbe.CreateQuery(TransactionId);
        var question = query.AsSpan(12);
        var response = new byte[12 + question.Length + 2 + 2 + 2 + 4 + 2 + 65];
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(0, 2), TransactionId);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), 0x8400);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
        question.CopyTo(response.AsSpan(12));
        var offset = 12 + question.Length;
        response[offset++] = 0xC0;
        response[offset++] = 0x0C;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 16);
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 1);
        offset += 2;
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset, 4), 0);
        offset += 4;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 65);
        offset += 2;
        response[offset++] = 64;
        Encoding.ASCII.GetBytes(txt).CopyTo(response, offset);
        return response;
    }
}
