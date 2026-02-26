using AgeSharp.Core.Payload;
using Xunit;

namespace AgeSharp.Tests.Payload;

public class PayloadCrypterTests
{
    [Fact]
    public void ConstructNonce_FirstChunk_NotFinal()
    {
        var nonce = PayloadCrypter.ConstructNonce(0, false);
        
        Assert.Equal(12, nonce.Length);
        Assert.Equal(0x00, nonce[11]);
    }

    [Fact]
    public void ConstructNonce_FirstChunk_IsFinal()
    {
        var nonce = PayloadCrypter.ConstructNonce(0, true);
        
        Assert.Equal(12, nonce.Length);
        Assert.Equal(0x01, nonce[11]);
    }

    [Fact]
    public void ConstructNonce_SecondChunk_NotFinal()
    {
        var nonce = PayloadCrypter.ConstructNonce(1, false);
        
        Assert.Equal(12, nonce.Length);
        Assert.Equal(0x00, nonce[11]);
        Assert.Equal(1, nonce[10]);
    }

    [Fact]
    public void ConstructNonce_ThirdChunk()
    {
        var nonce = PayloadCrypter.ConstructNonce(2, false);
        
        Assert.Equal(12, nonce.Length);
        Assert.Equal(0x02, nonce[10]);
    }

    [Fact]
    public void DerivePayloadKey_SameInputs_ProducesSameKey()
    {
        var fileKey = new byte[16];
        var nonce = new byte[16];
        
        var key1 = PayloadCrypter.DerivePayloadKey(fileKey, nonce);
        var key2 = PayloadCrypter.DerivePayloadKey(fileKey, nonce);
        
        Assert.Equal(32, key1.Length);
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void DerivePayloadKey_DifferentNonce_ProducesDifferentKey()
    {
        var fileKey = new byte[16];
        var nonce1 = new byte[16];
        var nonce2 = new byte[16];
        nonce2[0] = 1;
        
        var key1 = PayloadCrypter.DerivePayloadKey(fileKey, nonce1);
        var key2 = PayloadCrypter.DerivePayloadKey(fileKey, nonce2);
        
        Assert.NotEqual(key1, key2);
    }
}
