using AgeSharp.Core;
using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Keys;
using Xunit;

namespace AgeSharp.Tests.Keys;

public class AgeKeyGeneratorTests
{
    [Fact]
    public void GenerateX25519Key_ReturnsValidIdentity()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();

        Assert.NotNull(identity);
        Assert.Equal(RecipientType.X25519, identity.Type);
    }

    [Fact]
    public void GenerateX25519Key_ProducesUniqueKeys()
    {
        var identity1 = AgeKeyGenerator.GenerateX25519Key();
        var identity2 = AgeKeyGenerator.GenerateX25519Key();

        var privateKey1 = GetPrivateKey(identity1);
        var privateKey2 = GetPrivateKey(identity2);

        Assert.NotEqual(privateKey1, privateKey2);
    }

    [Fact]
    public void ToIdentityString_ReturnsValidBech32Format()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var identityString = identity.ToIdentityString();

        Assert.StartsWith("AGE-SECRET-KEY-1", identityString);
        Assert.True(AgeBech32.IsValidIdentity(identityString));
    }

    [Fact]
    public void GetRecipientString_ReturnsValidRecipient()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipientString = AgeKeyGenerator.GetRecipientString(identity);

        Assert.StartsWith("age1", recipientString);
        Assert.True(AgeBech32.IsValidRecipient(recipientString));
    }

    [Fact]
    public void IdentityAndRecipient_AreRelated()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipientString = AgeKeyGenerator.GetRecipientString(identity);

        var decodedRecipient = AgeBech32.DecodeRecipient(recipientString);
        var derivedPublicKey = DerivePublicKey(identity);

        Assert.Equal(decodedRecipient, derivedPublicKey);
    }

    [Fact]
    public void GetRecipientString_NullIdentity_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeKeyGenerator.GetRecipientString(null!));
    }

    private static byte[] GetPrivateKey(IIdentity identity)
    {
        var field = typeof(X25519Identity).GetField("_privateKey",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        return (byte[])(field?.GetValue(identity) ?? throw new InvalidOperationException("Cannot get private key"));
    }

    private static byte[] DerivePublicKey(IIdentity identity)
    {
        if (identity is X25519Identity x25519Identity)
        {
            return x25519Identity.GetPublicKey();
        }
        throw new InvalidOperationException("Cannot derive public key for unknown identity type");
    }
}
