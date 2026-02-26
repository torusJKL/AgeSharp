using AgeSharp.Core;
using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using AgeSharp.Core.Keys;
using Xunit;

namespace AgeSharp.Tests;

public class AgeParserTests
{
    [Fact]
    public void ParseRecipient_ValidRecipientString_ReturnsRecipient()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipientString = identity.ToRecipientString();

        var recipient = AgeParser.ParseRecipient(recipientString);

        Assert.NotNull(recipient);
        Assert.Equal(RecipientType.X25519, recipient.Type);
        Assert.Equal(recipientString, recipient.ToRecipientString());
    }

    [Fact]
    public void ParseRecipient_InvalidString_ThrowsAgeKeyException()
    {
        var invalidString = "invalid-recipient-string";

        Assert.Throws<AgeKeyException>(() => AgeParser.ParseRecipient(invalidString));
    }

    [Fact]
    public void ParseRecipient_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeParser.ParseRecipient(null!));
    }

    [Fact]
    public void ParseIdentity_ValidIdentityString_ReturnsIdentity()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var identityString = identity.ToIdentityString();

        var parsedIdentity = AgeParser.ParseIdentity(identityString);

        Assert.NotNull(parsedIdentity);
        Assert.Equal(RecipientType.X25519, parsedIdentity.Type);
        Assert.Equal(identityString, parsedIdentity.ToIdentityString());
    }

    [Fact]
    public void ParseIdentity_InvalidString_ThrowsAgeKeyException()
    {
        var invalidString = "AGE-SECRET-KEY-invalid";

        Assert.Throws<AgeKeyException>(() => AgeParser.ParseIdentity(invalidString));
    }

    [Fact]
    public void ParseIdentity_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AgeParser.ParseIdentity(null!));
    }

    [Fact]
    public void ParseRecipientsFile_ValidFile_ReturnsRecipients()
    {
        var identity1 = AgeKeyGenerator.GenerateX25519Key();
        var identity2 = AgeKeyGenerator.GenerateX25519Key();
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, $"""
                # This is a comment
                {identity1.ToRecipientString()}
                # Another comment
                {identity2.ToRecipientString()}
                """);

            var recipients = AgeParser.ParseRecipientsFile(tempFile).ToList();

            Assert.Equal(2, recipients.Count);
            Assert.Equal(identity1.ToRecipientString(), recipients[0].ToRecipientString());
            Assert.Equal(identity2.ToRecipientString(), recipients[1].ToRecipientString());
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseRecipientsFile_FileWithOnlyComments_ReturnsEmptyList()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, """
                # Comment 1
                # Comment 2
                """);

            var recipients = AgeParser.ParseRecipientsFile(tempFile).ToList();

            Assert.Empty(recipients);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseRecipientsFile_FileWithBlankLines_ReturnsRecipients()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, $"""

                {identity.ToRecipientString()}

                """);

            var recipients = AgeParser.ParseRecipientsFile(tempFile).ToList();

            Assert.Single(recipients);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseIdentitiesFile_ValidFile_ReturnsIdentities()
    {
        var identity1 = AgeKeyGenerator.GenerateX25519Key();
        var identity2 = AgeKeyGenerator.GenerateX25519Key();
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, $"""
                # This is a comment
                {identity1.ToIdentityString()}
                # Another comment
                {identity2.ToIdentityString()}
                """);

            var identities = AgeParser.ParseIdentitiesFile(tempFile).ToList();

            Assert.Equal(2, identities.Count);
            Assert.Equal(identity1.ToIdentityString(), identities[0].ToIdentityString());
            Assert.Equal(identity2.ToIdentityString(), identities[1].ToIdentityString());
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseIdentitiesFile_FileWithOnlyComments_ReturnsEmptyList()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, """
                # Comment 1
                # Comment 2
                """);

            var identities = AgeParser.ParseIdentitiesFile(tempFile).ToList();

            Assert.Empty(identities);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ParseRecipient_RealAgeRecipientString_ParsesCorrectly()
    {
        var realRecipient = "age1n0szz7y4u757g66s2qkmv7tmrtpq55h6ve9tvugutwttwtcs99jsqlrx6j";

        var recipient = AgeParser.ParseRecipient(realRecipient);

        Assert.NotNull(recipient);
        Assert.Equal(RecipientType.X25519, recipient.Type);
        Assert.Equal(realRecipient, recipient.ToRecipientString());
    }

    [Fact]
    public void ParseIdentity_RealAgeIdentityString_ParsesCorrectly()
    {
        var realIdentity = "AGE-SECRET-KEY-1RJD99JTCZLF60ACFAH9T34FF7XPFH5JF79VJNL8X3GA856KMDU5SZ0UU85";

        var identity = AgeParser.ParseIdentity(realIdentity);

        Assert.NotNull(identity);
        Assert.Equal(RecipientType.X25519, identity.Type);
        Assert.Equal(realIdentity, identity.ToIdentityString());
    }

    [Fact]
    public void ParseRecipient_RecipientWithWhitespace_TrimsAndParses()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var recipientWithWhitespace = $"   {identity.ToRecipientString()}   ";

        var recipient = AgeParser.ParseRecipient(recipientWithWhitespace);

        Assert.NotNull(recipient);
        Assert.Equal(identity.ToRecipientString(), recipient.ToRecipientString());
    }

    [Fact]
    public void ParseIdentity_IdentityWithWhitespace_TrimsAndParses()
    {
        var identity = AgeKeyGenerator.GenerateX25519Key();
        var identityWithWhitespace = $"   {identity.ToIdentityString()}   ";

        var parsedIdentity = AgeParser.ParseIdentity(identityWithWhitespace);

        Assert.NotNull(parsedIdentity);
        Assert.Equal(identity.ToIdentityString(), parsedIdentity.ToIdentityString());
    }
}
