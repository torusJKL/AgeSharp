using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using AgeSharp.Core.Encoding;
using AgeSharp.Core.Exceptions;
using Norgerman.Cryptography.Scrypt;

namespace AgeSharp.Core.Headers;

internal sealed class ScryptStanza : Stanza
{
    private const string StanzaType = "scrypt";
    private const int SaltSize = 16;
    private const int FileKeySize = 16;
    private const int NonceSize = 12;
    private const int DefaultLogN = 18;
    private const int MaxLogN = 22;

    private static readonly byte[] Nonce = new byte[NonceSize];
    private static readonly byte[] SaltPrefix = "age-encryption.org/v1/scrypt"u8.ToArray();

    private readonly byte[] _salt;
    private readonly int _logN;

    internal ScryptStanza(byte[] salt, int logN, byte[] body)
        : base([Base64NoPadding.Encode(salt), logN.ToString()], body)
    {
        _salt = salt;
        _logN = logN;
    }

    public override string Type => StanzaType;

    internal byte[] GetSalt() => _salt;
    internal int GetLogN() => _logN;

    internal static ScryptStanza Create(byte[] fileKey, string passphrase)
    {
        ArgumentNullException.ThrowIfNull(fileKey);
        ArgumentNullException.ThrowIfNull(passphrase);

        if (fileKey.Length != FileKeySize)
        {
            throw new ArgumentException($"File key must be {FileKeySize} bytes");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var wrapKey = DeriveKey(passphrase, salt, DefaultLogN);

        var nonce = new byte[NonceSize];
        var body = EncryptWithKey(wrapKey, fileKey, nonce);

        return new ScryptStanza(salt, DefaultLogN, body);
    }

    internal byte[] Unwrap(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);

        if (Body.Length != 32)
        {
            throw new AgeFormatException("Scrypt body must be exactly 32 bytes");
        }

        if (_logN > MaxLogN)
        {
            throw new AgeFormatException($"Scrypt logN exceeds maximum allowed value of {MaxLogN}");
        }

        var wrapKey = DeriveKey(passphrase, _salt, _logN);
        return DecryptWithKey(wrapKey, Body, Nonce);
    }

    private static byte[] DeriveKey(string passphrase, byte[] salt, int logN)
    {
        var normalizedPassphrase = NormalizePassphrase(passphrase);
        var passphraseBytes = new UTF8Encoding(false).GetBytes(normalizedPassphrase);

        var scryptSalt = new byte[SaltPrefix.Length + salt.Length];
        Buffer.BlockCopy(SaltPrefix, 0, scryptSalt, 0, SaltPrefix.Length);
        Buffer.BlockCopy(salt, 0, scryptSalt, SaltPrefix.Length, salt.Length);

        var n = 1 << logN;
        return ScryptUtil.Scrypt(passphraseBytes, scryptSalt, n, 8, 1, 32);
    }

    private static string NormalizePassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new AgeKeyException("Passphrase cannot be empty");
        }

        if (passphrase.Length > 64)
        {
            throw new AgeKeyException("Passphrase cannot exceed 64 characters");
        }

        return passphrase.Normalize(NormalizationForm.FormC);
    }

    private static byte[] EncryptWithKey(byte[] key, byte[] plaintext, byte[] nonce)
    {
        using var chacha = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        chacha.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    private static byte[] DecryptWithKey(byte[] key, byte[] ciphertextAndTag, byte[] nonce)
    {
        const int TagSize = 16;

        if (ciphertextAndTag.Length < TagSize)
        {
            throw new ArgumentException("Ciphertext too short");
        }

        var ciphertextLength = ciphertextAndTag.Length - TagSize;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagSize];
        Buffer.BlockCopy(ciphertextAndTag, 0, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(ciphertextAndTag, ciphertextLength, tag, 0, TagSize);

        using var chacha = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var plaintext = new byte[ciphertextLength];
        chacha.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    internal static ScryptStanza? TryParse(ParsedStanza stanza)
    {
        if (stanza.Type != StanzaType)
        {
            return null;
        }

        if (stanza.Arguments.Length != 2)
        {
            throw new AgeFormatException("Scrypt stanza must have exactly 2 arguments");
        }

        byte[] salt;
        try
        {
            salt = Base64NoPadding.Decode(stanza.Arguments[0]);
        }
        catch (FormatException)
        {
            throw new AgeFormatException("Invalid scrypt salt: not valid base64");
        }

        if (salt.Length != SaltSize)
        {
            throw new AgeFormatException($"Scrypt salt must be exactly {SaltSize} bytes");
        }

        var logNStr = stanza.Arguments[1];
        if (!Regex.IsMatch(logNStr, @"^[1-9][0-9]*$"))
        {
            throw new AgeFormatException("Scrypt logN must be a decimal number with no leading zeros");
        }

        if (!int.TryParse(logNStr, out var logN) || logN < 1)
        {
            throw new AgeFormatException("Invalid scrypt logN");
        }

        return new ScryptStanza(salt, logN, stanza.Body);
    }
}
