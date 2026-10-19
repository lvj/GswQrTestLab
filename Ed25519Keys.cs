using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace GswQrTestLab;

// Para kluczy Ed25519 (BouncyCastle) z prostym podpisywaniem i weryfikacją.
public sealed class Ed25519Keys
{
    private const int SeedLength = 32;

    private readonly Ed25519PrivateKeyParameters _privateKey;
    private readonly Ed25519PublicKeyParameters _publicKey;

    public byte[] Seed { get; }
    public byte[] PublicKeyBytes => _publicKey.GetEncoded();

    private Ed25519Keys(byte[] seed)
    {
        if (seed.Length != SeedLength)
            throw new ArgumentException($"Ed25519 seed musi mieć {SeedLength} bajty.");
        Seed = seed;
        _privateKey = new Ed25519PrivateKeyParameters(seed, 0);
        _publicKey = _privateKey.GeneratePublicKey();
    }

    // Null lub pusty seed = nowy, losowy klucz.
    public static Ed25519Keys Create(string? seedHex) =>
        new(string.IsNullOrEmpty(seedHex)
            ? RandomNumberGenerator.GetBytes(SeedLength)
            : Convert.FromHexString(seedHex));

    public byte[] Sign(byte[] input)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    public bool Verify(byte[] input, byte[] signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, _publicKey);
        verifier.BlockUpdate(input, 0, input.Length);
        return verifier.VerifySignature(signature);
    }

    // Podpisuje i od razu weryfikuje podpis (kontrola poprawności).
    public byte[] SignAndVerify(byte[] input)
    {
        byte[] signature = Sign(input);
        if (!Verify(input, signature))
            throw new CryptographicException("Podpis nie przeszedł weryfikacji.");
        return signature;
    }
}
