using System.Security.Cryptography;
using System.Text.Json;
using static GswQrTestLab.Encodings;

namespace GswQrTestLab;

// Buduje warianty QR zgodnie z flagami w LabConfig.
public static class Variants
{
    public static IEnumerable<QrVariant> Build(byte[] raw, Ed25519Keys keys, byte[] supplierMasterKey)
    {
        var unsigned = LabConfig.GenerateUnsigned ? BuildUnsigned(raw) : [];
        var signed = LabConfig.GenerateSigned ? BuildSigned(raw, keys) : [];
        IEnumerable<QrVariant> awizo = LabConfig.GenerateAwizoHmac
            ? [BuildAwizo("09_awizo_hmac_alnum", supplierMasterKey, LabConfig.ProductCode, FieldCharset.QrAlphanumeric)]
            : [];
        IEnumerable<QrVariant> awizoUtf8 = LabConfig.GenerateAwizoHmacUtf8
            ? [BuildAwizo("09a_awizo_hmac_utf8", supplierMasterKey, LabConfig.ProductCodeUtf8, FieldCharset.Utf8)]
            : [];
        return unsigned.Concat(signed).Concat(awizo).Concat(awizoUtf8);
    }

    private static IEnumerable<QrVariant> BuildUnsigned(byte[] raw)
    {
        if (LabConfig.GeneratePlainText)
            yield return new("01_plain", "Plain text UTF-8", raw, true,
                "Bez podpisu; tekst może uzyskać tryb QR alphanumeric");
        if (LabConfig.GenerateBinary)
            yield return new("02_binary", "QR byte mode", raw, false,
                "Te same bajty, wymuszony tryb byte");
        if (LabConfig.GenerateBase64Url)
            yield return new("03_base64url", "Base64url", Utf8(Base64Url(raw)), true,
                "Tekst zakodowany Base64url");
    }

    private static IEnumerable<QrVariant> BuildSigned(byte[] raw, Ed25519Keys keys)
    {
        // Podpis bez dodatkowych pól: [UTF8 payload][64B signature]
        byte[] signedRaw = [.. raw, .. keys.SignAndVerify(raw)];
        if (LabConfig.GenerateBinary)
            yield return new("04_signed_binary_raw", "Bytes: payload + signature", signedRaw, false,
                "Najmniejszy wariant bez ramki; rozmiar podpisu zawsze 64B");
        if (LabConfig.GenerateBase64Url)
            yield return new("05_signed_base64url_raw", "Base64url(payload + signature)", Utf8(Base64Url(signedRaw)), true,
                "Całość jako drukowalny tekst");

        // Jawna, jednoznaczna ramka binarna z magic i długością; podpis obejmuje całą ramkę.
        byte[] frame = BuildPdmFrame(raw);
        byte[] signedFrame = [.. frame, .. keys.SignAndVerify(frame)];
        if (LabConfig.GenerateBinary)
            yield return new("06_signed_binary_framed", $"Binary {LabConfig.BinaryMagic} + Ed25519", signedFrame, false,
                "4B magic + 2B długość + dane + 64B podpis");
        if (LabConfig.GenerateBase64Url)
            yield return new("07_signed_base64url_framed", $"Base64url({LabConfig.BinaryMagic} frame)", Utf8(Base64Url(signedFrame)), true,
                "Ramka binarna jako drukowalny tekst");

        // JWS Compact: base64url(header).base64url(payload).base64url(signature)
        if (LabConfig.GenerateJws)
            yield return new("08_signed_jws", "JWS compact", Utf8(BuildJws(raw, keys)), true,
                "JWS EdDSA; podpisuje header.payload");
    }

    private static string BuildJws(byte[] payload, Ed25519Keys keys)
    {
        string header = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["alg"] = "EdDSA",
            ["typ"] = LabConfig.JwsType,
            ["kid"] = LabConfig.KeyId,
        });
        string signingInput = Base64Url(Utf8(header)) + "." + Base64Url(payload);
        byte[] signature = keys.SignAndVerify(Utf8(signingInput));
        return signingInput + "." + Base64Url(signature);
    }

    // Awizacja okresowa: dostawca tworzy bilet kluczem awiza, system wagowy weryfikuje kluczem głównym dostawcy.
    private static QrVariant BuildAwizo(string name, byte[] supplierMasterKey, string productCode, FieldCharset charset)
    {
        byte[] awizoKey = AwizoTicket.DeriveAwizoKey(supplierMasterKey, LabConfig.AwizoId);
        var fields = new AwizoTicket.Fields(LabConfig.AwizoId, LabConfig.DocNumber, productCode, LabConfig.DeclaredWeightKg);
        string ticket = AwizoTicket.Create(awizoKey, LabConfig.AwizoPlate, fields, charset);
        if (!AwizoTicket.Verify(ticket, LabConfig.AwizoId, supplierMasterKey, LabConfig.AwizoPlate))
            throw new CryptographicException("Bilet awizacji okresowej nie przeszedł weryfikacji.");

        return charset == FieldCharset.QrAlphanumeric
            ? new(name, $"HMAC-SHA256/{LabConfig.HmacTagBytes}B + Base32, QR alphanumeric", Utf8(ticket), true,
                "Awizacja okresowa; tablica w MAC, nie w QR")
            : new(name, $"HMAC-SHA256/{LabConfig.HmacTagBytes}B + Base32, pola UTF-8 (QR byte)", Utf8(ticket), true,
                "Jak 9, ale pola tekstowe UTF-8 (np. polskie znaki)");
    }
}
