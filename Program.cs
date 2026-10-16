using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using QRCoder;
using GswQrTestLab;

var outDir = Path.GetFullPath(LabConfig.OutputDirectory);
Directory.CreateDirectory(outDir);
byte[] seed = LabConfig.PrivateSeedHex is { Length: > 0 } ? Convert.FromHexString(LabConfig.PrivateSeedHex) : RandomNumberGenerator.GetBytes(32);
if (seed.Length != 32) throw new ArgumentException("Ed25519 seed musi mieć 32 bajty.");
var secret = new Ed25519PrivateKeyParameters(seed, 0);
var publicKey = secret.GeneratePublicKey();
byte[] publicBytes = publicKey.GetEncoded();
byte[] raw = Encoding.UTF8.GetBytes(LabConfig.Payload);

var entries = new List<ReportEntry>();
void Add(string filename, string encoding, byte[] bytes, bool textMode, string notes)
{
    using var data = textMode
        ? QRCodeGenerator.GenerateQrCode(Encoding.UTF8.GetString(bytes), LabConfig.Correction)
        : QRCodeGenerator.GenerateQrCode(bytes, LabConfig.Correction);
    using var svg = new SvgQRCode(data);
    File.WriteAllText(Path.Combine(outDir, filename + ".svg"),
        svg.GetGraphic(LabConfig.PixelsPerModule, "#000000", "#ffffff", LabConfig.AddQuietZone), Encoding.UTF8);
    File.WriteAllBytes(Path.Combine(outDir, filename + ".bin"), bytes);
    var side = data.ModuleMatrix.Count;
    entries.Add(new(filename, encoding, bytes.Length, side, side * LabConfig.PixelsPerModule, notes));
}

string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
byte[] Sign(byte[] input)
{
    var signer = new Ed25519Signer();
    signer.Init(true, secret);
    signer.BlockUpdate(input, 0, input.Length);
    return signer.GenerateSignature();
}
bool Verify(byte[] input, byte[] signature)
{
    var verifier = new Ed25519Signer();
    verifier.Init(false, publicKey);
    verifier.BlockUpdate(input, 0, input.Length);
    return verifier.VerifySignature(signature);
}

if (LabConfig.GenerateUnsigned)
{
    if (LabConfig.GeneratePlainText) Add("01_plain", "Plain text UTF-8", raw, true, "Bez podpisu; tekst może uzyskać tryb QR alphanumeric");
    if (LabConfig.GenerateBinary) Add("02_binary", "QR byte mode", raw, false, "Te same bajty, wymuszony tryb byte");
    if (LabConfig.GenerateBase64Url) Add("03_base64url", "Base64url", Utf8(Base64Url(raw)), true, "Tekst zakodowany Base64url");
}

if (LabConfig.GenerateSigned)
{
    // Podpis bez dodatkowych pól: [UTF8 payload][64B signature]
    byte[] signature = Sign(raw);
    byte[] concatenated = [..raw, ..signature];
    if (!Verify(raw, signature)) throw new CryptographicException("Podpis nie przeszedł weryfikacji.");
    if (LabConfig.GenerateBinary) Add("04_signed_binary_raw", "Bytes: payload + signature", concatenated, false, "Najmniejszy wariant bez ramki; rozmiar podpisu zawsze 64B");
    if (LabConfig.GenerateBase64Url) Add("05_signed_base64url_raw", "Base64url(payload + signature)", Utf8(Base64Url(concatenated)), true, "Całość jako drukowalny tekst");

    // Jawna, jednoznaczna ramka binarna z wersją/długością.
    if (raw.Length > ushort.MaxValue) throw new ArgumentException("Zbyt długi payload dla ramki PDM1.");
    byte[] framed = new byte[6 + raw.Length];
    Encoding.ASCII.GetBytes(LabConfig.BinaryMagic).CopyTo(framed, 0);
    BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(4, 2), (ushort)raw.Length);
    raw.CopyTo(framed, 6);
    byte[] framedSig = Sign(framed);
    if (!Verify(framed, framedSig)) throw new CryptographicException("Podpis ramki nie przeszedł weryfikacji.");
    byte[] framedSigned = [..framed, ..framedSig];
    if (LabConfig.GenerateBinary) Add("06_signed_binary_framed", "Binary PDM1 + Ed25519", framedSigned, false, "4B magic + 2B długość + dane + 64B podpis");
    if (LabConfig.GenerateBase64Url) Add("07_signed_base64url_framed", "Base64url(PDM1 frame)", Utf8(Base64Url(framedSigned)), true, "Ramka binarna jako drukowalny tekst");

    // JWS Compact:  base64url(header).base64url(payload).base64url(signature)
    if (LabConfig.GenerateJws)
    {
        string header = JsonSerializer.Serialize(new Dictionary<string, string> {
            ["alg"] = "EdDSA", ["typ"] = LabConfig.JwsType, ["kid"] = LabConfig.KeyId });
        string signingInput = Base64Url(Utf8(header)) + "." + Base64Url(raw);
        byte[] jwsSig = Sign(Utf8(signingInput));
        if (!Verify(Utf8(signingInput), jwsSig)) throw new CryptographicException("JWS verify failed.");
        string compact = signingInput + "." + Base64Url(jwsSig);
        Add("08_signed_jws", "JWS compact", Utf8(compact), true, "JWS EdDSA; podpisuje header.payload");
    }
}

var sb = new StringBuilder();
sb.AppendLine("GswQrTestLab - porównanie QR");
sb.AppendLine("Payload: " + LabConfig.Payload);
sb.AppendLine("Payload UTF-8 bytes: " + raw.Length);
sb.AppendLine("ECC: " + LabConfig.Correction);
sb.AppendLine("KeyId: " + LabConfig.KeyId);
sb.AppendLine("Public key HEX: " + Convert.ToHexString(publicBytes));
sb.AppendLine("Private seed HEX (TYLKO TESTY; nie udostępniać): " + Convert.ToHexString(seed));
sb.AppendLine("UWAGA: SVG kodu binarnego należy testować skanerem/API zachowującym surowe bajty.");
sb.AppendLine();
sb.AppendLine("Filename | Encoding | bytes in QR | modules per side | SVG pixels per side | notes");
foreach (var e in entries)
    sb.AppendLine($"{e.Filename} | {e.Encoding} | {e.Bytes} | {e.Modules} | {e.Pixels} | {e.Notes}");
File.WriteAllText(Path.Combine(outDir, "report.txt"), sb.ToString(), Encoding.UTF8);
File.WriteAllText(Path.Combine(outDir, "public_key.hex"), Convert.ToHexString(publicBytes));
Console.WriteLine(sb);
Console.WriteLine("Zapisano SVG i binarne pliki payload w: " + outDir);

record ReportEntry(string Filename, string Encoding, int Bytes, int Modules, int Pixels, string Notes);
