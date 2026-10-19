namespace GswQrTestLab;

// Jeden wariant kodu QR. TextMode = bajty traktowane jako tekst UTF-8 (QRCoder sam dobiera tryb),
// w przeciwnym razie wymuszony tryb byte.
public record QrVariant(string Name, string Encoding, byte[] Bytes, bool TextMode, string Notes);
