using QRCoder;

namespace GswQrTestLab;

// Wszystkie opcje testowe są tutaj.
public static class LabConfig
{
    // {IdAwizo}}|{khCode}|{regPlate}|{docType}|{docNumber}|{declaredWeight}|{productCode}|{driverName}
    public const string Payload = "5|XKONTR|BS12345|WZ|WZ1542/10/2026|24500|TOW123|Jan Jankowski";
    public const string OutputDirectory = "output";
    public const QRCodeGenerator.ECCLevel Correction = QRCodeGenerator.ECCLevel.M;
    public const int PixelsPerModule = 12;
    public const bool AddQuietZone = true;

    // Podpis jest nad bajtami UTF-8 Payload, nigdy nad jego Base64.
    public const bool GenerateUnsigned = true;
    public const bool GenerateSigned = true;
    public const bool GenerateBinary = true;
    public const bool GenerateBase64Url = true;
    public const bool GeneratePlainText = true;
    public const bool GenerateJws = true;

    // Ed25519: 32-bajtowy seed (hex 64 znaki). Null = losowy, nowy przy każdym uruchomieniu.
    // Klucz testowy można zachować, kopiując wyświetlony seed do tego pola.
    // NIGDY nie stosuj testowych kluczy w produkcji.
    public const string? PrivateSeedHex = null;

    // Header JWS: nie zmieniaj alg na inny bez zmiany implementacji kryptografii.
    public const string KeyId = "K000145-KEY01";
    public const string JwsType = "JWT"; // tylko jeśli payload ma semantykę JWT; inaczej np. "PDM-QR".

    // Binarna ramka podpisu: [4 bajty ASCII 'PDM1'][2 bajty długości payload big endian][payload][64 bajty podpisu]
    // Podpis obejmuje nagłówek PDM1, długość i payload.
    public const string BinaryMagic = "PDMX";
}
