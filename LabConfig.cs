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
    // static readonly (nie const), aby kompilator nie traktował wartości jako stałej (CS8519).
    public static readonly string? PrivateSeedHex = null;

    // Header JWS: nie zmieniaj alg na inny bez zmiany implementacji kryptografii.
    public const string KeyId = "K000145-KEY01";
    public const string JwsType = "PDM-QR"; // tylko jeśli payload ma semantykę JWT; inaczej np. "PDM-QR".

    // Binarna ramka podpisu: [4 bajty ASCII 'PDM1'][2 bajty długości payload big endian][payload][64 bajty podpisu]
    // Podpis obejmuje nagłówek PDM1, długość i payload.
    public const string BinaryMagic = "PDMX";

    // ===== Wariant awizacji okresowej: HMAC-SHA256 + QR alphanumeric (Base32) =====
    // Opis procesu: README, sekcja "Awizacja okresowa".
    public const bool GenerateAwizoHmac = true;
    public const bool GenerateAwizoHmacUtf8 = true; // wariant 9a: pola tekstowe UTF-8 (QR byte mode)

    // Klucz główny dostawcy (jeden na dostawcę): 32 bajty (hex 64 znaki), przechowywany TYLKO w systemie wagowym.
    // Null = losowy, nowy przy każdym uruchomieniu.
    public static readonly string? SupplierMasterKeyHex = null;

    // Długość tagu HMAC w bajtach (6 B = 10 znaków Base32).
    public const int HmacTagBytes = 6;

    // Dane awizacji okresowej (znane systemowi wagowemu).
    public const int AwizoId = 1045; // identyfikator awiza w systemie wagowym (liczba całkowita)
    public const string AwizoPlate = "BS 12345"; // w MAC po normalizacji (wielkie litery, bez spacji/myślników); nie trafia do QR

    // Dane uzupełniane przez dostawcę dla konkretnej dostawy.
    // Dozwolone znaki: 0-9 A-Z spacja $ % + - . / : (małe litery są zamieniane na wielkie; '*' to separator).
    public const string DocNumber = "WZ1542/10/2026";
    public const string ProductCode = "TOW123";
    public const int DeclaredWeightKg = 24500;

    // Wariant 9a: dowolne znaki UTF-8 poza '*' i znakami sterującymi (małe litery zamieniane na wielkie, normalizacja NFC).
    public const string ProductCodeUtf8 = "GŻEGŻÓŁKA-245+18";
}
