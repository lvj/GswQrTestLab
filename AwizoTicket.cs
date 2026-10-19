using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using static GswQrTestLab.Encodings;

namespace GswQrTestLab;

// Bilet awizacji okresowej (wiele dostaw na jedno awizo): tekst w trybie QR alphanumeric, uwierzytelniony obciętym HMAC-SHA256.
//
//   QR:          V1*<awizoId>*<dokument>*<produkt>*<wagaKg>*<tag Base32>
//   Wejście MAC: V1*<awizoId>*<TABLICA>*<dokument>*<produkt>*<wagaKg>   (UTF-8)
//   Klucz:       awizoKey = HMAC-SHA256(supplierMasterKey, "awizo:" + <awizoId>)
//
// Tablica rejestracyjna jest w MAC, ale nie w QR: system wagowy zna ją z awizacji.
//
// Zestaw znaków pól tekstowych:
//   QrAlphanumeric (wariant 9):  0-9 A-Z spacja $ % + - . / :  → cały bilet w trybie QR alphanumeric.
//   Utf8           (wariant 9a): dowolny UTF-8 poza '*' i znakami sterującymi → QR byte mode, większy kod.
// Weryfikacja jest identyczna dla obu: HMAC liczony z bajtów UTF-8 tekstu (po normalizacji NFC).
public enum FieldCharset { QrAlphanumeric, Utf8 }

public static class AwizoTicket
{
    public const string Version = "V1";
    private const char Separator = '*';
    private const int FieldCount = 6;
    private const int MasterKeyLength = 32;

    // Zbiór znaków QR alphanumeric bez '*', który jest separatorem.
    private const string AllowedFieldChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%+-./:";

    public record Fields(int AwizoId, string DocNumber, string ProductCode, int DeclaredWeightKg);

    // Klucz główny dostawcy (jeden na dostawcę). Null lub pusty hex = nowy, losowy klucz.
    public static byte[] CreateSupplierMasterKey(string? hex)
    {
        byte[] key = string.IsNullOrEmpty(hex) ? RandomNumberGenerator.GetBytes(MasterKeyLength) : Convert.FromHexString(hex);
        if (key.Length != MasterKeyLength)
            throw new ArgumentException($"Klucz główny dostawcy musi mieć {MasterKeyLength} bajty.");
        return key;
    }

    // Klucz przekazywany dostawcy; system wagowy odtwarza go z klucza głównego dostawcy, nie musi go przechowywać.
    public static byte[] DeriveAwizoKey(byte[] supplierMasterKey, int awizoId) =>
        HMACSHA256.HashData(supplierMasterKey, Utf8("awizo:" + FormatInt(awizoId)));

    // Strona dostawcy: zna tylko awizoKey i tablicę z awizacji.
    public static string Create(byte[] awizoKey, string plate, Fields fields, FieldCharset charset = FieldCharset.QrAlphanumeric)
    {
        string[] ticketFields =
        [
            Version,
            FormatInt(fields.AwizoId),
            NormalizeField(fields.DocNumber, charset),
            NormalizeField(fields.ProductCode, charset),
            FormatInt(fields.DeclaredWeightKg),
        ];
        string tag = Base32(ComputeTag(awizoKey, plate, ticketFields));
        return string.Join(Separator, [.. ticketFields, tag]);
    }

    // Strona systemu wagowego: awizo znalezione dla pojazdu (po LPR) dostarcza oczekiwany AwizoId i tablicę;
    // klucz awiza odtwarzany z klucza głównego dostawcy.
    public static bool Verify(string ticket, int expectedAwizoId, byte[] supplierMasterKey, string plateFromNotice)
    {
        // NFC: ta sama postać znaków co u dostawcy, nawet jeśli skaner/system zwróci 'Ż' jako 'Z' + znak łączący.
        string[] parts = ticket.Trim().Normalize(NormalizationForm.FormC).Split(Separator);
        if (parts.Length != FieldCount || parts[0] != Version)
            return false;
        if (parts[1] != FormatInt(expectedAwizoId))
            return false;

        byte[] awizoKey = DeriveAwizoKey(supplierMasterKey, expectedAwizoId);
        string expectedTag = Base32(ComputeTag(awizoKey, plateFromNotice, parts[..^1]));
        return CryptographicOperations.FixedTimeEquals(Utf8(expectedTag), Utf8(parts[^1]));
    }

    private static byte[] ComputeTag(byte[] awizoKey, string plate, string[] ticketFields)
    {
        // V1*awizoId*TABLICA*dokument*produkt*waga — pola biletu bez tagu, z tablicą wstawioną po awizoId
        string macInput = string.Join(Separator,
            [ticketFields[0], ticketFields[1], NormalizePlate(plate), .. ticketFields[2..]]);
        return HMACSHA256.HashData(awizoKey, Utf8(macInput))[..LabConfig.HmacTagBytes];
    }

    public static string NormalizePlate(string plate) =>
        new(plate.ToUpperInvariant().Where(char.IsAsciiLetterOrDigit).ToArray());

    // Liczby całkowite: zapis dziesiętny, bez zer wiodących, separatorów i znaku.
    private static string FormatInt(int value) =>
        value > 0 ? value.ToString(CultureInfo.InvariantCulture) : throw new ArgumentException("Wartość musi być dodatnia.");

    private static string NormalizeField(string value, FieldCharset charset)
    {
        string normalized = value.Trim().Normalize(NormalizationForm.FormC).ToUpperInvariant();
        if (normalized.Length == 0)
            throw new ArgumentException("Pole nie może być puste.");

        bool valid = charset switch
        {
            FieldCharset.QrAlphanumeric => normalized.All(AllowedFieldChars.Contains),
            FieldCharset.Utf8 => !normalized.Any(c => c == Separator || char.IsControl(c)),
            _ => throw new ArgumentOutOfRangeException(nameof(charset)),
        };
        if (!valid)
            throw new ArgumentException(charset == FieldCharset.QrAlphanumeric
                ? $"Pole '{value}' zawiera znaki spoza trybu QR alphanumeric (dozwolone: {AllowedFieldChars})."
                : $"Pole '{value}' zawiera separator '{Separator}' lub znak sterujący.");
        return normalized;
    }
}
