using System.Text;

namespace GswQrTestLab;

public record ReportEntry(string Filename, string Encoding, int Bytes, int Version, int Modules, int Pixels, string Notes);

public static class Report
{
    public static string Build(byte[] raw, Ed25519Keys keys, byte[] supplierMasterKey, IEnumerable<ReportEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine("GswQrTestLab - porównanie QR");
        sb.AppendLine("Payload: " + LabConfig.Payload);
        sb.AppendLine("Payload UTF-8 bytes: " + raw.Length);
        sb.AppendLine("ECC: " + LabConfig.Correction);
        sb.AppendLine("KeyId: " + LabConfig.KeyId);
        sb.AppendLine("Public key HEX: " + Convert.ToHexString(keys.PublicKeyBytes));
        sb.AppendLine("Private seed HEX (TYLKO TESTY; nie udostępniać): " + Convert.ToHexString(keys.Seed));
        if (LabConfig.GenerateAwizoHmac)
        {
            byte[] awizoKey = AwizoTicket.DeriveAwizoKey(supplierMasterKey, LabConfig.AwizoId);
            sb.AppendLine($"Awizo: {LabConfig.AwizoId}, tablica: {AwizoTicket.NormalizePlate(LabConfig.AwizoPlate)}");
            sb.AppendLine("Supplier master key HEX (TYLKO system wagowy; nie udostępniać): " + Convert.ToHexString(supplierMasterKey));
            sb.AppendLine("Awizo key HEX (przekazywany dostawcy): " + Convert.ToHexString(awizoKey));
        }
        sb.AppendLine("UWAGA: SVG kodu binarnego należy testować skanerem/API zachowującym surowe bajty.");
        sb.AppendLine();
        sb.AppendLine("Filename | Encoding | bytes in QR | QR version | modules per side | SVG pixels per side | notes");
        foreach (var e in entries)
            sb.AppendLine($"{e.Filename} | {e.Encoding} | {e.Bytes} | {e.Version} | {e.Modules} | {e.Pixels} | {e.Notes}");
        return sb.ToString();
    }
}
