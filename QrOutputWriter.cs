using System.Text;
using QRCoder;

namespace GswQrTestLab;

// Zapisuje wariant jako .svg, .bin oraz .txt (zawartość + QR w ASCII) i wypisuje część ASCII na konsolę.
public sealed class QrOutputWriter(string outputDirectory)
{
    private const int QuietZoneModules = 4;

    public ReportEntry Write(QrVariant variant)
    {
        using var data = variant.TextMode
            ? QRCodeGenerator.GenerateQrCode(Encoding.UTF8.GetString(variant.Bytes), LabConfig.Correction)
            : QRCodeGenerator.GenerateQrCode(variant.Bytes, LabConfig.Correction);

        // ModuleMatrix zawiera strefę ciszy (po 4 moduły z każdej strony); sam symbol jest mniejszy.
        int modules = data.ModuleMatrix.Count - 2 * QuietZoneModules;
        int version = (modules - 17) / 4;
        int svgModules = LabConfig.AddQuietZone ? data.ModuleMatrix.Count : modules;

        // Renderery QRCoder nie są tu zwalniane: ich Dispose() zwalnia też współdzielone QRCodeData.
        WriteSvg(variant.Name, data);
        File.WriteAllBytes(PathFor(variant.Name, ".bin"), variant.Bytes);

        string ascii = BuildAscii(variant, data, version, modules);
        File.WriteAllText(PathFor(variant.Name, ".txt"), ascii, Encoding.UTF8);
        Console.WriteLine(ascii);

        return new ReportEntry(variant.Name, variant.Encoding, variant.Bytes.Length,
            version, modules, svgModules * LabConfig.PixelsPerModule, variant.Notes);
    }

    private void WriteSvg(string name, QRCodeData data)
    {
        string graphic = new SvgQRCode(data).GetGraphic(LabConfig.PixelsPerModule, "#000000", "#ffffff", LabConfig.AddQuietZone);
        File.WriteAllText(PathFor(name, ".svg"), graphic, Encoding.UTF8);
    }

    private static string BuildAscii(QrVariant variant, QRCodeData data, int version, int modules)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"===== {variant.Name} =====");
        sb.AppendLine($"Encoding: {variant.Encoding}");
        sb.AppendLine($"Bytes in QR: {variant.Bytes.Length}, QR version: {version} ({modules}x{modules} modules)");
        sb.AppendLine();

        sb.AppendLine("Content:");
        sb.AppendLine(variant.TextMode
            ? Encoding.UTF8.GetString(variant.Bytes)
            : Encodings.HexDump(variant.Bytes).TrimEnd());
        sb.AppendLine();

        sb.AppendLine(new AsciiQRCode(data).GetGraphicSmall(drawQuietZones: LabConfig.AddQuietZone));
        return sb.ToString();
    }

    private string PathFor(string name, string extension) => Path.Combine(outputDirectory, name + extension);
}
