using System.Text;
using GswQrTestLab;

// Znaki ▀▄█ w QR ASCII wymagają UTF-8 na konsoli.
Console.OutputEncoding = Encoding.UTF8;

string outDir = Path.GetFullPath(LabConfig.OutputDirectory);
Directory.CreateDirectory(outDir);

var keys = Ed25519Keys.Create(LabConfig.PrivateSeedHex);
byte[] supplierMasterKey = AwizoTicket.CreateSupplierMasterKey(LabConfig.SupplierMasterKeyHex);
byte[] raw = Encodings.Utf8(LabConfig.Payload);

var writer = new QrOutputWriter(outDir);
var entries = Variants.Build(raw, keys, supplierMasterKey).Select(writer.Write).ToList();

string report = Report.Build(raw, keys, supplierMasterKey, entries);
File.WriteAllText(Path.Combine(outDir, "report.txt"), report, Encoding.UTF8);
File.WriteAllText(Path.Combine(outDir, "public_key.hex"), Convert.ToHexString(keys.PublicKeyBytes));

Console.WriteLine(report);
Console.WriteLine("Zapisano SVG, ASCII (.txt) i binarne pliki payload w: " + outDir);
