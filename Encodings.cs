using System.Buffers.Binary;
using System.Text;

namespace GswQrTestLab;

public static class Encodings
{
    private const int MagicLength = 4;
    private const int FrameHeaderLength = MagicLength + sizeof(ushort);
    private const int HexDumpBytesPerLine = 16;

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // RFC 4648 Base32 bez paddingu '='; alfabet A-Z 2-7 mieści się w trybie QR alphanumeric.
    public static string Base32(byte[] bytes)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder((bytes.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (byte b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(Alphabet[(buffer >> bits) & 31]);
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0)
            sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    // Ramka: [4B magic ASCII][2B długość payload, big endian][payload]
    public static byte[] BuildPdmFrame(byte[] payload)
    {
        byte[] magic = Encoding.ASCII.GetBytes(LabConfig.BinaryMagic);
        if (magic.Length != MagicLength)
            throw new ArgumentException($"BinaryMagic musi mieć dokładnie {MagicLength} znaki ASCII.");
        if (payload.Length > ushort.MaxValue)
            throw new ArgumentException("Zbyt długi payload dla ramki binarnej.");

        byte[] frame = new byte[FrameHeaderLength + payload.Length];
        magic.CopyTo(frame, 0);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(MagicLength, sizeof(ushort)), (ushort)payload.Length);
        payload.CopyTo(frame, FrameHeaderLength);
        return frame;
    }

    // Klasyczny zrzut: offset | hex | ASCII ('.' dla znaków niedrukowalnych).
    public static string HexDump(byte[] bytes)
    {
        var sb = new StringBuilder();
        for (int offset = 0; offset < bytes.Length; offset += HexDumpBytesPerLine)
        {
            var line = bytes.AsSpan(offset, Math.Min(HexDumpBytesPerLine, bytes.Length - offset));
            sb.Append($"{offset:X4}  ");
            for (int i = 0; i < HexDumpBytesPerLine; i++)
                sb.Append(i < line.Length ? $"{line[i]:X2} " : "   ");
            sb.Append(' ');
            foreach (byte b in line)
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
