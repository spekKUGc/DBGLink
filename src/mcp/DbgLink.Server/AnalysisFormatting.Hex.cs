using System.Text;

namespace DbgLink.Server;

internal static partial class AnalysisFormatting
{
    internal static string FormatCompactHex(ReadOnlySpan<byte> bytes, int maxBytesPerLine = 16)
    {
        if (bytes.IsEmpty) return "";

        var sb = new StringBuilder();
        var zeroCount = 0;

        for (int i = 0; i < bytes.Length; i += maxBytesPerLine)
        {
            var chunkLen = Math.Min(maxBytesPerLine, bytes.Length - i);
            var chunk = bytes.Slice(i, chunkLen);

            var isAllZero = true;
            for (int j = 0; j < chunk.Length; j++)
            {
                if (chunk[j] != 0)
                {
                    isAllZero = false;
                    break;
                }
            }

            if (isAllZero)
            {
                zeroCount += chunkLen;
                continue;
            }

            if (zeroCount > 0)
            {
                sb.AppendLine($"* [repeated {zeroCount} zero bytes omitted]");
                zeroCount = 0;
            }

            sb.Append(Convert.ToHexString(chunk));
            sb.AppendLine();
        }

        if (zeroCount > 0)
        {
            sb.AppendLine($"* [repeated {zeroCount} zero bytes omitted]");
        }

        return sb.ToString().TrimEnd();
    }
}
