using System.Globalization;

namespace SpeicherPrüfstation.Desktop.Formatting;

public static class ByteSizeFormatter
{
    private static readonly string[] Units =
    [
        "B",
        "KiB",
        "MiB",
        "GiB",
        "TiB",
        "PiB"
    ];

    public static string Format(long byteCount)
    {
        if (byteCount < 0)
        {
            return "Unbekannt";
        }

        double value = byteCount;
        int unitIndex = 0;

        while (value >= 1024
               && unitIndex < Units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        string numberFormat;

        if (unitIndex == 0 || value >= 100)
        {
            numberFormat = "0";
        }
        else if (value >= 10)
        {
            numberFormat = "0.0";
        }
        else
        {
            numberFormat = "0.00";
        }

        string formattedValue =
            value.ToString(
                numberFormat,
                CultureInfo.CurrentCulture);

        return $"{formattedValue} {Units[unitIndex]}";
    }
}