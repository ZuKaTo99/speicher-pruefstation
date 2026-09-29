using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using SpeicherPrüfstation.Desktop.Formatting;
using SpeicherPrüfstation.Desktop.Models;

namespace SpeicherPrüfstation.Desktop.ViewModels;

public sealed partial class QuarantineStorageEntryViewModel :
    ViewModelBase
{
    public QuarantineStorageEntryViewModel(
        QuarantineStorageEntry entry)
    {
        Entry = entry
            ?? throw new ArgumentNullException(
                nameof(entry));

        SourceText = CreateSourceText(entry);

        SignaturesText =
            CreateSignaturesText(entry.Signatures);
    }

    public QuarantineStorageEntry Entry { get; }

    [ObservableProperty]
    public partial bool IsSelected
    {
        get;
        set;
    }

    public string EntryId =>
        Entry.EntryId;

    public string OriginalFilePath =>
        Entry.OriginalFilePath;

    public string QuarantinedAtText =>
        Entry.QuarantinedAtUtc
            .ToLocalTime()
            .ToString(
                "g",
                CultureInfo.CurrentCulture);

    public string SourceText { get; }

    public string OriginalSizeText =>
        ByteSizeFormatter.Format(
            Entry.OriginalSizeBytes);

    public string StoredSizeText =>
        ByteSizeFormatter.Format(
            Entry.StoredSizeBytes);

    public string SignaturesText { get; }

    private static string CreateSourceText(
        QuarantineStorageEntry entry)
    {
        var deviceDescription =
            new List<string>();

        if (!string.IsNullOrWhiteSpace(
                entry.SourceVendor))
        {
            deviceDescription.Add(
                entry.SourceVendor.Trim());
        }

        if (!string.IsNullOrWhiteSpace(
                entry.SourceModel))
        {
            deviceDescription.Add(
                entry.SourceModel.Trim());
        }

        return deviceDescription.Count == 0
            ? entry.SourceDevicePath
            : entry.SourceDevicePath
              + " · "
              + string.Join(
                  " ",
                  deviceDescription);
    }

    private static string CreateSignaturesText(
        IReadOnlyList<string> signatures)
    {
        string[] values =
            signatures
                .Where(value =>
                    !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

        return values.Length == 0
            ? "Keine Signatur gespeichert"
            : string.Join(", ", values);
    }
}
