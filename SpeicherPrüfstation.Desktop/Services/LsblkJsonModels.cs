using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace SpeicherPrüfstation.Desktop.Services;

internal sealed class LsblkJsonResult
{
    [JsonPropertyName("blockdevices")]
    public List<LsblkJsonDevice> BlockDevices { get; init; } = [];
}

internal sealed class LsblkJsonDevice
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("kname")]
    public string? KernelName { get; init; }

    [JsonPropertyName("path")]
    public string? DevicePath { get; init; }

    [JsonPropertyName("pkname")]
    public string? ParentKernelName { get; init; }

    [JsonPropertyName("type")]
    public string? NodeType { get; init; }

    [JsonPropertyName("tran")]
    public string? Transport { get; init; }

    [JsonPropertyName("rm")]
    public bool IsRemovable { get; init; }

    [JsonPropertyName("hotplug")]
    public bool IsHotPlug { get; init; }

    [JsonPropertyName("size")]
    public long SizeBytes { get; init; }

    [JsonPropertyName("ro")]
    public bool IsReadOnly { get; init; }

    [JsonPropertyName("fstype")]
    public string? FileSystem { get; init; }

    [JsonPropertyName("label")]
    public string? Label { get; init; }

    [JsonPropertyName("mountpoints")]
    public List<string?> MountPoints { get; init; } = [];

    [JsonPropertyName("model")]
    public string? Model { get; init; }

    [JsonPropertyName("vendor")]
    public string? Vendor { get; init; }

    [JsonPropertyName("children")]
    public List<LsblkJsonDevice> Children { get; init; } = [];
}