using System.Collections.Generic;
using System.Text.Json;

namespace GameHelperGUI.Models;

public sealed class ParameterMetadataRoot
{
    public List<ParameterSectionMetadata> Sections { get; set; } = new();
}

public sealed class ParameterSectionMetadata
{
    public string Name { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public List<ParameterItemMetadata> Items { get; set; } = new();
}

public sealed class ParameterItemMetadata
{
    public string Key { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Type { get; set; } = "string";
    public JsonElement Default { get; set; }
    public double? Min { get; set; }
    public double? Max { get; set; }
    public string Desc { get; set; } = string.Empty;
}
