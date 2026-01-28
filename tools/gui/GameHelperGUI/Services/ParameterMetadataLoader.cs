using System.IO;
using System.Text.Json;
using GameHelperGUI.Models;

namespace GameHelperGUI.Services;

public sealed class ParameterMetadataLoader
{
    public ParameterMetadataRoot Load(string path)
    {
        var json = File.ReadAllText(path);
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
        return JsonSerializer.Deserialize<ParameterMetadataRoot>(json, options) ?? new ParameterMetadataRoot();
    }
}
