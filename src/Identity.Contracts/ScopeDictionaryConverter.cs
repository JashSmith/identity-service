using System.Text.Json;
using System.Text.Json.Serialization;

namespace Identity.Contracts;

/// <summary>
/// Accepts both "key": "single" and "key": ["a","b"] and normalizes to IReadOnlyCollection&lt;string&gt;.
/// Always writes as array.
/// </summary>
public sealed class ScopeDictionaryConverter : JsonConverter<IReadOnlyDictionary<string, IReadOnlyCollection<string>>>
{
    public override IReadOnlyDictionary<string, IReadOnlyCollection<string>> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null) return new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        if (reader.TokenType != JsonTokenType.StartObject) throw new JsonException("Scopes must be an object.");
        var dict = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject) break;
            if (reader.TokenType != JsonTokenType.PropertyName) throw new JsonException("Expected property name.");
            var key = reader.GetString() ?? string.Empty;
            reader.Read();
            IReadOnlyCollection<string> values;
            if (reader.TokenType == JsonTokenType.String)
            {
                var s = reader.GetString();
                values = string.IsNullOrWhiteSpace(s) ? Array.Empty<string>() : new[] { s!.Trim() };
            }
            else if (reader.TokenType == JsonTokenType.StartArray)
            {
                var list = new List<string>();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        var s = reader.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) list.Add(s!.Trim());
                    }
                    else if (reader.TokenType == JsonTokenType.Null) { }
                    else throw new JsonException($"Scope values must be strings. Path: {key}");
                }
                values = list.Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToArray();
            }
            else if (reader.TokenType == JsonTokenType.Null)
            {
                values = Array.Empty<string>();
            }
            else throw new JsonException($"Scope values must be a string or array of strings. Path: {key}");

            var trimmedKey = key.Trim();
            if (!string.IsNullOrWhiteSpace(trimmedKey))
                dict[trimmedKey] = values;
        }
        return dict;
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyDictionary<string, IReadOnlyCollection<string>> value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        foreach (var kv in value.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            writer.WritePropertyName(kv.Key);
            writer.WriteStartArray();
            foreach (var v in kv.Value) writer.WriteStringValue(v);
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
}
