using System.Text.Json.Serialization;

namespace NativeSecrets.Fallback;

[JsonSerializable(typeof(VaultFile))]
internal partial class VaultJsonContext : JsonSerializerContext;