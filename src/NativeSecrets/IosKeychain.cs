#if IOS || __IOS__ || MACCATALYST || __MACCATALYST__
using Foundation;
using Security;

namespace NativeSecrets;

internal sealed class IosKeychain : IKeychainStore
{
    private static string BuildService(string package, string service) => $"{package}/{service}";

    public bool IsAvailable()
    {
        try
        {
            using var query = new SecRecord(SecKind.GenericPassword)
            {
                Service = "__vault_probe__",
                Account = "__probe__"
            };
            var match = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
            match?.Dispose();
            return code == SecStatusCode.Success || code == SecStatusCode.ItemNotFound;
        }
        catch
        {
            return false;
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        string svc = BuildService(package, service);
        using var query = new SecRecord(SecKind.GenericPassword)
        {
            Service = svc,
            Account = user
        };

        var existing = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
        if (code == SecStatusCode.Success && existing != null)
        {
            existing.ValueData = NSData.FromString(password);
            var status = SecKeyChain.Update(query, existing);
            existing.Dispose();
            if (status != SecStatusCode.Success)
                throw new InvalidOperationException($"SecItemUpdate failed: {status}");
            return;
        }

        using var record = new SecRecord(SecKind.GenericPassword)
        {
            Service = svc,
            Account = user,
            ValueData = NSData.FromString(password),
            Accessible = SecAccessible.AfterFirstUnlock
        };
        var addStatus = SecKeyChain.Add(record);
        if (addStatus != SecStatusCode.Success)
            throw new InvalidOperationException($"SecItemAdd failed: {addStatus}");
    }

    public string? GetPassword(string package, string service, string user)
    {
        using var query = new SecRecord(SecKind.GenericPassword)
        {
            Service = BuildService(package, service),
            Account = user
        };

        using var match = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
        if (code != SecStatusCode.Success || match?.ValueData == null)
            return null;

        using var decoded = NSString.FromData(match.ValueData, NSStringEncoding.UTF8);
        return decoded?.ToString();
    }


    // public string? GetPassword(string package, string service, string user)
    // {
    //     using var query = new SecRecord(SecKind.GenericPassword)
    //     {
    //         Service = BuildService(package, service),
    //         Account = user
    //     };
    //
    //     var match = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
    //     if (code == SecStatusCode.ItemNotFound) return null;
    //     if (code != SecStatusCode.Success || match == null) return null;
    //
    //     try
    //     {
    //         return match.ValueData?.ToString();
    //     }
    //     finally
    //     {
    //         match.Dispose();
    //     }
    // }

    public bool DeletePassword(string package, string service, string user)
    {
        using var query = new SecRecord(SecKind.GenericPassword)
        {
            Service = BuildService(package, service),
            Account = user
        };
        var status = SecKeyChain.Remove(query);
        return status == SecStatusCode.Success || status == SecStatusCode.ItemNotFound;
    }
}
#endif
