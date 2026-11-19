#if IOS || __IOS__ || MACCATALYST || __MACCATALYST__
using Foundation;
using Security;
using NativeSecrets.Abstractions;
using NativeSecrets.Internal;

namespace NativeSecrets.Platforms;

internal sealed class IosKeychain : IKeychainStore
{
    public bool IsAvailable()
    {
        try
        {
            const string probePkg = "__nativesecrets_probe__";
            const string probeSvc = "__probe__";
            const string probeUsr = "__probe__";
            const string probeVal = "probe_ok";

            SetPassword(probePkg, probeSvc, probeUsr, probeVal);
            var roundtrip = GetPassword(probePkg, probeSvc, probeUsr);
            DeletePassword(probePkg, probeSvc, probeUsr);

            return roundtrip == probeVal;
        }
        catch
        {
            return false;
        }
    }

    public void SetPassword(string package, string service, string user, string password)
    {
        string svc = KeyBuilder.BuildService(package, service);
        using var query = new SecRecord(SecKind.GenericPassword)
        {
            Service = svc,
            Account = user
        };

        using var passwordData = NSData.FromString(password, NSStringEncoding.UTF8)
            ?? throw new InvalidOperationException("Failed to encode password as UTF-8.");

        using var existing = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
        if (code == SecStatusCode.Success && existing != null)
        {
            existing.ValueData = passwordData;
            var status = SecKeyChain.Update(query, existing);
            if (status != SecStatusCode.Success)
                throw new InvalidOperationException($"SecItemUpdate failed: {status}");
            return;
        }

        using var record = new SecRecord(SecKind.GenericPassword)
        {
            Service = svc,
            Account = user,
            ValueData = passwordData,
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
            Service = KeyBuilder.BuildService(package, service),
            Account = user
        };

        using var match = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
        if (code != SecStatusCode.Success || match?.ValueData == null)
            return null;

        using var decoded = NSString.FromData(match.ValueData, NSStringEncoding.UTF8);
        return decoded?.ToString();
    }

    public bool DeletePassword(string package, string service, string user)
    {
        using var query = new SecRecord(SecKind.GenericPassword)
        {
            Service = KeyBuilder.BuildService(package, service),
            Account = user
        };
        var status = SecKeyChain.Remove(query);
        return status == SecStatusCode.Success || status == SecStatusCode.ItemNotFound;
    }
}
#endif

// namespace NativeSecrets.Platforms;
// #if IOS || __IOS__ || MACCATALYST || __MACCATALYST__
// using Foundation;
// using Security;
//
// namespace NativeSecrets;
//
// internal sealed class IosKeychain : IKeychainStore
// {
//     private static string BuildService(string package, string service) => $"{package}/{service}";
//
//     public bool IsAvailable()
//     {
//         try
//         {
//             const string probePkg = "__nativesecrets_probe__";
//             const string probeSvc = "__probe__";
//             const string probeUsr = "__probe__";
//             const string probeVal = "probe_ok";
//
//             SetPassword(probePkg, probeSvc, probeUsr, probeVal);
//             var roundtrip = GetPassword(probePkg, probeSvc, probeUsr);
//             DeletePassword(probePkg, probeSvc, probeUsr);
//
//             return roundtrip == probeVal;
//         }
//         catch
//         {
//             return false;
//         }
//     }
//
//     public void SetPassword(string package, string service, string user, string password)
//     {
//         string svc = BuildService(package, service);
//         using var query = new SecRecord(SecKind.GenericPassword)
//         {
//             Service = svc,
//             Account = user
//         };
//
//         using var passwordData = NSData.FromString(password, NSStringEncoding.UTF8)
//             ?? throw new InvalidOperationException("Failed to encode password as UTF-8.");
//
//         using var existing = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
//         if (code == SecStatusCode.Success && existing != null)
//         {
//             existing.ValueData = passwordData;
//             var status = SecKeyChain.Update(query, existing);
//             if (status != SecStatusCode.Success)
//                 throw new InvalidOperationException($"SecItemUpdate failed: {status}");
//             return;
//         }
//
//         using var record = new SecRecord(SecKind.GenericPassword)
//         {
//             Service = svc,
//             Account = user,
//             ValueData = passwordData,
//             Accessible = SecAccessible.AfterFirstUnlock
//         };
//         var addStatus = SecKeyChain.Add(record);
//         if (addStatus != SecStatusCode.Success)
//             throw new InvalidOperationException($"SecItemAdd failed: {addStatus}");
//     }
//
//     public string? GetPassword(string package, string service, string user)
//     {
//         using var query = new SecRecord(SecKind.GenericPassword)
//         {
//             Service = BuildService(package, service),
//             Account = user
//         };
//
//         using var match = SecKeyChain.QueryAsRecord(query, out SecStatusCode code);
//         if (code != SecStatusCode.Success || match?.ValueData == null)
//             return null;
//
//         using var decoded = NSString.FromData(match.ValueData, NSStringEncoding.UTF8);
//         return decoded?.ToString();
//     }
//
//     public bool DeletePassword(string package, string service, string user)
//     {
//         using var query = new SecRecord(SecKind.GenericPassword)
//         {
//             Service = BuildService(package, service),
//             Account = user
//         };
//         var status = SecKeyChain.Remove(query);
//         return status == SecStatusCode.Success || status == SecStatusCode.ItemNotFound;
//     }
// }
// #endif