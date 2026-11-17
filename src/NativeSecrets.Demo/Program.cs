using NativeSecrets;

var secrets = NativeSecretsBase.Create();

// Синхронно
secrets.SetSecret("MyApp", "api_user", "super_secret_token");
var token = secrets.GetSecret("MyApp", "api_user");
Console.WriteLine(token);

secrets.DeleteSecret("MyApp", "api_user");
var tokenDel = secrets.GetSecret("MyApp", "api_user");
Console.WriteLine(tokenDel);



Console.ReadKey();
