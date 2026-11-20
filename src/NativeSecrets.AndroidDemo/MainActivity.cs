using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;
using NativeSecrets.Core;

namespace NativeSecrets.AndroidDemo;

[Activity(Label = "@string/app_name", MainLauncher = true)]
public class MainActivity : Activity
{
    private const string Pkg = "org.nativesecrets.demo";
    private const string Svc = "persist-test";
    private const string Usr = "djacobi";
    private const string SecretValue = "Saved_Across_Restarts_2026!";

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        var layout = new LinearLayout(this)
        {
            Orientation = Orientation.Vertical
        };
        layout.SetPadding(48, 200, 48, 48);

        var statusView = new TextView(this) { TextSize = 18f };
        var resetButton = new Button(this) { Text = "Удалить секрет (сбросить тест)" };

        layout.AddView(statusView);
        layout.AddView(resetButton);
        SetContentView(layout);

        try
        {
            var store = KeychainFactory.Instance;
            var isFallback = KeychainFactory.IsUsingFallback;

            resetButton.Click += (_, _) =>
            {
                var deleted = store.DeletePassword(Pkg, Svc, Usr);
                statusView.Text = $"Fallback: {isFallback}\nСекрет удалён: {deleted}.\nПерезапусти приложение для нового теста.";
            };

            var existing = store.GetPassword(Pkg, Svc, Usr);

            if (existing == null)
            {
                store.SetPassword(Pkg, Svc, Usr, SecretValue);
                string msg = $"Fallback: {isFallback}\n\nШАГ 1: Пароль сохранён!\nЗакрой приложение (смахни из недавних) и запусти снова.";
                Log.Info("NativeSecrets", msg);
                statusView.Text = msg;
            }
            else if (existing == SecretValue)
            {
                string msg = $"Fallback: {isFallback}\n\nШАГ 2 (УСПЕХ): Пароль прочитан после перезапуска!\nЗначение: {existing}";
                Log.Info("NativeSecrets", msg);
                statusView.Text = msg;
            }
            else
            {
                statusView.Text = $"ОШИБКА: Ожидалось '{SecretValue}', получено '{existing}'";
            }
        }
        catch (Exception ex)
        {
            Log.Error("NativeSecrets", ex.ToString());
            statusView.TextSize = 13f;
            statusView.Text = $"ERROR:\n{ex}";
        }
    }
}
