using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Telegram.Bot;
using DetectorBotV2.Services;
using DetectorBotV2.Handlers;

var config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var botToken = config["BotToken"]
    ?? config["TELEGRAM_BOT_TOKEN"]
    ?? throw new InvalidOperationException("Token topilmadi!");

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((_, services) =>
    {
        services.AddSingleton<ITelegramBotClient>(new TelegramBotClient(botToken));
        services.AddSingleton<FileAnalysisService>();
        services.AddSingleton<UrlAnalysisService>();
        services.AddSingleton<DatabaseService>();
        services.AddSingleton<MessageHandler>();
        services.AddHostedService<BotHostedService>();
    })
    .Build();

await host.RunAsync();
