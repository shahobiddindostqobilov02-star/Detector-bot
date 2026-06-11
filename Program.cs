using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Telegram.Bot;
using FraudDetectorBot.Services;
using FraudDetectorBot.Handlers;
using Microsoft.Extensions.Configuration;

var config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var botToken = config["BotToken"]
    ?? throw new InvalidOperationException("Token topilmadi!");

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((context, services) =>
    {
        services.AddSingleton<ITelegramBotClient>(new TelegramBotClient(botToken));
        services.AddSingleton<FileAnalysisService>();
        services.AddSingleton<VirusTotalService>();
        services.AddSingleton<ReportService>();
        services.AddHostedService<BotHostedService>();
        services.AddSingleton<MessageHandler>();
    })
    .Build();

await host.RunAsync();