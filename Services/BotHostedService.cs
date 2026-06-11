using Microsoft.Extensions.Hosting;
using Telegram.Bot;
using Telegram.Bot.Polling;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using FraudDetectorBot.Handlers;

namespace FraudDetectorBot.Services;

public class BotHostedService : BackgroundService
{
    private readonly ITelegramBotClient _bot;
    private readonly MessageHandler _messageHandler;

    public BotHostedService(ITelegramBotClient bot, MessageHandler messageHandler)
    {
        _bot = bot;
        _messageHandler = messageHandler;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var me = await _bot.GetMe(stoppingToken);
        Console.WriteLine($"✅ Bot ishga tushdi: @{me.Username}");
        Console.WriteLine($"🛡️ Firibgarlikni Aniqlash Boti tayyor!");

        var receiverOptions = new ReceiverOptions
        {
            AllowedUpdates = new[] { UpdateType.Message, UpdateType.CallbackQuery },
            DropPendingUpdates = true
        };

_bot.StartReceiving(
    HandleUpdateAsync,
    HandleErrorAsync,
    receiverOptions,
    stoppingToken
);

        await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private async Task HandleUpdateAsync(ITelegramBotClient bot, Update update, CancellationToken ct)
    {
        await _messageHandler.HandleUpdateAsync(update, ct);
    }

    private Task HandleErrorAsync(ITelegramBotClient bot, Exception exception, CancellationToken ct)
    {
        Console.WriteLine($"❌ Telegram API xatosi: {exception.Message}");
        return Task.CompletedTask;
    }
}
