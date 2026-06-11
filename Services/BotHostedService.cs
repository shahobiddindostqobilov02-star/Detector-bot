using Microsoft.Extensions.Hosting;
using Telegram.Bot;
using Telegram.Bot.Polling;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using DetectorBotV2.Handlers;

namespace DetectorBotV2.Services;

public class BotHostedService : BackgroundService
{
    private readonly ITelegramBotClient _bot;
    private readonly MessageHandler _handler;

    public BotHostedService(ITelegramBotClient bot, MessageHandler handler)
    {
        _bot = bot;
        _handler = handler;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var me = await _bot.GetMe(ct);
        Console.WriteLine($"✅ Bot ishga tushdi: @{me.Username}");
        Console.WriteLine($"🛡️ Firibgarlikni Aniqlash Boti v2.0 tayyor!");

        _bot.StartReceiving(
            (bot, update, ct) => _handler.HandleUpdateAsync(update, ct),
            (bot, ex, ct) => { Console.WriteLine($"❌ Xato: {ex.Message}"); return Task.CompletedTask; },
            new ReceiverOptions
            {
                AllowedUpdates = new[] { UpdateType.Message, UpdateType.CallbackQuery },
                DropPendingUpdates = true
            },
            ct
        );

        await Task.Delay(Timeout.Infinite, ct);
    }
}
