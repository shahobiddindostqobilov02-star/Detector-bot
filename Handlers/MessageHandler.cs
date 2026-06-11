using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;
using DetectorBotV2.Models;
using DetectorBotV2.Services;

namespace DetectorBotV2.Handlers;

public class MessageHandler
{
    private readonly ITelegramBotClient _bot;
    private readonly FileAnalysisService _fileService;
    private readonly UrlAnalysisService _urlService;
    private readonly DatabaseService _db;

    // Admin ID lar
    private static readonly HashSet<long> AdminIds = new()
    {
        8067524302, // Admin
    };

    public MessageHandler(
        ITelegramBotClient bot,
        FileAnalysisService fileService,
        UrlAnalysisService urlService,
        DatabaseService db)
    {
        _bot = bot;
        _fileService = fileService;
        _urlService = urlService;
        _db = db;
    }

    public async Task HandleUpdateAsync(Update update, CancellationToken ct)
    {
        try
        {
            if (update.Type == UpdateType.Message && update.Message != null)
                await HandleMessageAsync(update.Message, ct);
            else if (update.Type == UpdateType.CallbackQuery && update.CallbackQuery != null)
                await HandleCallbackAsync(update.CallbackQuery, ct);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Xato: {ex.Message}");
        }
    }

    private async Task HandleMessageAsync(Message msg, CancellationToken ct)
    {
        var chatId = msg.Chat.Id;
        var userId = msg.From?.Id ?? 0;
        var username = msg.From?.Username ?? "";
        var firstName = msg.From?.FirstName ?? "Foydalanuvchi";

        // Foydalanuvchini ro'yxatga olish
        _db.GetOrCreateUser(userId, username, firstName);

        // Ban tekshirish
        if (_db.IsUserBanned(userId) && !AdminIds.Contains(userId))
        {
            await _bot.SendMessage(chatId, "🚫 Siz botdan bloklangansiz.", cancellationToken: ct);
            return;
        }

        // Matn xabarlar
        if (msg.Type == MessageType.Text && msg.Text != null)
        {
            var text = msg.Text.Trim();

            // Buyruqlar
            if (text.StartsWith("/start")) { await SendMainMenu(chatId, firstName, ct); return; }
            if (text.StartsWith("/help")) { await SendHelp(chatId, ct); return; }
            if (text.StartsWith("/stats")) { await SendUserStats(chatId, userId, ct); return; }
            if (text.StartsWith("/menu")) { await SendMainMenu(chatId, firstName, ct); return; }

            // Admin buyruqlari
            if (AdminIds.Contains(userId))
            {
                if (text.StartsWith("/admin")) { await SendAdminPanel(chatId, ct); return; }
                if (text.StartsWith("/ban "))
                {
                    var banId = long.TryParse(text[5..].Trim(), out var id) ? id : 0;
                    await BanUserCmd(chatId, banId, ct);
                    return;
                }
                if (text.StartsWith("/unban "))
                {
                    var unbanId = long.TryParse(text[7..].Trim(), out var id) ? id : 0;
                    await UnbanUserCmd(chatId, unbanId, ct);
                    return;
                }
                if (text.StartsWith("/broadcast "))
                {
                    await BroadcastCmd(chatId, text[11..], ct);
                    return;
                }
            }

            // URL tekshirish
            if (text.StartsWith("http://") || text.StartsWith("https://") ||
                text.StartsWith("www.") || (text.Contains(".") && text.Contains("/") && !text.StartsWith("/")))
            {
                await AnalyzeUrlAsync(chatId, userId, username, firstName, text, ct);
                return;
            }

            // Telegram username
            if (text.StartsWith("@") && text.Length > 3)
            {
                await AnalyzeUsernameAsync(chatId, userId, username, firstName, text, ct);
                return;
            }

            // Telefon raqam
            if (Regex.IsMatch(text, @"^[\+\d\s\-\(\)]{7,15}$"))
            {
                await AnalyzePhoneAsync(chatId, userId, username, firstName, text, ct);
                return;
            }

            // Boshqa matn
            await _bot.SendMessage(chatId,
                "📋 Menga quyidagilarni yuboring:\n\n"
                + "📎 *Fayl* — virus tekshirish\n"
                + "🔗 *Link* — URL tekshirish\n"
                + "👤 *@username* — Telegram akkaunt\n"
                + "📞 *Telefon raqam* — operator tekshirish\n\n"
                + "Yoki /menu bosing",
                parseMode: ParseMode.Markdown,
                cancellationToken: ct);
            return;
        }

        // Fayl tekshirish
        string? fileId = null;
        string? fileName = null;
        long fileSize = 0;

        if (msg.Type == MessageType.Document && msg.Document != null)
        {
            fileId = msg.Document.FileId;
            fileName = msg.Document.FileName ?? "nomsiz";
            fileSize = msg.Document.FileSize ?? 0;
        }

        if (fileId != null && fileName != null)
            await AnalyzeFileAsync(chatId, userId, username, firstName, fileId, fileName, fileSize, ct);
    }

    // ==================== FAYL TAHLIL ====================
    private async Task AnalyzeFileAsync(long chatId, long userId, string username, string firstName,
        string fileId, string fileName, long fileSize, CancellationToken ct)
    {
        if (fileSize > 50 * 1024 * 1024)
        {
            await _bot.SendMessage(chatId, "❌ Fayl 50MB dan katta, qabul qilinmadi.", cancellationToken: ct);
            return;
        }

        var wait = await _bot.SendMessage(chatId, "⏳ *Fayl tahlil qilinmoqda...*",
            parseMode: ParseMode.Markdown, cancellationToken: ct);

        try
        {
            byte[] bytes;
            using var stream = new MemoryStream();
            var tgFile = await _bot.GetFile(fileId, ct);
            await _bot.DownloadFile(tgFile.FilePath!, stream, ct);
            bytes = stream.ToArray();

            var result = await _fileService.AnalyzeFileAsync(fileName, bytes);
            _db.RecordScan(userId, username, firstName, fileName, "FILE", result.RiskLevel);

            await _bot.DeleteMessage(chatId, wait.MessageId, ct);
            await SendAnalysisResult(chatId, result, ct);
        }
        catch (Exception ex)
        {
            await _bot.EditMessageText(chatId, wait.MessageId, $"❌ Xatolik: {ex.Message}", cancellationToken: ct);
        }
    }

    // ==================== URL TAHLIL ====================
    private async Task AnalyzeUrlAsync(long chatId, long userId, string username, string firstName,
        string url, CancellationToken ct)
    {
        var wait = await _bot.SendMessage(chatId, "⏳ *Link tekshirilmoqda...*",
            parseMode: ParseMode.Markdown, cancellationToken: ct);

        var result = _urlService.AnalyzeUrl(url);
        _db.RecordScan(userId, username, firstName, url, "URL", result.RiskLevel);

        await _bot.DeleteMessage(chatId, wait.MessageId, ct);
        await SendAnalysisResult(chatId, result, ct);
    }

    // ==================== USERNAME TAHLIL ====================
    private async Task AnalyzeUsernameAsync(long chatId, long userId, string username, string firstName,
        string target, CancellationToken ct)
    {
        var result = _urlService.AnalyzeUsername(target);
        _db.RecordScan(userId, username, firstName, target, "USERNAME", result.RiskLevel);
        await SendAnalysisResult(chatId, result, ct);
    }

    // ==================== TELEFON TAHLIL ====================
    private async Task AnalyzePhoneAsync(long chatId, long userId, string username, string firstName,
        string phone, CancellationToken ct)
    {
        var result = _urlService.AnalyzePhone(phone);
        _db.RecordScan(userId, username, firstName, phone, "PHONE", result.RiskLevel);
        await SendAnalysisResult(chatId, result, ct);
    }

    // ==================== NATIJA YUBORISH ====================
    private async Task SendAnalysisResult(long chatId, AnalysisResult result, CancellationToken ct)
    {
        var (emoji, text) = result.RiskLevel switch
        {
            RiskLevel.Safe => ("🟢", "XAVFSIZ"),
            RiskLevel.Low => ("🟡", "PAST XAVF"),
            RiskLevel.Medium => ("🟠", "O'RTA XAVF"),
            RiskLevel.High => ("🔴", "YUQORI XAVF"),
            RiskLevel.Critical => ("☠️", "JUDA XAVFLI"),
            _ => ("❓", "NOMA'LUM")
        };

        var typeEmoji = result.Type switch
        {
            "FILE" => "📄",
            "URL" => "🔗",
            "USERNAME" => "👤",
            "PHONE" => "📞",
            _ => "❓"
        };

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"{emoji} *{text}* {emoji}");
        sb.AppendLine($"{typeEmoji} `{TruncateText(result.Target, 40)}`");
        sb.AppendLine();

        if (result.Threats.Any())
        {
            sb.AppendLine("🚨 *Tahdidlar:*");
            foreach (var t in result.Threats.Take(4)) sb.AppendLine(t);
            sb.AppendLine();
        }

        if (result.Warnings.Any())
        {
            sb.AppendLine("⚠️ *Ogohlantirishlar:*");
            foreach (var w in result.Warnings.Take(3)) sb.AppendLine(w);
            sb.AppendLine();
        }

        if (result.SafePoints.Any() && result.RiskLevel <= RiskLevel.Low)
        {
            sb.AppendLine("✅ *Xavfsiz belgilar:*");
            foreach (var s in result.SafePoints.Take(2)) sb.AppendLine(s);
            sb.AppendLine();
        }

        sb.AppendLine("━━━━━━━━━━━━━━");
        sb.AppendLine($"💡 {result.Recommendation}");

        var keyboard = new InlineKeyboardMarkup(new[]
        {
            new[]
            {
                InlineKeyboardButton.WithCallbackData("🛡️ Maslahatlar", "tips"),
                InlineKeyboardButton.WithCallbackData("📢 Xabar berish", "report")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData("🏠 Bosh menyu", "mainmenu")
            }
        });

        await _bot.SendMessage(chatId, sb.ToString(),
            parseMode: ParseMode.Markdown, replyMarkup: keyboard, cancellationToken: ct);
    }

    // ==================== MENYULAR ====================
    private async Task SendMainMenu(long chatId, string name, CancellationToken ct)
    {
        var text = $"""
        👋 Salom, *{name}*!
        🛡️ *Firibgarlikni Aniqlash Boti*

        Menga quyidagilarni yuboring:
        """;

        var keyboard = new InlineKeyboardMarkup(new[]
        {
            new[]
            {
                InlineKeyboardButton.WithCallbackData("📎 Fayl tekshirish", "how_file"),
                InlineKeyboardButton.WithCallbackData("🔗 Link tekshirish", "how_url")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData("👤 Username tekshirish", "how_user"),
                InlineKeyboardButton.WithCallbackData("📞 Telefon tekshirish", "how_phone")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData("📊 Statistikam", "mystats"),
                InlineKeyboardButton.WithCallbackData("🛡️ Maslahatlar", "tips")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData("ℹ️ Bot haqida", "about")
            }
        });

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown,
            replyMarkup: keyboard, cancellationToken: ct);
    }

    private async Task SendHelp(long chatId, CancellationToken ct)
    {
        var text = """
        📖 *Yordam:*

        *Fayl tekshirish:*
        Faylni bevosita botga yuboring (dokument sifatida)

        *Link tekshirish:*
        URL manzilni yuboring:
        `https://example.com`

        *Username tekshirish:*
        `@username` yuboring

        *Telefon tekshirish:*
        `+998901234567` yuboring

        *Buyruqlar:*
        /start — Bosh menyu
        /stats — Statistikam
        /help — Yordam
        """;

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendUserStats(long chatId, long userId, CancellationToken ct)
    {
        var text = _db.GetUserStatsText(userId);
        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    // ==================== ADMIN PANEL ====================
    private async Task SendAdminPanel(long chatId, CancellationToken ct)
    {
        var stats = _db.GetGlobalStats();
        var text = $"""
        🔐 *ADMIN PANEL*

        👥 Jami foydalanuvchilar: *{stats.TotalUsers}*
        🔍 Jami tekshirishlar: *{stats.TotalScans}*
        🚨 Tahdidlar aniqlandi: *{stats.TotalThreats}*
        📅 Bugun faol: *{stats.ActiveToday}* ta user
        """;

        var keyboard = new InlineKeyboardMarkup(new[]
        {
            new[]
            {
                InlineKeyboardButton.WithCallbackData("👥 Foydalanuvchilar", "admin_users"),
                InlineKeyboardButton.WithCallbackData("📊 Batafsil stat", "admin_stats")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData("🚨 Oxirgi tahdidlar", "admin_threats"),
                InlineKeyboardButton.WithCallbackData("🏆 Top userlar", "admin_top")
            },
            new[]
            {
                InlineKeyboardButton.WithCallbackData("📢 Xabar yuborish", "admin_broadcast"),
            }
        });

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown,
            replyMarkup: keyboard, cancellationToken: ct);
    }

    private async Task BanUserCmd(long chatId, long targetId, CancellationToken ct)
    {
        if (targetId == 0) { await _bot.SendMessage(chatId, "❌ ID noto'g'ri. `/ban 123456789`", parseMode: ParseMode.Markdown, cancellationToken: ct); return; }
        var success = _db.BanUser(targetId);
        await _bot.SendMessage(chatId, success ? $"✅ User {targetId} bloklandi." : "❌ User topilmadi.", cancellationToken: ct);
    }

    private async Task UnbanUserCmd(long chatId, long targetId, CancellationToken ct)
    {
        if (targetId == 0) { await _bot.SendMessage(chatId, "❌ ID noto'g'ri.", cancellationToken: ct); return; }
        var success = _db.UnbanUser(targetId);
        await _bot.SendMessage(chatId, success ? $"✅ User {targetId} blokdan chiqarildi." : "❌ User topilmadi.", cancellationToken: ct);
    }

    private async Task BroadcastCmd(long chatId, string message, CancellationToken ct)
    {
        var users = _db.GetAllUsers();
        var sent = 0;
        foreach (var user in users)
        {
            try
            {
                await _bot.SendMessage(user.UserId, $"📢 *Xabar:*\n\n{message}",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                sent++;
                await Task.Delay(50, ct);
            }
            catch { }
        }
        await _bot.SendMessage(chatId, $"✅ Xabar {sent}/{users.Count} foydalanuvchiga yuborildi.", cancellationToken: ct);
    }

    // ==================== CALLBACK ====================
    private async Task HandleCallbackAsync(CallbackQuery cb, CancellationToken ct)
    {
        var chatId = cb.Message?.Chat.Id ?? 0;
        var userId = cb.From.Id;
        var data = cb.Data ?? "";

        await _bot.AnswerCallbackQuery(cb.Id, cancellationToken: ct);

        switch (data)
        {
            case "mainmenu":
                await SendMainMenu(chatId, cb.From.FirstName, ct);
                break;

            case "mystats":
                await SendUserStats(chatId, userId, ct);
                break;

            case "tips":
                await _bot.SendMessage(chatId, GetSafetyTips(), parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "about":
                await _bot.SendMessage(chatId, GetAboutText(), parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "report":
                await _bot.SendMessage(chatId,
                    "📢 *Firibgarlikni qayerga xabar berish:*\n\n"
                    + "🇺🇿 Kiberjinoyatlar: *1102*\n"
                    + "📧 Telegram: @notoscam\n"
                    + "🌐 VirusTotal: https://virustotal.com",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "how_file":
                await _bot.SendMessage(chatId,
                    "📎 *Fayl tekshirish:*\n\nFaylni menga *Dokument* sifatida yuboring.\n_(Attach → File)_\n\nMax hajm: 50MB",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "how_url":
                await _bot.SendMessage(chatId,
                    "🔗 *Link tekshirish:*\n\nLink/URL manzilni yuboring:\n`https://example.com`\n`www.example.com`",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "how_user":
                await _bot.SendMessage(chatId,
                    "👤 *Username tekshirish:*\n\n@username ko'rinishida yuboring:\n`@uzcard_official`",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "how_phone":
                await _bot.SendMessage(chatId,
                    "📞 *Telefon tekshirish:*\n\nRaqamni yuboring:\n`+998901234567`\n`998901234567`",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            // Admin callbacklar
            case "admin_stats" when AdminIds.Contains(userId):
                await SendDetailedStats(chatId, ct);
                break;

            case "admin_users" when AdminIds.Contains(userId):
                await SendUsersList(chatId, ct);
                break;

            case "admin_threats" when AdminIds.Contains(userId):
                var threats = _db.GetRecentThreats(10);
                var threatText = threats.Any()
                    ? "🚨 *Oxirgi tahdidlar:*\n\n" + string.Join("\n", threats)
                    : "✅ Tahdid topilmadi.";
                await _bot.SendMessage(chatId, threatText, parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;

            case "admin_top" when AdminIds.Contains(userId):
                await SendTopUsers(chatId, ct);
                break;

            case "admin_broadcast" when AdminIds.Contains(userId):
                await _bot.SendMessage(chatId,
                    "📢 Xabar yuborish uchun:\n`/broadcast Xabar matni`",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
                break;
        }
    }

    private async Task SendDetailedStats(long chatId, CancellationToken ct)
    {
        var stats = _db.GetGlobalStats();
        var users = _db.GetAllUsers();
        var banned = users.Count(u => u.IsBanned);

        var text = $"""
        📊 *Batafsil statistika:*

        👥 Jami userlar: *{stats.TotalUsers}*
        🚫 Bloklangan: *{banned}*
        🔍 Jami tekshirishlar: *{stats.TotalScans}*
        🚨 Tahdidlar: *{stats.TotalThreats}*
        📅 Bugun faol: *{stats.ActiveToday}*
        """;

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendUsersList(long chatId, CancellationToken ct)
    {
        var users = _db.GetAllUsers().OrderByDescending(u => u.LastActivity).Take(10).ToList();
        var sb = new System.Text.StringBuilder("👥 *Oxirgi faol foydalanuvchilar:*\n\n");

        foreach (var u in users)
        {
            var status = u.IsBanned ? "🚫" : "✅";
            sb.AppendLine($"{status} `{u.UserId}` @{u.Username} — {u.TotalScans} ta scan");
        }

        sb.AppendLine($"\n*Ban uchun:* `/ban USER_ID`");
        await _bot.SendMessage(chatId, sb.ToString(), parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendTopUsers(long chatId, CancellationToken ct)
    {
        var top = _db.GetTopUsers(10);
        var sb = new System.Text.StringBuilder("🏆 *Top foydalanuvchilar:*\n\n");
        var i = 1;
        foreach (var u in top)
            sb.AppendLine($"{i++}. @{u.Username} — {u.TotalScans} ta scan ({u.ThreatsFound} tahdid)");

        await _bot.SendMessage(chatId, sb.ToString(), parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private static string GetSafetyTips() => """
        🛡️ *Xavfsizlik maslahatlar:*

        📱 *APK fayllar:*
        • Faqat Google Play Store dan yuklab oling
        • Noma'lum APK larga ishonmang

        🔗 *Linklar:*
        • HTTPS li linklar xavfsizroq
        • Qisqa linklar (bit.ly) ga ehtiyot bo'ling
        • Bank saytlarini qo'lda kiriting

        💬 *Telegram:*
        • Rasmiy kanallar ✅ belgisiga ega
        • SMS kod so'ragan botlarga ishonmang
        • @username ni tekshiring

        🏦 *Bank va to'lovlar:*
        • PIN va parolni hech kimga bermang
        • SMS kodni hech kim so'ramaydi
        • Shubhali bo'lsa — bankga qo'ng'iring
        """;

    private static string GetAboutText() => """
        🤖 *Bot haqida:*

        *Firibgarlikni Aniqlash Boti v2.0*

        *Tekshirish imkoniyatlari:*
        📎 Fayl — 40+ xavfli kengaytma
        🔗 URL — phishing aniqlash
        👤 Username — soxta akkaunt
        📞 Telefon — operator tekshirish

        *Texnologiyalar:*
        • C# / .NET 9
        • Telegram.Bot 22.0
        • SHA-256 kriptografiya

        ⚠️ Bot 100% kafolat bera olmaydi!
        """;

    private static string TruncateText(string text, int max) =>
        text.Length > max ? text[..max] + "..." : text;
}

// Regex namespace
using System.Text.RegularExpressions;
