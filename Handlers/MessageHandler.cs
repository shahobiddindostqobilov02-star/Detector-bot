using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;
using FraudDetectorBot.Models;
using FraudDetectorBot.Services;

namespace FraudDetectorBot.Handlers;

public class MessageHandler
{
    // ==========================================
// ADMIN ID LAR - @userinfobot dan oling
// ==========================================
private static readonly HashSet<long> AdminIds = new()
{
    8067524302,   // Sizning Telegram ID ingiz
};
    private readonly ITelegramBotClient _bot;
    private readonly FileAnalysisService _analysisService;
    private readonly VirusTotalService _virusTotalService;
    private readonly ReportService _reportService;

    // Faylni yuklab olishning maksimal hajmi (50MB)
    private const long MaxFileSize = 50 * 1024 * 1024;

    public MessageHandler(
        ITelegramBotClient bot,
        FileAnalysisService analysisService,
        VirusTotalService virusTotalService,
        ReportService reportService)
    {
        _bot = bot;
        _analysisService = analysisService;
        _virusTotalService = virusTotalService;
        _reportService = reportService;
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
            Console.WriteLine($"Handler xatosi: {ex.Message}");
        }
    }

    private async Task HandleMessageAsync(Message message, CancellationToken ct)
    {
        var chatId = message.Chat.Id;
        var userId = message.From?.Id ?? 0;
        var username = message.From?.Username ?? message.From?.FirstName ?? "Foydalanuvchi";

        // Buyruqlar
        if (message.Type == MessageType.Text && message.Text != null)
        {
            var text = message.Text.Trim();

            if (text.StartsWith("/start"))
                await SendWelcomeAsync(chatId, username, ct);
            else if (text.StartsWith("/help"))
                await SendHelpAsync(chatId, ct);
            else if (text.StartsWith("/stats"))
                await SendUserStatsAsync(chatId, userId, username, ct);
            else if (text.StartsWith("/globalstats"))
{
    if (!AdminIds.Contains(userId))
    {
        await _bot.SendMessage(chatId, "❌ Bu buyruq faqat adminlar uchun!", cancellationToken: ct);
        return;
    }
    await SendGlobalStatsAsync(chatId, ct);
}
            else if (text.StartsWith("/threats"))
                await SendRecentThreatsAsync(chatId, ct);
            else if (text.StartsWith("/about"))
                await SendAboutAsync(chatId, ct);
            else
                await _bot.SendMessage(chatId,
                    "📎 Faylni menga yuboring, men uni tekshirib beraman.\n"
                    + "❓ Yordam uchun: /help",
                    cancellationToken: ct);
            return;
        }

        // Fayl qabul qilish
        string? fileId = null;
        string? fileName = null;
        long fileSize = 0;

        if (message.Type == MessageType.Document && message.Document != null)
        {
            fileId = message.Document.FileId;
            fileName = message.Document.FileName ?? "nomsiz_fayl";
            fileSize = message.Document.FileSize ?? 0;
        }
        else if (message.Type == MessageType.Photo && message.Photo != null)
        {
            // Rasm sifatida yuborilgan APK/EXE fayllar
            var photo = message.Photo.LastOrDefault();
            if (photo != null)
            {
                fileId = photo.FileId;
                fileName = "image.jpg";
                fileSize = photo.FileSize ?? 0;
            }
        }

        if (fileId == null || fileName == null)
        {
            await _bot.SendMessage(chatId,
                "⚠️ Iltimos, faylni *Dokument* sifatida yuboring.\n"
                + "(Siqish yoki o'zgartirish bo'lmasligi uchun)",
                parseMode: ParseMode.Markdown,
                cancellationToken: ct);
            return;
        }

        // Hajm tekshirish
        if (fileSize > MaxFileSize)
        {
            await _bot.SendMessage(chatId,
                $"❌ Fayl juda katta ({fileSize / 1024 / 1024} MB).\n"
                + $"Maksimal: {MaxFileSize / 1024 / 1024} MB",
                cancellationToken: ct);
            return;
        }

        await AnalyzeFileAsync(chatId, userId, username, fileId, fileName, ct);
    }

    private async Task AnalyzeFileAsync(
        long chatId, long userId, string username,
        string fileId, string fileName, CancellationToken ct)
    {
        // Kutish xabari
        var waitMsg = await _bot.SendMessage(chatId,
            "⏳ *Fayl tahlil qilinmoqda...*\n"
            + "🔍 Virus va firibgarlik belgilari tekshirilmoqda...",
            parseMode: ParseMode.Markdown,
            cancellationToken: ct);

        try
        {
            // Faylni yuklab olish
            byte[] fileBytes;
            using (var memStream = new MemoryStream())
            {
                var tgFile = await _bot.GetFile(fileId, cancellationToken: ct);
                await _bot.DownloadFile(tgFile.FilePath!, memStream, cancellationToken: ct);
                fileBytes = memStream.ToArray();
            }

            // Asosiy tahlil
            var result = await _analysisService.AnalyzeFileAsync(fileName, fileBytes);

            // VirusTotal tekshirish (agar API kalit bo'lsa)
            if (_virusTotalService.IsAvailable && result.Sha256Hash != null)
            {
                await _bot.EditMessageText(chatId, waitMsg.MessageId,
                    "⏳ *VirusTotal tekshirilmoqda...*",
                    parseMode: ParseMode.Markdown,
                    cancellationToken: ct);

                var (found, detections, total) = await _virusTotalService.CheckHashAsync(result.Sha256Hash);
                result.VirusTotalChecked = true;

                if (found)
                {
                    result.VirusTotalDetections = detections;
                    if (detections > 0)
                    {
                        result.DetectedThreats.Add($"🦠 VirusTotal: {detections}/{total} antivirus xavf aniqladi!");
                    }
                    else
                    {
                        result.SafeIndicators.Add($"✅ VirusTotal: {total} antivirusdan hech biri tahdid topmadi");
                    }
                }
            }

            // Statistika saqlash
            _reportService.RecordScan(userId, username, fileName, result.RiskLevel);

            // Natijani yuborish
            await _bot.DeleteMessage(chatId, waitMsg.MessageId, ct);
            await SendAnalysisResultAsync(chatId, result, ct);
        }
        catch (Exception ex)
        {
            await _bot.EditMessageText(chatId, waitMsg.MessageId,
                $"❌ Tahlil paytida xatolik: {ex.Message}",
                cancellationToken: ct);
        }
    }

    private async Task SendAnalysisResultAsync(long chatId, FileAnalysisResult result, CancellationToken ct)
    {
        var riskEmoji = result.RiskLevel switch
        {
            RiskLevel.Safe => "🟢",
            RiskLevel.Low => "🟡",
            RiskLevel.Medium => "🟠",
            RiskLevel.High => "🔴",
            RiskLevel.Critical => "☠️",
            _ => "❓"
        };

        var riskText = result.RiskLevel switch
        {
            RiskLevel.Safe => "XAVFSIZ",
            RiskLevel.Low => "PAST XAVF",
            RiskLevel.Medium => "O'RTA XAVF",
            RiskLevel.High => "YUQORI XAVF",
            RiskLevel.Critical => "JUDA XAVFLI",
            _ => "NOMA'LUM"
        };

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"{riskEmoji} *{riskText}* {riskEmoji}");
        sb.AppendLine();
        sb.AppendLine($"📄 Fayl: `{result.FileName}`");
        sb.AppendLine();

        if (result.DetectedThreats.Any())
        {
            sb.AppendLine("🚨 *Aniqlangan muammolar:*");
            foreach (var threat in result.DetectedThreats.Take(5))
                sb.AppendLine(threat);
            sb.AppendLine();
        }

        if (result.SuspiciousIndicators.Any())
        {
            sb.AppendLine("⚠️ *Shubhali belgilar:*");
            foreach (var ind in result.SuspiciousIndicators.Take(3))
                sb.AppendLine(ind);
            sb.AppendLine();
        }

        if (result.SafeIndicators.Any() && result.RiskLevel <= RiskLevel.Low)
        {
            sb.AppendLine("✅ *Xavfsizlik belgilari:*");
            foreach (var ind in result.SafeIndicators.Take(3))
                sb.AppendLine(ind);
            sb.AppendLine();
        }

        sb.AppendLine("━━━━━━━━━━━━━━━━");
        sb.AppendLine($"💡 *Tavsiya:*");
        sb.AppendLine(result.Recommendation);

        if (result.VirusTotalChecked)
        {
            sb.AppendLine();
            sb.AppendLine(result.VirusTotalDetections > 0
                ? $"🦠 VirusTotal: {result.VirusTotalDetections} ta antivirus tahdid aniqladi"
                : "✅ VirusTotal: Tahdid topilmadi");
        }

        // Keyboard - foydalanuvchiga tanlov berish
        InlineKeyboardMarkup? keyboard = null;

        if (result.RiskLevel >= RiskLevel.Medium)
        {
            keyboard = new InlineKeyboardMarkup(new[]
            {
                new[]
                {
                    InlineKeyboardButton.WithCallbackData("📖 Batafsil ma'lumot", $"detail_{result.Sha256Hash?[..8]}"),
                    InlineKeyboardButton.WithCallbackData("📢 Firibgarlikni xabar qil", $"report_{result.Sha256Hash?[..8]}")
                },
                new[]
                {
                    InlineKeyboardButton.WithCallbackData("🛡️ Himoya maslahatlar", "safety_tips"),
                }
            });
        }
        else
        {
            keyboard = new InlineKeyboardMarkup(new[]
            {
                new[]
                {
                    InlineKeyboardButton.WithCallbackData("📖 Batafsil ma'lumot", $"detail_{result.Sha256Hash?[..8]}"),
                }
            });
        }

        await _bot.SendMessage(chatId,
            sb.ToString(),
            parseMode: ParseMode.Markdown,
            replyMarkup: keyboard,
            cancellationToken: ct);
    }

    private async Task HandleCallbackAsync(CallbackQuery callback, CancellationToken ct)
    {
        var chatId = callback.Message?.Chat.Id ?? 0;
        var data = callback.Data ?? "";

        await _bot.AnswerCallbackQuery(callback.Id, cancellationToken: ct);

        if (data == "safety_tips")
        {
            await _bot.SendMessage(chatId, GetSafetyTips(), parseMode: ParseMode.Markdown, cancellationToken: ct);
        }
        else if (data.StartsWith("report_"))
        {
            await _bot.SendMessage(chatId,
                "📢 *Firibgarlik haqida xabar berish:*\n\n"
                + "Bu faylni quyidagilarga xabar bering:\n"
                + "• Kiberjinoyatlar bo'limi: *1102* (O'zbekiston)\n"
                + "• Telegram: @telegram\n"
                + "• https://www.virustotal.com\n\n"
                + "Faylni HECH KIMGA yubormangg va o'chiring!",
                parseMode: ParseMode.Markdown,
                cancellationToken: ct);
        }
        else if (data.StartsWith("detail_"))
        {
            await _bot.SendMessage(chatId,
                "🔍 *Batafsil ma'lumot:*\n\n"
                + "Bot quyidagi usullar bilan faylni tekshiradi:\n"
                + "• Kengaytma tahlili (EXE, APK, BAT va h.k.)\n"
                + "• Ikki kengaytma hiylasi (photo.jpg.apk)\n"
                + "• Unicode RLO hujumi aniqlash\n"
                + "• Magic bytes tekshirish (ichki format)\n"
                + "• Taniqli brend nomlarini suiiste'mol aniqlash\n"
                + "• APK tarkibini tahlil qilish\n"
                + "• VirusTotal integratsiyasi",
                parseMode: ParseMode.Markdown,
                cancellationToken: ct);
        }
    }

    private async Task SendWelcomeAsync(long chatId, string username, CancellationToken ct)
    {
        var text = $"""
        👋 Salom, *{username}*!
        
        🛡️ *Firibgarlikni Aniqlash Boti*ga xush kelibsiz!
        
        Bu bot sizga shubhali fayllarni tekshirishda yordam beradi:
        
        📱 *Hozir ommalashgan xavflar:*
        • "Sut'dan" deb yuboriladigan APK fayllar
        • Soxta bank ilovalari (UzCard, Click, Payme)
        • RLO hujumi (nomni teskari ko'rsatish)
        • Ikki kengaytmali fayllar (foto.jpg.exe)
        
        📎 *Faylni yuboring* — men darhol tekshirib beraman!
        
        /help — Ko'rsatmalar
        /stats — Sizning statistikangiz
        """;

        var keyboard = new InlineKeyboardMarkup(new[]
        {
            new[]
            {
                InlineKeyboardButton.WithCallbackData("🛡️ Xavfsizlik maslahatlar", "safety_tips")
            }
        });

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown,
            replyMarkup: keyboard, cancellationToken: ct);
    }

    private async Task SendHelpAsync(long chatId, CancellationToken ct)
    {
        var text = """
        📖 *Yordam va ko'rsatmalar:*
        
        *Faylni qanday tekshirish:*
        1️⃣ Shubhali faylni botga yuboring
        2️⃣ Bot avtomatik tahlil qiladi
        3️⃣ Natija va tavsiya olasiz
        
        *Buyruqlar:*
        /start — Bosh menyu
        /help — Shu yordam sahifasi
        /stats — Sizning statistikangiz
        /globalstats — Umumiy statistika
        /threats — Oxirgi aniqlangan tahdidlar
        /about — Bot haqida
        
        *Qanday fayllar xavfli:*
        🔴 .exe, .msi — Windows viruslari
        🔴 .apk, .xapk — Norasmiy Android ilovalar
        🔴 .bat, .cmd, .ps1 — Skriptlar
        🔴 .vbs, .js — Skript viruslari
        🔴 Ikki kengaytmali fayllar
        
        *Muhim:* Faylni *Dokument* sifatida yuboring!
        """;

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendUserStatsAsync(long chatId, long userId, string username, CancellationToken ct)
    {
        var text = _reportService.GetUserStatsMessage(userId, username);
        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendGlobalStatsAsync(long chatId, CancellationToken ct)
    {
        var text = _reportService.GetGlobalStats();
        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendRecentThreatsAsync(long chatId, CancellationToken ct)
    {
        var threats = _reportService.GetRecentThreats();
        var text = threats.Any()
            ? "🚨 *Oxirgi aniqlangan tahdidlar:*\n\n" + string.Join("\n", threats)
            : "✅ Hozircha tahdid aniqlanmagan.";

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private async Task SendAboutAsync(long chatId, CancellationToken ct)
    {
        var text = """
        🤖 *Bot haqida:*
        
        *Firibgarlikni Aniqlash Boti v1.0*
        
        Bu bot O'zbekistonda keng tarqalgan firibgarlik usullaridan himoya qilish uchun yaratilgan.
        
        *Texnologiyalar:*
        • C# / .NET 8
        • Telegram.Bot kutubxonasi
        • VirusTotal API (ixtiyoriy)
        • SHA-256 kriptografiya
        
        *Aniqlash imkoniyatlari:*
        ✅ 40+ xavfli fayl kengaytmasi
        ✅ Ikki kengaytma hiylasi
        ✅ Unicode RLO hujumi
        ✅ Magic bytes tahlili
        ✅ APK tarkib tahlili
        ✅ Soxta brend nomlari
        ✅ VirusTotal integratsiyasi
        
        ⚠️ Bot 100% kafolat bera olmaydi. 
        Har doim ehtiyot bo'ling!
        """;

        await _bot.SendMessage(chatId, text, parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private static string GetSafetyTips() => """
        🛡️ *Xavfsizlik maslahatlar:*
        
        📱 *APK fayllar uchun:*
        • Faqat Google Play Store'dan yuklab oling
        • Noma'lum manbalardan o'rnatmang
        • Bank ilovalarini rasmiy saytlardan toping
        
        💻 *Kompyuter fayllar uchun:*
        • Noma'lumdan kelgan EXE fayllarni ochmang
        • Antivirusni doim yangilab turing
        • Muhim ma'lumotlarni zaxiralang
        
        📨 *Telegram/WhatsApp orqali:*
        • "Sut'dan" degan fayllarni ochmang
        • Taniqli brend nomidagi norasmiy fayllar xavfli
        • Kutilmaganda kelgan arxivlarni tekshiring
        
        🏦 *Bank va to'lovlar:*
        • Rasmiy ilovadan foydalaning
        • SMS kod so'ragan saytlarga ishonmang
        • Parolingizni hech kimga bermang
        """;
}
