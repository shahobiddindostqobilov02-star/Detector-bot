using System.Text.RegularExpressions;
using DetectorBotV2.Models;

namespace DetectorBotV2.Services;

public class UrlAnalysisService
{
    // Xavfli domenlar ro'yxati
    private static readonly HashSet<string> DangerousDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd", "buff.ly",
        "rb.gy", "cutt.ly", "short.io", "tiny.cc", "shorturl.at"
    };

    // Firibgar sayt belgilari
    private static readonly string[] SuspiciousKeywords = new[]
    {
        "login", "signin", "account", "verify", "secure", "update", "confirm",
        "banking", "paypal", "amazon", "google", "microsoft", "apple", "netflix",
        "uzcard", "humo", "click", "payme", "hamkorbank", "kapitalbank",
        "prize", "winner", "lottery", "bonus", "free", "giveaway",
        "crypto", "bitcoin", "invest", "profit", "earn",
        "admin", "support", "help-center", "customer-service"
    };

    // Phishing naqshlari
    private static readonly string[] PhishingPatterns = new[]
    {
        @"[a-z]+-[a-z]+-[a-z]+\.[a-z]{2,}",      // ko'p defis: uzcard-login-verify.com
        @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   // IP manzil: http://192.168.1.1/bank
        @"[а-яёА-ЯЁ]",                              // Kirill harflari (punycode hujumi)
        @"secure.*bank|bank.*secure",               // secure+bank kombinatsiyasi
        @"(paypal|amazon|google|microsoft)\.[a-z]{4,}", // Soxta domenlar
    };

    public AnalysisResult AnalyzeUrl(string url)
    {
        var result = new AnalysisResult { Target = url, Type = "URL" };

        // URL normalizatsiya
        if (!url.StartsWith("http://") && !url.StartsWith("https://"))
            url = "https://" + url;

        Uri? uri = null;
        try { uri = new Uri(url); } catch { }

        if (uri == null)
        {
            result.Threats.Add("❌ Noto'g'ri URL formati");
            result.RiskLevel = RiskLevel.High;
            result.Recommendation = "🔴 Bu URL noto'g'ri — ehtiyot bo'ling!";
            return result;
        }

        var host = uri.Host.ToLowerInvariant();
        var fullUrl = url.ToLowerInvariant();

        // HTTP tekshirish
        if (uri.Scheme == "http")
            result.Warnings.Add("⚠️ HTTP — shifrsiz ulanish (HTTPS emas)");
        else
            result.SafePoints.Add("✅ HTTPS — shifrlangan ulanish");

        // Qisqartiruvchi linklar
        if (DangerousDomains.Contains(host))
        {
            result.Warnings.Add($"⚠️ Qisqartiruvchi link: `{host}` — asl manzil yashirilgan!");
            result.Warnings.Add("   Qisqartiruvchi linklar firibgarlikda keng ishlatiladi");
        }

        // IP manzil
        if (Regex.IsMatch(host, @"^\d+\.\d+\.\d+\.\d+$"))
            result.Threats.Add("🚨 IP manzil ishlatilgan — firibgarlik belgisi!");

        // Ko'p subdomen
        var domainParts = host.Split('.');
        if (domainParts.Length > 4)
            result.Warnings.Add($"⚠️ Ko'p subdomen ({domainParts.Length}) — shubhali!");

        // Phishing naqshlari
        foreach (var pattern in PhishingPatterns)
        {
            if (Regex.IsMatch(fullUrl, pattern, RegexOptions.IgnoreCase))
            {
                result.Threats.Add($"🎣 Phishing naqshi aniqlandi!");
                break;
            }
        }

        // Shubhali kalit so'zlar
        var foundKeywords = SuspiciousKeywords.Where(kw => fullUrl.Contains(kw)).Take(3).ToList();
        if (foundKeywords.Any())
            result.Warnings.Add($"⚠️ Shubhali so'zlar: `{string.Join(", ", foundKeywords)}`");

        // Uzoq domen nomi
        if (host.Length > 40)
            result.Warnings.Add("⚠️ Domen nomi juda uzun — yashirish urinishi bo'lishi mumkin");

        // Ko'p maxsus belgilar
        var specialChars = url.Count(c => c == '-' || c == '_');
        if (specialChars > 5)
            result.Warnings.Add($"⚠️ Ko'p maxsus belgi ({specialChars} ta) URL da");

        // Xavf darajasi
        result.RiskLevel = CalculateRisk(result);
        result.Recommendation = GenerateRecommendation(result.RiskLevel);

        return result;
    }

    // Telegram username tekshirish
    public AnalysisResult AnalyzeUsername(string username)
    {
        var result = new AnalysisResult
        {
            Target = username,
            Type = "USERNAME"
        };

        username = username.TrimStart('@').ToLowerInvariant();

        // Taniqli xizmatlarni taqlid qilish
        string[] officialBrands = { "uzcard", "humo", "click", "payme", "telegram",
            "support", "admin", "official", "helpdesk", "service", "bank" };

        foreach (var brand in officialBrands)
        {
            if (username.Contains(brand))
            {
                result.Warnings.Add($"⚠️ '@{brand}' nomi ishlatilgan — rasmiy ekanligini tekshiring!");
                result.Warnings.Add("   Telegram da rasmiy kanallar tasdiqlangan ✅ belgisiga ega");
            }
        }

        // Raqam ko'p bo'lsa
        var digitCount = username.Count(char.IsDigit);
        if (digitCount > 4)
            result.Warnings.Add($"⚠️ Username da {digitCount} ta raqam — bot yoki soxta akkaunt bo'lishi mumkin");

        // Juda uzun
        if (username.Length > 25)
            result.Warnings.Add("⚠️ Username juda uzun");

        if (!result.Warnings.Any() && !result.Threats.Any())
            result.SafePoints.Add("✅ Username da aniq xavfli belgilar topilmadi");

        result.RiskLevel = CalculateRisk(result);
        result.Recommendation = GenerateRecommendation(result.RiskLevel);
        return result;
    }

    // Telefon raqam tekshirish
    public AnalysisResult AnalyzePhone(string phone)
    {
        var result = new AnalysisResult { Target = phone, Type = "PHONE" };
        phone = Regex.Replace(phone, @"[^\d+]", "");

        // O'zbekiston raqamlari
        var uzPrefixes = new[] { "+998", "998" };
        bool isUz = uzPrefixes.Any(p => phone.StartsWith(p));

        if (isUz)
        {
            var operators = new Dictionary<string, string>
            {
                { "90", "Beeline" }, { "91", "Beeline" },
                { "93", "Ucell" }, { "94", "Ucell" },
                { "95", "Uzmobile" }, { "99", "Uzmobile" },
                { "97", "MTS" }, { "78", "UzTelecom" },
                { "88", "UzTelecom" }, { "33", "Humans" }
            };

            var localNum = phone.TrimStart('+').TrimStart('9', '9', '8');
            var prefix = localNum.Length >= 2 ? localNum[..2] : "";

            if (operators.TryGetValue(prefix, out var op))
                result.SafePoints.Add($"✅ O'zbekiston raqami — {op} operatori");
            else
                result.Warnings.Add("⚠️ Noma'lum O'zbekiston operatori");
        }
        else
        {
            result.Warnings.Add("⚠️ Xorijiy raqam — ehtiyot bo'ling");
        }

        // Raqam uzunligi
        var digits = phone.Replace("+", "");
        if (digits.Length < 10 || digits.Length > 15)
            result.Threats.Add("❌ Noto'g'ri telefon raqam uzunligi");

        result.RiskLevel = CalculateRisk(result);
        result.Recommendation = GenerateRecommendation(result.RiskLevel);
        return result;
    }

    private static RiskLevel CalculateRisk(AnalysisResult result)
    {
        var score = result.Threats.Count * 30 + result.Warnings.Count * 10 - result.SafePoints.Count * 5;
        return score switch
        {
            <= 0 => RiskLevel.Safe,
            <= 10 => RiskLevel.Low,
            <= 30 => RiskLevel.Medium,
            <= 60 => RiskLevel.High,
            _ => RiskLevel.Critical
        };
    }

    private static string GenerateRecommendation(RiskLevel level) => level switch
    {
        RiskLevel.Safe => "✅ XAVFSIZ: Davom etishingiz mumkin.",
        RiskLevel.Low => "🟡 PAST XAVF: Manbasini tekshiring.",
        RiskLevel.Medium => "🟠 O'RTA XAVF: Ehtiyot bo'ling!",
        RiskLevel.High => "🔴 YUQORI XAVF: Ishonmasangiz, kirmang!",
        RiskLevel.Critical => "☠️ JUDA XAVFLI: Bu linkni OCHMANG!",
        _ => "❓ Noma'lum"
    };
}
