using System.Text.RegularExpressions;
using DetectorBotV2.Models;

namespace DetectorBotV2.Services;

public class UrlAnalysisService
{
    // ==========================================
    // RASMIY DOMENLAR - bular xavfsiz
    // ==========================================
    private static readonly HashSet<string> OfficialDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        // Ijtimoiy tarmoqlar
        "instagram.com", "www.instagram.com", "l.instagram.com",
        "facebook.com", "www.facebook.com", "m.facebook.com",
        "twitter.com", "www.twitter.com", "x.com", "www.x.com",
        "tiktok.com", "www.tiktok.com",
        "youtube.com", "www.youtube.com", "youtu.be",
        "linkedin.com", "www.linkedin.com",
        "snapchat.com", "www.snapchat.com",
        "reddit.com", "www.reddit.com",

        // Telegram
        "t.me", "telegram.org", "telegram.me", "web.telegram.org",

        // Google
        "google.com", "www.google.com", "accounts.google.com",
        "gmail.com", "mail.google.com", "drive.google.com",
        "play.google.com",

        // O'zbekiston rasmiylari
        "click.uz", "my.click.uz",
        "payme.uz", "checkout.payme.uz",
        "uzcard.uz", "www.uzcard.uz",
        "humo.uz", "www.humo.uz",
        "myid.uz", "id.egov.uz",
        "gov.uz", "egov.uz",
        "uzum.uz", "www.uzum.uz",
        "hamkorbank.uz", "www.hamkorbank.uz",
        "kapitalbank.uz", "www.kapitalbank.uz",
        "xalqbank.uz", "www.xalqbank.uz",
        "aloqabank.uz", "www.aloqabank.uz",
        "agrobank.uz", "www.agrobank.uz",
        "ipoteka.uz", "www.ipoteka.uz",

        // Boshqa mashhur saytlar
        "apple.com", "www.apple.com", "appleid.apple.com",
        "microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
        "amazon.com", "www.amazon.com",
        "netflix.com", "www.netflix.com",
        "github.com", "www.github.com",
        "paypal.com", "www.paypal.com",
    };

    // ==========================================
    // QISQARTIRUVCHI LINKLAR - yashirilgan manzil
    // ==========================================
    private static readonly HashSet<string> ShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
        "buff.ly", "rb.gy", "cutt.ly", "short.io", "tiny.cc",
        "shorturl.at", "tly.sh", "bl.ink", "s.id", "clck.ru",
        "vk.cc", "u.to", "v.gd", "0rz.tw", "2u.pw"
    };

    // ==========================================
    // TANIQLI BRENDLAR - soxta domenni aniqlash
    // ==========================================
    private static readonly Dictionary<string, string[]> BrandDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        ["instagram"] = new[] { "instagram.com" },
        ["facebook"]  = new[] { "facebook.com" },
        ["tiktok"]    = new[] { "tiktok.com" },
        ["twitter"]   = new[] { "twitter.com", "x.com" },
        ["youtube"]   = new[] { "youtube.com", "youtu.be" },
        ["telegram"]  = new[] { "t.me", "telegram.org", "telegram.me" },
        ["google"]    = new[] { "google.com", "gmail.com" },
        ["apple"]     = new[] { "apple.com" },
        ["microsoft"] = new[] { "microsoft.com", "microsoftonline.com" },
        ["paypal"]    = new[] { "paypal.com" },
        ["amazon"]    = new[] { "amazon.com" },
        ["netflix"]   = new[] { "netflix.com" },
        ["click"]     = new[] { "click.uz" },
        ["payme"]     = new[] { "payme.uz" },
        ["uzcard"]    = new[] { "uzcard.uz" },
        ["humo"]      = new[] { "humo.uz" },
        ["hamkorbank"]= new[] { "hamkorbank.uz" },
        ["kapitalbank"]= new[] { "kapitalbank.uz" },
        ["uzum"]      = new[] { "uzum.uz" },
        ["myid"]      = new[] { "myid.uz" },
    };

    // ==========================================
    // PHISHING NAQSHLARI
    // ==========================================
    private static readonly (string pattern, string description)[] PhishingPatterns = new[]
    {
        (@"inst[a-z]*gram[a-z]*\.", "Instagram nomi o'zgartirilgan"),
        (@"faceb[a-z]*ok[a-z]*\.", "Facebook nomi o'zgartirilgan"),
        (@"telegr[a-z]*m[a-z]*\.", "Telegram nomi o'zgartirilgan"),
        (@"g[o0][o0]gle[a-z]*\.", "Google nomi o'zgartirilgan"),
        (@"paypa[l1][a-z]*\.", "PayPal nomi o'zgartirilgan"),
        (@"micr[o0]s[o0]ft[a-z]*\.", "Microsoft nomi o'zgartirilgan"),
        (@"amaz[o0]n[a-z]*\.", "Amazon nomi o'zgartirilgan"),

        // Phishing so'zlar domenida
        (@"(verify|confirm|secure|login|signin|account|update|recover|restore|unlock|reactivate|checkpoint|disabled|appeal|suspended|validate|authenticate)\.", "Phishing kalit so'z domenida"),
        (@"\.(verify|confirm|checkpoint|login|signin|secure|recover)\.", "Phishing kalit so'z subdomenida"),

        // IP manzil
        (@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP manzil ishlatilgan"),

        // Ko'p defis
        (@"[a-z]+-[a-z]+-[a-z]+-[a-z]+\.", "Ko'p defisli shubhali domen"),

        // Kirill harflari (homograph attack)
        (@"[а-яёА-ЯЁ]", "Kirill harflari — vizual aldash hujumi"),
    };

    // ==========================================
    // ASOSIY URL TAHLIL
    // ==========================================
    public AnalysisResult AnalyzeUrl(string url)
    {
        var result = new AnalysisResult { Target = url, Type = "URL" };

        if (!url.StartsWith("http://") && !url.StartsWith("https://"))
            url = "https://" + url;

        Uri? uri = null;
        try { uri = new Uri(url); }
        catch
        {
            result.Threats.Add("❌ Noto'g'ri URL formati");
            result.RiskLevel = RiskLevel.High;
            result.Recommendation = "🔴 Bu URL noto'g'ri!";
            return result;
        }

        var host = uri.Host.ToLowerInvariant().TrimStart('w').TrimStart('w').TrimStart('w').TrimStart('.');
        var fullHost = uri.Host.ToLowerInvariant();
        var fullUrl = url.ToLowerInvariant();
        var path = uri.PathAndQuery.ToLowerInvariant();

        // 1. HTTPS tekshirish
        if (uri.Scheme == "http")
            result.Warnings.Add("⚠️ HTTP — shifrsiz ulanish (HTTPS emas)");
        else
            result.SafePoints.Add("✅ HTTPS — shifrlangan ulanish");

        // 2. Rasmiy domen tekshirish
        bool isOfficial = OfficialDomains.Contains(fullHost);
        if (isOfficial)
        {
            result.SafePoints.Add($"✅ Rasmiy tasdiqlangan domen: `{fullHost}`");
            // Rasmiy domenlar uchun path tekshirish
            CheckOfficialDomainPath(result, fullHost, path);
            result.RiskLevel = CalcRisk(result);
            result.Recommendation = GenRecommendation(result.RiskLevel);
            return result;
        }

        // 3. Qisqartiruvchi link
        if (ShortenerDomains.Contains(fullHost))
        {
            result.Warnings.Add($"⚠️ Qisqartiruvchi link: `{fullHost}`");
            result.Warnings.Add("   Asl manzil yashirilgan — ehtiyot bo'ling!");
        }

        // 4. Brend nomini soxta domendan aniqlash
        CheckBrandImpersonation(result, fullHost, fullUrl);

        // 5. Phishing naqshlari
        CheckPhishingPatterns(result, fullHost, fullUrl);

        // 6. Subdomenlar soni
        var domainParts = fullHost.Split('.');
        if (domainParts.Length > 4)
            result.Warnings.Add($"⚠️ Ko'p subdomen ({domainParts.Length}) — shubhali tuzilma");

        // 7. Domen uzunligi
        if (fullHost.Length > 35)
            result.Warnings.Add($"⚠️ Domen nomi juda uzun ({fullHost.Length} belgi)");

        // 8. Ko'p maxsus belgilar
        var dashes = fullHost.Count(c => c == '-');
        if (dashes >= 3)
            result.Warnings.Add($"⚠️ Domenда {dashes} ta defis — yashirish urinishi");

        // 9. Raqamlar domenida
        var digits = fullHost.Count(char.IsDigit);
        if (digits > 3)
            result.Warnings.Add($"⚠️ Domenда {digits} ta raqam — shubhali");

        // 10. Path da shubhali so'zlar
        var pathKeywords = new[] { "login", "signin", "password", "credential", "verify", "confirm", "checkpoint", "recover", "phishing" };
        var foundPath = pathKeywords.Where(k => path.Contains(k)).ToList();
        if (foundPath.Any())
            result.Warnings.Add($"⚠️ URL da shubhali so'z: `{string.Join(", ", foundPath)}`");

        // Natija
        result.RiskLevel = CalcRisk(result);
        result.Recommendation = GenRecommendation(result.RiskLevel);
        return result;
    }

    private void CheckOfficialDomainPath(AnalysisResult result, string host, string path)
    {
        // Rasmiy domendan kelgan lekin shubhali path
        var suspiciousPaths = new[] { "phishing", "hack", "stolen", "malware" };
        foreach (var sp in suspiciousPaths)
        {
            if (path.Contains(sp))
                result.Warnings.Add($"⚠️ URL da shubhali so'z: `{sp}`");
        }
    }

    private void CheckBrandImpersonation(AnalysisResult result, string host, string fullUrl)
    {
        foreach (var (brand, officialDomains) in BrandDomains)
        {
            // Domenда brend nomi bor, lekin rasmiy domen emas
            if (host.Contains(brand) && !officialDomains.Any(od => host == od || host.EndsWith("." + od)))
            {
                result.Threats.Add($"🎣 PHISHING! `{brand.ToUpper()}` nomi soxta domenда ishlatilgan!");
                result.Threats.Add($"   Rasmiy: `{officialDomains[0]}` | Soxta: `{host}`");
                break;
            }
        }
    }

    private void CheckPhishingPatterns(AnalysisResult result, string host, string fullUrl)
    {
        foreach (var (pattern, desc) in PhishingPatterns)
        {
            if (Regex.IsMatch(host, pattern, RegexOptions.IgnoreCase))
            {
                result.Threats.Add($"🚨 {desc}");
                break;
            }
        }
    }

    // ==========================================
    // USERNAME TAHLIL
    // ==========================================
    public AnalysisResult AnalyzeUsername(string username)
    {
        var result = new AnalysisResult { Target = username, Type = "USERNAME" };
        var clean = username.TrimStart('@').ToLowerInvariant();

        string[] officialBrands = {
            "uzcard", "humo", "click", "payme", "telegram", "support",
            "admin", "official", "helpdesk", "service", "bank", "help",
            "instagram", "facebook", "tiktok", "google", "apple"
        };

        foreach (var brand in officialBrands)
        {
            if (clean.Contains(brand))
            {
                result.Warnings.Add($"⚠️ '{brand}' nomi ishlatilgan — rasmiy emasligini tekshiring!");
                result.Warnings.Add("   Rasmiy kanallar Telegram da ✅ tasdiqlangan belgiga ega");
                break;
            }
        }

        var digitCount = clean.Count(char.IsDigit);
        if (digitCount > 5)
            result.Warnings.Add($"⚠️ Username da {digitCount} ta raqam — bot yoki soxta akkaunt");

        if (clean.Length > 25)
            result.Warnings.Add("⚠️ Username juda uzun");

        if (!result.Warnings.Any() && !result.Threats.Any())
            result.SafePoints.Add("✅ Aniq xavfli belgilar topilmadi");

        result.RiskLevel = CalcRisk(result);
        result.Recommendation = GenRecommendation(result.RiskLevel);
        return result;
    }

    // ==========================================
    // TELEFON TAHLIL
    // ==========================================
    public AnalysisResult AnalyzePhone(string phone)
    {
        var result = new AnalysisResult { Target = phone, Type = "PHONE" };
        var clean = Regex.Replace(phone, @"[^\d+]", "");

        var uzOperators = new Dictionary<string, string>
        {
            {"90","Beeline"}, {"91","Beeline"}, {"93","Ucell"},
            {"94","Ucell"}, {"95","Uzmobile"}, {"99","Uzmobile"},
            {"97","MTS"}, {"78","UzTelecom"}, {"88","UzTelecom"},
            {"33","Humans"}, {"71","UzTelecom"}, {"77","UzTelecom"}
        };

        bool isUz = clean.StartsWith("+998") || clean.StartsWith("998") || clean.StartsWith("0");

        if (isUz)
        {
            var local = clean.TrimStart('+').TrimStart('9', '9', '8').TrimStart('0');
            var prefix = local.Length >= 2 ? local[..2] : "";

            if (uzOperators.TryGetValue(prefix, out var op))
                result.SafePoints.Add($"✅ O'zbekiston raqami — {op} operatori");
            else
                result.Warnings.Add("⚠️ Noma'lum O'zbekiston operatori prefiks");
        }
        else if (clean.StartsWith("+7") || clean.StartsWith("7"))
            result.Warnings.Add("⚠️ Rossiya raqami — ehtiyot bo'ling");
        else
            result.Warnings.Add("⚠️ Xorijiy raqam — ehtiyot bo'ling");

        var digits = clean.Replace("+", "");
        if (digits.Length < 9 || digits.Length > 15)
            result.Threats.Add("❌ Noto'g'ri raqam uzunligi");
        else
            result.SafePoints.Add($"✅ Raqam uzunligi to'g'ri ({digits.Length} raqam)");

        result.RiskLevel = CalcRisk(result);
        result.Recommendation = GenRecommendation(result.RiskLevel);
        return result;
    }

    private static RiskLevel CalcRisk(AnalysisResult r)
    {
        var score = r.Threats.Count * 35 + r.Warnings.Count * 10 - r.SafePoints.Count * 8;
        return score switch
        {
            <= 0  => RiskLevel.Safe,
            <= 10 => RiskLevel.Low,
            <= 30 => RiskLevel.Medium,
            <= 65 => RiskLevel.High,
            _     => RiskLevel.Critical
        };
    }

    private static string GenRecommendation(RiskLevel l) => l switch
    {
        RiskLevel.Safe     => "✅ XAVFSIZ: Davom etishingiz mumkin.",
        RiskLevel.Low      => "🟡 PAST XAVF: Manbasini tekshiring.",
        RiskLevel.Medium   => "🟠 O'RTA XAVF: Ehtiyot bo'ling!",
        RiskLevel.High     => "🔴 YUQORI XAVF: Kirmang!",
        RiskLevel.Critical => "☠️ JUDA XAVFLI: Bu linkni OCHMANG!",
        _                  => "❓ Noma'lum"
    };
}
