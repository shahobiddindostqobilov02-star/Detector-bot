using System.Security.Cryptography;
using System.Text.RegularExpressions;
using FraudDetectorBot.Models;

namespace FraudDetectorBot.Services;

public class FileAnalysisService
{
    // ==========================================
    // XAVFLI KENGAYTMALAR RO'YXATI
    // ==========================================
    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Bajariladigan fayllar
        ".exe", ".msi", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".vbe",
        ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".ps1", ".ps1xml", ".ps2",
        ".ps2xml", ".psc1", ".psc2", ".msh", ".msh1", ".msh2", ".mshxml",
        
        // Android zararli fayllar (asosiy nishon)
        ".apk", ".xapk", ".apks", ".aab",
        
        // Makro va skript fayllar
        ".xlsm", ".xlsb", ".docm", ".dotm", ".pptm", ".potm", ".ppam",
        
        // Arxiv va paketlar (yashirilgan zararli kod)
        ".jar", ".war",
        
        // Tizim fayllar
        ".dll", ".sys", ".drv", ".ocx", ".cpl", ".inf",
        
        // Boshqa xavflilar
        ".lnk", ".url", ".reg", ".hta", ".application"
    };

    // Ikki kengaytmali firibgarlik naqshlari (masalan: "foto.jpg.apk")
    private static readonly string[] DoublExtensionTricks = new[]
    {
        @"\.(jpg|jpeg|png|gif|bmp|pdf|doc|docx|mp3|mp4|avi|txt)\.(exe|apk|bat|vbs|ps1|cmd|msi|scr)$",
        @"\.(exe|apk|bat|vbs)\.(jpg|jpeg|png|gif|pdf)$" // Teskari - haqiqiy kengaytmani yashirish
    };

    // Firibgar ilova nomlari (O'zbekistonda ommalashgan)
    private static readonly string[] FraudulentAppNames = new[]
    {
        "uzum", "uzcard", "humo", "click", "payme", "myid", "egov",
        "davr", "ipak-yoli", "hamkorbank", "kapitalbank", "xalqbank",
        "aloqabank", "agrobank", "asaka", "trustbank", "ziraat",
        "netflix", "telegram", "whatsapp", "instagram", "tiktok",
        "youtube", "google", "microsoft", "apple", "samsung",
        "lottery", "loterya", "yutish", "bonus", "sovg'a", "sovga",
        "bepul", "free", "hack", "crack", "mod", "premium", "pro-unlock",
        "bank", "kredit", "qarz", "moliya", "invest", "crypto",
        "bitcoin", "binance", "bybit", "huobi", "okx",
        "prize", "winner", "congratulations", "tabrik", "mukofot"
    };

    // Magic bytes - fayl boshidagi haqiqiy format belgilari
    private static readonly Dictionary<string, byte[]> MagicBytes = new()
    {
        { "ZIP/APK", new byte[] { 0x50, 0x4B, 0x03, 0x04 } },
        { "EXE/DLL", new byte[] { 0x4D, 0x5A } },  // MZ header
        { "PDF",     new byte[] { 0x25, 0x50, 0x44, 0x46 } },
        { "JPEG",    new byte[] { 0xFF, 0xD8, 0xFF } },
        { "PNG",     new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
        { "RAR",     new byte[] { 0x52, 0x61, 0x72, 0x21 } },
    };

    // Shubhali Unicode belgilar (RLO attack - o'ngdan chapga yozish hiylasi)
    private static readonly char[] SuspiciousUnicodeChars = new[]
    {
        '\u202E', // RIGHT-TO-LEFT OVERRIDE - eng xavfli
        '\u200F', // RIGHT-TO-LEFT MARK
        '\u200B', // ZERO WIDTH SPACE
        '\u00AD', // SOFT HYPHEN
    };

    public async Task<FileAnalysisResult> AnalyzeFileAsync(string fileName, byte[] fileBytes)
    {
        var result = new FileAnalysisResult
        {
            FileName = fileName,
            FileSize = fileBytes.Length,
            FileExtension = Path.GetExtension(fileName).ToLowerInvariant(),
            Sha256Hash = ComputeSha256(fileBytes)
        };

        // Barcha tekshiruvlarni amalga oshirish
        CheckExtension(result, fileName);
        CheckDoubleExtension(result, fileName);
        CheckUnicodeAttack(result, fileName);
        CheckFileSize(result, fileBytes.Length);
        CheckMagicBytes(result, fileName, fileBytes);
        CheckFraudulentAppName(result, fileName);
        CheckApkSpecific(result, fileName, fileBytes);
        CheckSuspiciousZipContent(result, fileBytes);

        // Umumiy xavf darajasini hisoblash
        result.RiskLevel = CalculateRiskLevel(result);
        result.Recommendation = GenerateRecommendation(result);
        result.DetailedExplanation = GenerateDetailedExplanation(result);

        return await Task.FromResult(result);
    }

    private void CheckExtension(FileAnalysisResult result, string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        if (DangerousExtensions.Contains(ext))
        {
            result.DetectedThreats.Add($"⚠️ Xavfli kengaytma: `{ext}`");

            if (ext == ".apk" || ext == ".xapk")
                result.DetectedThreats.Add("📱 Android APK fayli - norasmiy manbadan o'rnatish xavfli!");
            else if (ext == ".exe" || ext == ".msi")
                result.DetectedThreats.Add("💻 Windows bajariladigan fayli");
            else if (ext == ".bat" || ext == ".cmd" || ext == ".ps1")
                result.DetectedThreats.Add("⌨️ Buyruq satri skripti - tizimni boshqarishi mumkin");
            else if (ext == ".vbs" || ext == ".js")
                result.DetectedThreats.Add("🔧 Skript fayli - avtomatik ishga tushishi mumkin");
        }
        else
        {
            result.SafeIndicators.Add($"✅ Kengaytma odatda xavfsiz: `{ext}`");
        }
    }

    private void CheckDoubleExtension(FileAnalysisResult result, string fileName)
    {
        foreach (var pattern in DoublExtensionTricks)
        {
            if (Regex.IsMatch(fileName, pattern, RegexOptions.IgnoreCase))
            {
                result.IsDoubleExtension = true;
                result.IsMasquerading = true;
                result.DetectedThreats.Add("🎭 IKKI KENGAYTMA HIYLASI aniqlandi!");
                result.DetectedThreats.Add($"   Fayl o'zini boshqa format sifatida ko'rsatmoqda");
                result.SuspiciousIndicators.Add("Masalan: 'rasm.jpg.apk' - aslida APK lekin JPG ko'rinishida");
                break;
            }
        }

        // Umuman bir nechta nuqta tekshirish
        var nameParts = Path.GetFileNameWithoutExtension(fileName).Split('.');
        if (nameParts.Length > 1 && DangerousExtensions.Contains("." + nameParts.Last()))
        {
            result.IsMasquerading = true;
            result.SuspiciousIndicators.Add($"⚠️ Fayl nomida yashirin kengaytma: `.{nameParts.Last()}`");
        }
    }

    private void CheckUnicodeAttack(FileAnalysisResult result, string fileName)
    {
        foreach (var ch in SuspiciousUnicodeChars)
        {
            if (fileName.Contains(ch))
            {
                result.IsMasquerading = true;
                result.DetectedThreats.Add("🔄 RLO (O'ngdan-chapga) UNICODE HUJUMI aniqlandi!");
                result.DetectedThreats.Add("   Fayl nomi aslida teskari yozilgan - ko'rinishi aldatadi!");
                result.SuspiciousIndicators.Add("Bu usul bilan 'gpj.exe' fayli 'exe.jpg' ko'rinishida yashiriladi");
                break;
            }
        }
    }

    private void CheckFileSize(FileAnalysisResult result, long size)
    {
        var ext = result.FileExtension;

        // Juda kichik APK - shubhali (haqiqiy ilovalar kamida 1-2 MB)
        if ((ext == ".apk" || ext == ".xapk") && size < 500_000) // 500 KB dan kam
        {
            result.SuspiciousIndicators.Add($"📦 APK hajmi juda kichik: {FormatSize(size)} - haqiqiy ilova emas bo'lishi mumkin");
        }

        // Juda katta fayl arxivda yashirilgan bo'lishi mumkin
        if (size > 100_000_000) // 100 MB dan katta
        {
            result.SuspiciousIndicators.Add($"📦 Fayl juda katta: {FormatSize(size)} - ichida nima borligini tekshiring");
        }

        result.SafeIndicators.Add($"📏 Fayl hajmi: {FormatSize(size)}");
    }

    private void CheckMagicBytes(FileAnalysisResult result, string fileName, byte[] bytes)
    {
        if (bytes.Length < 4) return;

        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        string? detectedFormat = null;

        foreach (var (format, magic) in MagicBytes)
        {
            if (bytes.Take(magic.Length).SequenceEqual(magic))
            {
                detectedFormat = format;
                break;
            }
        }

        if (detectedFormat == null) return;

        // APK aslida ZIP format
        if (detectedFormat == "ZIP/APK" && ext != ".apk" && ext != ".xapk" &&
            ext != ".zip" && ext != ".jar" && ext != ".docx" && ext != ".xlsx")
        {
            result.IsMasquerading = true;
            result.DetectedThreats.Add($"🔍 Fayl ichki formatiga ko'ra ZIP/APK, lekin kengaytmasi `{ext}`");
        }

        // EXE boshqa nom bilan
        if (detectedFormat == "EXE/DLL" && ext != ".exe" && ext != ".dll" && ext != ".sys")
        {
            result.IsMasquerading = true;
            result.DetectedThreats.Add($"🔍 Fayl aslida EXE/DLL, lekin `{ext}` kengaytmasi bilan yashirilgan!");
        }

        result.SafeIndicators.Add($"🔎 Ichki format: {detectedFormat}");
    }

    private void CheckFraudulentAppName(FileAnalysisResult result, string fileName)
    {
        var lowerName = fileName.ToLowerInvariant();

        foreach (var appName in FraudulentAppNames)
        {
            if (lowerName.Contains(appName))
            {
                var ext = result.FileExtension;
                if (DangerousExtensions.Contains(ext))
                {
                    result.DetectedThreats.Add($"🏦 Taniqli nom ishlatilgan: '{appName}' - bu rasmiy ilova EMAS!");
                    result.SuspiciousIndicators.Add($"Firibgarlar '{appName}' nomini ishlatib ishonch qozonmoqchi");
                }
                else
                {
                    result.SuspiciousIndicators.Add($"ℹ️ '{appName}' nomi topildi - rasmiy do'kondan yuklanganligini tekshiring");
                }
                break;
            }
        }
    }

    private void CheckApkSpecific(FileAnalysisResult result, string fileName, byte[] bytes)
    {
        if (result.FileExtension != ".apk" && result.FileExtension != ".xapk") return;

        result.DetectedThreats.Add("📱 APK fayli - faqat rasmiy Play Store orqali o'rnating!");

        // APK tarkibini tekshirish (ZIP ichida)
        try
        {
            using var stream = new MemoryStream(bytes);
            using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);

            var entries = zip.Entries.Select(e => e.FullName).ToList();

            // AndroidManifest.xml bormi?
            if (!entries.Any(e => e.Equals("AndroidManifest.xml", StringComparison.OrdinalIgnoreCase)))
            {
                result.DetectedThreats.Add("❌ AndroidManifest.xml yo'q - bu haqiqiy APK emas!");
            }
            else
            {
                result.SafeIndicators.Add("✅ AndroidManifest.xml mavjud");
            }

            // Shubhali fayllar ichida
            var suspiciousInZip = entries.Where(e =>
                e.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                e.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                e.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
            ).ToList();

            if (suspiciousInZip.Any())
            {
                result.DetectedThreats.Add($"☠️ APK ichida xavfli fayllar topildi: {string.Join(", ", suspiciousInZip.Take(3))}");
            }

            // Fayllar soni
            result.SuspiciousIndicators.Add($"📂 APK ichida {entries.Count} ta fayl");
        }
        catch
        {
            result.SuspiciousIndicators.Add("⚠️ APK tarkibini o'qib bo'lmadi - buzilgan yoki himoyalangan");
        }
    }

    private void CheckSuspiciousZipContent(FileAnalysisResult result, byte[] bytes)
    {
        var ext = result.FileExtension;
        if (ext != ".zip" && ext != ".rar" && ext != ".7z") return;

        // ZIP bo'lsa ichini tekshirish
        if (ext == ".zip")
        {
            try
            {
                using var stream = new MemoryStream(bytes);
                using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);

                var dangerousEntries = zip.Entries
                    .Where(e => DangerousExtensions.Contains(Path.GetExtension(e.Name).ToLowerInvariant()))
                    .Select(e => e.FullName)
                    .ToList();

                if (dangerousEntries.Any())
                {
                    result.DetectedThreats.Add($"📦 ZIP ichida xavfli fayllar: {string.Join(", ", dangerousEntries.Take(5))}");
                }
                else
                {
                    result.SafeIndicators.Add("✅ ZIP ichida xavfli fayllar topilmadi");
                }
            }
            catch { /* Himoyalangan ZIP */ }
        }
    }

    private RiskLevel CalculateRiskLevel(FileAnalysisResult result)
    {
        var score = 0;

        score += result.DetectedThreats.Count * 25;
        score += result.SuspiciousIndicators.Count * 10;
        score -= result.SafeIndicators.Count * 5;

        if (result.IsMasquerading) score += 50;
        if (result.IsDoubleExtension) score += 40;

        return score switch
        {
            <= 0 => RiskLevel.Safe,
            <= 15 => RiskLevel.Low,
            <= 40 => RiskLevel.Medium,
            <= 80 => RiskLevel.High,
            _ => RiskLevel.Critical
        };
    }

    private string GenerateRecommendation(FileAnalysisResult result)
    {
        return result.RiskLevel switch
        {
            RiskLevel.Safe => "✅ XAVFSIZ: Bu faylni ochishingiz mumkin, lekin doim ehtiyot bo'ling.",
            RiskLevel.Low => "🟡 PAST XAVF: Faylni ochishdan oldin manbasini tekshiring.",
            RiskLevel.Medium => "🟠 O'RTA XAVF: Ehtiyot bo'ling! Noma'lum manbadan kelgan bo'lsa, ochmang.",
            RiskLevel.High => "🔴 YUQORI XAVF: Bu faylni OCHMANG! Yuborgan shaxsga ishonmasangiz, o'chiring.",
            RiskLevel.Critical => "☠️ JUDA XAVFLI: Bu faylni HECH QACHON OCHMANG! Darhol o'chiring!",
            _ => "❓ Noma'lum"
        };
    }

    private string GenerateDetailedExplanation(FileAnalysisResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine($"📋 *Tahlil xulosasi:*");
        sb.AppendLine($"Fayl: `{result.FileName}`");
        sb.AppendLine($"Hajm: {FormatSize(result.FileSize)}");
        sb.AppendLine($"SHA-256: `{result.Sha256Hash?[..16]}...`");
        sb.AppendLine();

        if (result.DetectedThreats.Any())
        {
            sb.AppendLine("🚨 *Aniqlangan tahdidlar:*");
            foreach (var threat in result.DetectedThreats)
                sb.AppendLine($"  {threat}");
            sb.AppendLine();
        }

        if (result.SuspiciousIndicators.Any())
        {
            sb.AppendLine("⚠️ *Shubhali belgilar:*");
            foreach (var indicator in result.SuspiciousIndicators)
                sb.AppendLine($"  {indicator}");
            sb.AppendLine();
        }

        if (result.SafeIndicators.Any())
        {
            sb.AppendLine("✅ *Xavfsizlik belgilari:*");
            foreach (var indicator in result.SafeIndicators)
                sb.AppendLine($"  {indicator}");
        }

        return sb.ToString();
    }

    public static string ComputeSha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:F1} MB";
        return $"{bytes / 1024.0 / 1024.0 / 1024.0:F1} GB";
    }
}
