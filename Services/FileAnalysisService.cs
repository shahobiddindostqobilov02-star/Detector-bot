using System.Security.Cryptography;
using System.Text.RegularExpressions;
using DetectorBotV2.Models;

namespace DetectorBotV2.Services;

public class FileAnalysisService
{
    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".msi", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".vbe",
        ".js", ".jse", ".ws", ".wsf", ".ps1", ".ps2", ".msh", ".hta",
        ".apk", ".xapk", ".apks", ".aab",
        ".xlsm", ".docm", ".pptm",
        ".jar", ".war",
        ".dll", ".sys", ".drv", ".ocx", ".cpl", ".inf",
        ".lnk", ".url", ".reg"
    };

    private static readonly string[] DoubleExtensionPatterns = new[]
    {
        @"\.(jpg|jpeg|png|gif|pdf|doc|docx|mp3|mp4|txt)\.(exe|apk|bat|vbs|ps1|cmd|msi|scr)$",
    };

    private static readonly string[] FraudNames = new[]
    {
        "uzum", "uzcard", "humo", "click", "payme", "myid", "egov",
        "hamkorbank", "kapitalbank", "xalqbank", "aloqabank",
        "netflix", "telegram", "whatsapp", "instagram", "tiktok",
        "lottery", "loterya", "yutish", "bonus", "sovga", "bepul",
        "hack", "crack", "mod", "premium", "bank", "kredit",
        "bitcoin", "binance", "crypto", "invest", "prize", "winner"
    };

    private static readonly Dictionary<string, byte[]> MagicBytes = new()
    {
        { "ZIP/APK", new byte[] { 0x50, 0x4B, 0x03, 0x04 } },
        { "EXE/DLL", new byte[] { 0x4D, 0x5A } },
        { "PDF",     new byte[] { 0x25, 0x50, 0x44, 0x46 } },
        { "JPEG",    new byte[] { 0xFF, 0xD8, 0xFF } },
        { "PNG",     new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
    };

    public async Task<AnalysisResult> AnalyzeFileAsync(string fileName, byte[] bytes)
    {
        var result = new AnalysisResult
        {
            Target = fileName,
            Type = "FILE",
            Size = bytes.Length,
            Hash = ComputeSha256(bytes)
        };

        CheckExtension(result, fileName);
        CheckDoubleExtension(result, fileName);
        CheckUnicode(result, fileName);
        CheckMagicBytes(result, fileName, bytes);
        CheckFraudName(result, fileName);
        CheckApkContent(result, fileName, bytes);
        CheckZipContent(result, fileName, bytes);

        result.RiskLevel = CalcRisk(result);
        result.Recommendation = GenRecommendation(result.RiskLevel);

        return await Task.FromResult(result);
    }

    private void CheckExtension(AnalysisResult r, string name)
    {
        var ext = Path.GetExtension(name).ToLowerInvariant();
        if (DangerousExtensions.Contains(ext))
        {
            r.Threats.Add($"⚠️ Xavfli kengaytma: `{ext}`");
            if (ext is ".apk" or ".xapk")
                r.Threats.Add("📱 Android APK — norasmiy manbadan o'rnatish xavfli!");
            else if (ext is ".exe" or ".msi")
                r.Threats.Add("💻 Windows bajariladigan fayl");
            else if (ext is ".bat" or ".cmd" or ".ps1")
                r.Threats.Add("⌨️ Buyruq skripti");
        }
        else
            r.SafePoints.Add($"✅ Kengaytma odatda xavfsiz: `{ext}`");

        r.SafePoints.Add($"📏 Hajm: {FormatSize(r.Size)}");
    }

    private void CheckDoubleExtension(AnalysisResult r, string name)
    {
        foreach (var p in DoubleExtensionPatterns)
        {
            if (Regex.IsMatch(name, p, RegexOptions.IgnoreCase))
            {
                r.Threats.Add("🎭 IKKI KENGAYTMA HIYLASI! (masalan: rasm.jpg.apk)");
                break;
            }
        }
    }

    private void CheckUnicode(AnalysisResult r, string name)
    {
        char[] dangerous = { '\u202E', '\u200F', '\u200B' };
        if (name.Any(c => dangerous.Contains(c)))
            r.Threats.Add("🔄 RLO Unicode hujumi — fayl nomi aldatadi!");
    }

    private void CheckMagicBytes(AnalysisResult r, string name, byte[] bytes)
    {
        if (bytes.Length < 4) return;
        var ext = Path.GetExtension(name).ToLowerInvariant();
        foreach (var (format, magic) in MagicBytes)
        {
            if (bytes.Take(magic.Length).SequenceEqual(magic))
            {
                if (format == "EXE/DLL" && ext != ".exe" && ext != ".dll")
                    r.Threats.Add($"🔍 Fayl aslida EXE/DLL lekin `{ext}` ko'rinishida yashirilgan!");
                else
                    r.SafePoints.Add($"🔎 Ichki format: {format}");
                break;
            }
        }
    }

    private void CheckFraudName(AnalysisResult r, string name)
    {
        var lower = name.ToLowerInvariant();
        var ext = Path.GetExtension(name).ToLowerInvariant();
        foreach (var fraud in FraudNames)
        {
            if (lower.Contains(fraud) && DangerousExtensions.Contains(ext))
            {
                r.Threats.Add($"🏦 Taniqli nom suiiste'mol: '{fraud}' — RASMIY EMAS!");
                break;
            }
        }
    }

    private void CheckApkContent(AnalysisResult r, string name, byte[] bytes)
    {
        if (Path.GetExtension(name).ToLowerInvariant() is not (".apk" or ".xapk")) return;
        try
        {
            using var stream = new MemoryStream(bytes);
            using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
            var entries = zip.Entries.Select(e => e.FullName).ToList();

            if (!entries.Any(e => e.Equals("AndroidManifest.xml", StringComparison.OrdinalIgnoreCase)))
                r.Threats.Add("❌ AndroidManifest.xml yo'q — haqiqiy APK emas!");
            else
                r.SafePoints.Add("✅ AndroidManifest.xml mavjud");

            var bad = entries.Where(e => e.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).ToList();
            if (bad.Any()) r.Threats.Add($"☠️ APK ichida EXE fayl topildi!");
        }
        catch { r.Warnings.Add("⚠️ APK tarkibini o'qib bo'lmadi"); }
    }

    private void CheckZipContent(AnalysisResult r, string name, byte[] bytes)
    {
        if (Path.GetExtension(name).ToLowerInvariant() != ".zip") return;
        try
        {
            using var stream = new MemoryStream(bytes);
            using var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Read);
            var bad = zip.Entries.Where(e => DangerousExtensions.Contains(Path.GetExtension(e.Name).ToLowerInvariant())).ToList();
            if (bad.Any())
                r.Threats.Add($"📦 ZIP ichida xavfli fayllar: {string.Join(", ", bad.Take(3).Select(e => e.Name))}");
            else
                r.SafePoints.Add("✅ ZIP ichida xavfli fayllar topilmadi");
        }
        catch { }
    }

    private static RiskLevel CalcRisk(AnalysisResult r)
    {
        var score = r.Threats.Count * 25 + r.Warnings.Count * 10 - r.SafePoints.Count * 5;
        return score switch { <= 0 => RiskLevel.Safe, <= 15 => RiskLevel.Low, <= 40 => RiskLevel.Medium, <= 80 => RiskLevel.High, _ => RiskLevel.Critical };
    }

    private static string GenRecommendation(RiskLevel level) => level switch
    {
        RiskLevel.Safe => "✅ XAVFSIZ: Ochishingiz mumkin.",
        RiskLevel.Low => "🟡 PAST XAVF: Manbasini tekshiring.",
        RiskLevel.Medium => "🟠 O'RTA XAVF: Ehtiyot bo'ling!",
        RiskLevel.High => "🔴 YUQORI XAVF: Ochmang!",
        RiskLevel.Critical => "☠️ JUDA XAVFLI: Darhol o'chiring!",
        _ => "❓"
    };

    public static string ComputeSha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
    }

    private static string FormatSize(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024 * 1024) return $"{b / 1024.0:F1} KB";
        return $"{b / 1024.0 / 1024.0:F1} MB";
    }
}
