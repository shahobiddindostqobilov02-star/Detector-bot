namespace FraudDetectorBot.Models;

public enum RiskLevel
{
    Safe,       // Xavfsiz
    Low,        // Past xavf
    Medium,     // O'rta xavf
    High,       // Yuqori xavf
    Critical    // Juda xavfli - OCHMA!
}

public class FileAnalysisResult
{
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public string FileExtension { get; set; } = "";
    public RiskLevel RiskLevel { get; set; }
    public List<string> DetectedThreats { get; set; } = new();
    public List<string> SuspiciousIndicators { get; set; } = new();
    public List<string> SafeIndicators { get; set; } = new();
    public string Recommendation { get; set; } = "";
    public string DetailedExplanation { get; set; } = "";
    public bool IsDoubleExtension { get; set; }
    public bool IsMasquerading { get; set; }
    public string? Sha256Hash { get; set; }
    public bool VirusTotalChecked { get; set; }
    public int? VirusTotalDetections { get; set; }
    public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;
}

public class UserStats
{
    public long UserId { get; set; }
    public string Username { get; set; } = "";
    public int TotalFilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public int SafeFiles { get; set; }
    public DateTime LastActivity { get; set; }
}

public class SuspiciousPattern
{
    public string Pattern { get; set; } = "";
    public string Description { get; set; } = "";
    public RiskLevel RiskLevel { get; set; }
}
