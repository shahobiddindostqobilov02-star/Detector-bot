namespace DetectorBotV2.Models;

public enum RiskLevel { Safe, Low, Medium, High, Critical }

public class AnalysisResult
{
    public string Target { get; set; } = "";
    public string Type { get; set; } = ""; // FILE, URL, PHONE, USERNAME
    public RiskLevel RiskLevel { get; set; }
    public List<string> Threats { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> SafePoints { get; set; } = new();
    public string Recommendation { get; set; } = "";
    public string? Hash { get; set; }
    public long Size { get; set; }
    public bool VirusTotalChecked { get; set; }
    public int? VTDetections { get; set; }
    public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;
}

public class UserData
{
    public long UserId { get; set; }
    public string Username { get; set; } = "";
    public string FirstName { get; set; } = "";
    public int TotalScans { get; set; }
    public int ThreatsFound { get; set; }
    public int SafeCount { get; set; }
    public bool IsBanned { get; set; }
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;
    public DateTime LastActivity { get; set; } = DateTime.UtcNow;
}

public class BotStats
{
    public int TotalUsers { get; set; }
    public int TotalScans { get; set; }
    public int TotalThreats { get; set; }
    public int ActiveToday { get; set; }
}
