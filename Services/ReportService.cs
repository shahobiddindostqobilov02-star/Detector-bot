using System.Collections.Concurrent;
using FraudDetectorBot.Models;

namespace FraudDetectorBot.Services;

/// <summary>
/// Foydalanuvchi statistikasi va xabar berish xizmati.
/// Production'da SQLite yoki PostgreSQL ishlatish tavsiya etiladi.
/// </summary>
public class ReportService
{
    private readonly ConcurrentDictionary<long, UserStats> _userStats = new();
    private readonly List<(DateTime time, string fileName, RiskLevel risk, long userId)> _globalHistory = new();
    private readonly object _lock = new();

    public void RecordScan(long userId, string username, string fileName, RiskLevel risk)
    {
        _userStats.AddOrUpdate(userId,
            new UserStats
            {
                UserId = userId,
                Username = username,
                TotalFilesScanned = 1,
                ThreatsFound = risk >= RiskLevel.Medium ? 1 : 0,
                SafeFiles = risk < RiskLevel.Medium ? 1 : 0,
                LastActivity = DateTime.UtcNow
            },
            (_, existing) =>
            {
                existing.TotalFilesScanned++;
                existing.Username = username;
                if (risk >= RiskLevel.Medium) existing.ThreatsFound++;
                else existing.SafeFiles++;
                existing.LastActivity = DateTime.UtcNow;
                return existing;
            });

        lock (_lock)
        {
            _globalHistory.Add((DateTime.UtcNow, fileName, risk, userId));
            // Faqat oxirgi 1000 ta yozuvni saqlash
            if (_globalHistory.Count > 1000)
                _globalHistory.RemoveAt(0);
        }
    }

    public UserStats? GetUserStats(long userId)
    {
        return _userStats.TryGetValue(userId, out var stats) ? stats : null;
    }

    public string GetUserStatsMessage(long userId, string username)
    {
        var stats = GetUserStats(userId);
        if (stats == null)
            return "📊 Siz hali hech qanday fayl tekshirmadingiz.";

        var safePercent = stats.TotalFilesScanned > 0
            ? (stats.SafeFiles * 100.0 / stats.TotalFilesScanned)
            : 0;

        return $"""
        📊 *Sizning statistikangiz, {username}:*
        
        🔍 Jami tekshirilgan: *{stats.TotalFilesScanned}* ta fayl
        ✅ Xavfsiz fayllar: *{stats.SafeFiles}* ta
        🚨 Tahdid aniqlangan: *{stats.ThreatsFound}* ta
        📈 Xavfsizlik darajasi: *{safePercent:F0}%*
        🕐 Oxirgi faollik: {stats.LastActivity:dd.MM.yyyy HH:mm}
        """;
    }

    public string GetGlobalStats()
    {
        lock (_lock)
        {
            var total = _globalHistory.Count;
            var today = _globalHistory.Count(h => h.time.Date == DateTime.UtcNow.Date);
            var threats = _globalHistory.Count(h => h.risk >= RiskLevel.Medium);
            var criticals = _globalHistory.Count(h => h.risk == RiskLevel.Critical);

            return $"""
            🌐 *Bot umumiy statistikasi:*
            
            📁 Jami tekshirilgan: *{total}* ta fayl
            📅 Bugun: *{today}* ta
            🚨 Tahdid aniqlangan: *{threats}* ta
            ☠️ Kritik tahdidlar: *{criticals}* ta
            👥 Foydalanuvchilar: *{_userStats.Count}* ta
            """;
        }
    }

    public List<string> GetRecentThreats(int count = 5)
    {
        lock (_lock)
        {
            return _globalHistory
                .Where(h => h.risk >= RiskLevel.High)
                .OrderByDescending(h => h.time)
                .Take(count)
                .Select(h => $"🔴 `{h.fileName}` - {h.risk} ({h.time:HH:mm dd.MM})")
                .ToList();
        }
    }
}
