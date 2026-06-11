using System.Collections.Concurrent;
using DetectorBotV2.Models;

namespace DetectorBotV2.Services;

public class DatabaseService
{
    private readonly ConcurrentDictionary<long, UserData> _users = new();
    private readonly List<(DateTime time, string target, string type, RiskLevel risk, long userId)> _history = new();
    private readonly object _lock = new();

    // ==================== FOYDALANUVCHILAR ====================
    public UserData GetOrCreateUser(long userId, string username, string firstName)
    {
        return _users.AddOrUpdate(userId,
            new UserData { UserId = userId, Username = username, FirstName = firstName },
            (_, existing) =>
            {
                existing.Username = username;
                existing.FirstName = firstName;
                existing.LastActivity = DateTime.UtcNow;
                return existing;
            });
    }

    public void RecordScan(long userId, string username, string firstName, string target, string type, RiskLevel risk)
    {
        var user = GetOrCreateUser(userId, username, firstName);
        user.TotalScans++;
        user.LastActivity = DateTime.UtcNow;
        if (risk >= RiskLevel.Medium) user.ThreatsFound++;
        else user.SafeCount++;

        lock (_lock)
        {
            _history.Add((DateTime.UtcNow, target, type, risk, userId));
            if (_history.Count > 5000) _history.RemoveAt(0);
        }
    }

    public bool BanUser(long userId)
    {
        if (_users.TryGetValue(userId, out var user))
        {
            user.IsBanned = true;
            return true;
        }
        return false;
    }

    public bool UnbanUser(long userId)
    {
        if (_users.TryGetValue(userId, out var user))
        {
            user.IsBanned = false;
            return true;
        }
        return false;
    }

    public bool IsUserBanned(long userId)
    {
        return _users.TryGetValue(userId, out var user) && user.IsBanned;
    }

    public UserData? GetUser(long userId) =>
        _users.TryGetValue(userId, out var user) ? user : null;

    public List<UserData> GetAllUsers() => _users.Values.ToList();

    // ==================== STATISTIKA ====================
    public BotStats GetGlobalStats()
    {
        lock (_lock)
        {
            var today = _history.Where(h => h.time.Date == DateTime.UtcNow.Date).ToList();
            return new BotStats
            {
                TotalUsers = _users.Count,
                TotalScans = _history.Count,
                TotalThreats = _history.Count(h => h.risk >= RiskLevel.Medium),
                ActiveToday = today.Select(h => h.userId).Distinct().Count()
            };
        }
    }

    public string GetUserStatsText(long userId)
    {
        var user = GetUser(userId);
        if (user == null) return "📊 Siz hali hech narsa tekshirmadingiz.";

        var safePercent = user.TotalScans > 0 ? (user.SafeCount * 100.0 / user.TotalScans) : 0;
        return $"""
        📊 *Sizning statistikangiz:*
        
        🔍 Jami tekshirilgan: *{user.TotalScans}* ta
        ✅ Xavfsiz: *{user.SafeCount}* ta
        🚨 Tahdid topilgan: *{user.ThreatsFound}* ta
        📈 Xavfsizlik: *{safePercent:F0}%*
        📅 Ro'yxatdan: {user.RegisteredAt:dd.MM.yyyy}
        🕐 Oxirgi faollik: {user.LastActivity:dd.MM.yyyy HH:mm}
        """;
    }

    public List<string> GetRecentThreats(int count = 5)
    {
        lock (_lock)
        {
            return _history
                .Where(h => h.risk >= RiskLevel.High)
                .OrderByDescending(h => h.time)
                .Take(count)
                .Select(h => $"🔴 `{TruncateTarget(h.target)}` [{h.type}] — {h.risk} ({h.time:HH:mm dd.MM})")
                .ToList();
        }
    }

    public List<UserData> GetTopUsers(int count = 10)
    {
        return _users.Values
            .OrderByDescending(u => u.TotalScans)
            .Take(count)
            .ToList();
    }

    private static string TruncateTarget(string target) =>
        target.Length > 30 ? target[..27] + "..." : target;
}
