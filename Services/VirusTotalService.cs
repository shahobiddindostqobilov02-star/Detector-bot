using System.Net.Http.Headers;
using System.Text.Json;
using FraudDetectorBot.Models;

namespace FraudDetectorBot.Services;

/// <summary>
/// VirusTotal API bilan integratsiya.
/// Bepul API: https://www.virustotal.com/gui/join-us
/// 4 ta so'rov/daqiqa bepul limitiga ega.
/// </summary>
public class VirusTotalService
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private readonly SemaphoreSlim _rateLimiter = new(1, 1);
    private DateTime _lastRequestTime = DateTime.MinValue;

    public VirusTotalService()
    {
        _apiKey = Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY");
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/"),
            Timeout = TimeSpan.FromSeconds(30)
        };

        if (!string.IsNullOrEmpty(_apiKey))
        {
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
        }
    }

    public bool IsAvailable => !string.IsNullOrEmpty(_apiKey);

    /// <summary>
    /// SHA256 hash bo'yicha VirusTotal'da tekshirish
    /// </summary>
    public async Task<(bool found, int detections, int total)> CheckHashAsync(string sha256Hash)
    {
        if (!IsAvailable) return (false, 0, 0);

        await RateLimitAsync();

        try
        {
            var response = await _httpClient.GetAsync($"files/{sha256Hash}");

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return (false, 0, 0);

            if (!response.IsSuccessStatusCode)
                return (false, 0, 0);

            var content = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(content);

            var stats = doc.RootElement
                .GetProperty("data")
                .GetProperty("attributes")
                .GetProperty("last_analysis_stats");

            var malicious = stats.GetProperty("malicious").GetInt32();
            var suspicious = stats.GetProperty("suspicious").GetInt32();
            var totalEngines = malicious + suspicious +
                               stats.GetProperty("harmless").GetInt32() +
                               stats.GetProperty("undetected").GetInt32();

            return (true, malicious + suspicious, totalEngines);
        }
        catch
        {
            return (false, 0, 0);
        }
    }

    /// <summary>
    /// Faylni VirusTotal'ga yuborish (kichik fayllar uchun)
    /// </summary>
    public async Task<string?> UploadFileAsync(byte[] fileBytes, string fileName)
    {
        if (!IsAvailable || fileBytes.Length > 32 * 1024 * 1024) return null; // 32MB limit

        await RateLimitAsync();

        try
        {
            using var content = new MultipartFormDataContent();
            using var fileContent = new ByteArrayContent(fileBytes);
            fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
            content.Add(fileContent, "file", fileName);

            var response = await _httpClient.PostAsync("files", content);
            if (!response.IsSuccessStatusCode) return null;

            var responseContent = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseContent);

            return doc.RootElement.GetProperty("data").GetProperty("id").GetString();
        }
        catch
        {
            return null;
        }
    }

    private async Task RateLimitAsync()
    {
        await _rateLimiter.WaitAsync();
        try
        {
            var elapsed = DateTime.UtcNow - _lastRequestTime;
            if (elapsed.TotalSeconds < 15) // 4 so'rov/daqiqa = har 15 soniyada 1 ta
            {
                await Task.Delay(TimeSpan.FromSeconds(15) - elapsed);
            }
            _lastRequestTime = DateTime.UtcNow;
        }
        finally
        {
            _rateLimiter.Release();
        }
    }
}
