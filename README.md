# 🛡️ Firibgarlikni Aniqlash Boti

O'zbekistonda ommalashib ketgan firibgarlik fayllarini aniqlash uchun Telegram bot.

## 🎯 Nima qiladi?

- **APK fayllar** — "sut'dan" yuborilgan soxta Android ilovalar
- **EXE/BAT viruslari** — Windows tizimiga zarar beruvchi fayllar
- **Ikki kengaytma hiylasi** — `foto.jpg.apk` kabi aldamchi nomlar
- **Unicode RLO hujumi** — fayl nomini teskari ko'rsatish
- **Soxta brend nomlari** — UzCard, Click, Payme, Hamkorbank soxtalari
- **APK tarkib tahlili** — faylning ichida nima borligini tekshirish
- **VirusTotal integratsiyasi** — 70+ antivirus bilan tekshirish

---

## 🚀 O'rnatish

### 1. Talab qilinadigan dasturlar
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Telegram bot token (@BotFather dan oling)

### 2. Token sozlash

**Windows (CMD):**
```cmd
set TELEGRAM_BOT_TOKEN=123456789:ABCdef...
```

**Windows (PowerShell):**
```powershell
$env:TELEGRAM_BOT_TOKEN = "123456789:ABCdef..."
```

**Linux/Mac:**
```bash
export TELEGRAM_BOT_TOKEN="123456789:ABCdef..."
```

### 3. VirusTotal (ixtiyoriy, bepul)
- https://www.virustotal.com/gui/join-us saytida ro'yxatdan o'ting
- API kalitini oling va qo'shing:
```bash
export VIRUSTOTAL_API_KEY="sizning_api_kalitingiz"
```

### 4. Ishga tushirish
```bash
cd FraudDetectorBot
dotnet restore
dotnet run
```

---

## 📁 Loyiha tuzilmasi

```
FraudDetectorBot/
├── Program.cs                     # Asosiy kirish nuqtasi
├── FraudDetectorBot.csproj        # Loyiha fayli
├── Models/
│   └── AnalysisResult.cs          # Ma'lumotlar modeli
├── Services/
│   ├── BotHostedService.cs        # Bot ishga tushirish xizmati
│   ├── FileAnalysisService.cs     # Asosiy tahlil mantiq (eng muhim!)
│   ├── VirusTotalService.cs       # VirusTotal API integratsiyasi
│   └── ReportService.cs           # Statistika va hisobot
└── Handlers/
    └── MessageHandler.cs           # Telegram xabarlari
```

---

## 🔍 Aniqlash qobiliyatlari

| Hujum turi | Aniqlash | Xavf darajasi |
|------------|----------|---------------|
| .apk/.exe fayllar | ✅ | Yuqori |
| Ikki kengaytma | ✅ | Kritik |
| Unicode RLO | ✅ | Kritik |
| Magic bytes mismatch | ✅ | Yuqori |
| Soxta bank nomlari | ✅ | O'rta |
| APK tarkib tahlili | ✅ | Yuqori |
| ZIP ichida xavfli fayllar | ✅ | Yuqori |
| VirusTotal hash | ✅ (API bilan) | Yuqori |

---

## 🤖 Bot buyruqlari

| Buyruq | Vazifasi |
|--------|----------|
| `/start` | Botni ishga tushirish |
| `/help` | Yordam va ko'rsatmalar |
| `/stats` | Sizning statistikangiz |
| `/globalstats` | Umumiy bot statistikasi |
| `/threats` | Oxirgi aniqlangan tahdidlar |
| `/about` | Bot haqida ma'lumot |

---

## ⚠️ Muhim eslatmalar

1. **100% kafolat yo'q** — bot yordamchi vosita, professional antivirus emas
2. **Faylni dokument sifatida yuboring** — siqilmaslik uchun
3. **Production'da** SQLite/PostgreSQL ishlatish tavsiya etiladi
4. **VirusTotal limit** — bepul API: 4 so'rov/daqiqa

---

## 🔧 Kengaytirish g'oyalari

- [ ] SQLite ma'lumotlar bazasi
- [ ] Admin panel
- [ ] Guruh rejimi
- [ ] Fayl whitelist/blacklist
- [ ] Avtomatik yangilash
- [ ] Email/SMS ogohlantirish

---

## 📞 Yordam

Kiberjinoyatlar haqida xabar berish:
- **O'zbekiston:** 1102 (Ichki ishlar vazirligi)
- **VirusTotal:** https://www.virustotal.com
