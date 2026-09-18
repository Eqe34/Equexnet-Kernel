<div align="center">

# 🛡️ EquexNet Kernel

### Windows Kernel-Mode IDS/IPS — WFP Tabanlı Ağ Savunma Sürücüsü

*Windows Filtering Platform üzerinde çalışan, kernel seviyesinde gerçek zamanlı paket
analizi ve otomatik threat mitigation yapan savunma sürücüsü*

![C](https://img.shields.io/badge/C-11-A8B9CC?style=for-the-badge&logo=c&logoColor=white)
![Windows Kernel](https://img.shields.io/badge/Windows%20Kernel-Ring%200-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![WFP](https://img.shields.io/badge/WFP-Filtering%20Platform-4B8BBE?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge)

</div>

---

## ⚖️ YASAL UYARI (ÖNCE OKUYUN)

> ### 🚨 Bu bir Kernel-Mode Sürücüdür!
>
> Bu yazılım **Windows kernel (Ring 0)** seviyesinde çalışır. Yanlış kullanımda
> **mavi ekran (BSOD)**, sistem bütünlüğü sorunları veya daha ciddi hasarlar
> oluşabilir.
>
> - ✅ **İZİN VERİLEN:** Kendi sisteminizde, izole VM test ortamında, yetkili
>   savunma güvenliği araştırmalarında
> - ❌ **YASAK:** Başkasının sisteminde izinsiz kurulum, production ortamı,
>   zararlı yazılım entegrasyonu, izinsiz ağ gözetleme
>
> **Yetkisiz kullanım Türkiye'de 5237 sayılı TCK Madde 243-245 kapsamında
> suçtur.**
>
> Detaylar için [`LICENSE`](LICENSE.md) dosyasına bakın.

---

## 📌 Proje Hakkında

**EquexNet Kernel**, Windows Filtering Platform (WFP) üzerinde çalışan, **kernel
seviyesinde** (Ring 0) paket analizi yapan bir **savunma sürücüsüdür** (Blue Team
aracı). Gelen ağ trafiğini gerçek zamanlı olarak inceler; port tarama,
brute-force, ICMP flood ve web payload saldırılarını (SQLi, XSS, path traversal)
tespit eder; tespit edilen kaynak IP'leri **BFE (Base Filtering Engine)** üzerinden
otomatik olarak engeller.

Proje iki bileşenden oluşur:

1. **Kernel Driver** (`driver/`) — WFP callout + ring buffer + IP blacklist
2. **User-Mode Controller** (`controller/`) — Konsol arayüzü, istatistik, manuel
   komutlar

---

## ✨ Özellikler

### 🔍 Tespit Motoru (Kernel Mode)
- **Port tarama tespiti** — 10 saniyelik pencere içinde 15+ farklı porta SYN
- **Brute-force tespiti** — SSH/FTP/Telnet/RDP/SMB'de 30 saniyede 20+ deneme
- **ICMP flood** — 3 saniyede 80+ ICMP paketi
- **Malformed paket tespiti** — NULL scan, XMAS scan, SYN+FIN kombinasyonları
- **Web payload analizi** — SQL injection, XSS, path traversal imzaları

### 🛡️ Mitigation
- **Otomatik IP engelleme** — WFP filter üzerinden
- **Hash tabanlı blacklist** — 1024 bucket FNV-1a hash table
- **Maksimum 512 eşzamanlı bloklanmış IP**
- **Hit count takibi** — kaç paketin engellendiği kaydedilir

### ⚡ Performans
- **Lock-free ring buffer** — 256 entry, kernel→user asenkron aktarım
- **Mikrosaniye seviyesinde classify** — WFP callout içinde minimal iş
- **ExAcquireRundownProtection** — unload sırasında race condition koruması
- **Fail-open tasarım** — hata durumunda trafik bloklanmaz (güvenli taraf)

### 🎮 User-Mode Controller
- **ANSI renkli konsol arayüzü**
- **Klavye kısayolları** — `S` (stats), `B` (auto-block), `U` (unblock), `R`
  (reset), `Q` (quit)
- **BFE servis kontrolü** — sürücü başlamadan önce otomatik kontrol
- **Kernel istatistikleri** — packets, blocked, dropped, malformed
- **Log dosyası** — `equexnet_alerts.log` (zaman damgalı)

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER MODE (Ring 3)                          │
│                                                                     │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │  Controller (main.c)                                         │  │
│   │  • Konsol arayüzü                                            │  │
│   │  • Klavye kısayolları (S/B/U/R/Q)                            │  │
│   │  • İstatistik gösterimi                                      │  │
│   │  • Manuel IP block/unblock                                   │  │
│   └────────────────────────────┬─────────────────────────────────┘  │
│                                │                                    │
│                    DeviceIoControl (IOCTL_*)                        │
│                                │                                    │
└────────────────────────────────┼────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         KERNEL MODE (Ring 0)                        │
│                                                                     │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │  EquexNet Driver (equexnet_driver.c)                         │  │
│   │                                                              │  │
│   │  ┌────────────────┐    ┌────────────────┐   ┌─────────────┐  │  │
│   │  │  WFP Callout   │    │  IP Blacklist  │   │ Ring Buffer │  │  │
│   │  │  EquexClassify │───►│  1024-bucket   │   │  256 entry  │  │  │
│   │  │  (INBOUND_V4)  │    │  FNV-1a hash   │   │  lock-free  │  │  │
│   │  └────────┬───────┘    └────────────────┘   └─────────────┘  │  │
│   │           │                                                  │  │
│   │           │ Packet filter decision                          │  │
│   │           ▼                                                  │  │
│   │      PERMIT / BLOCK                                          │  │
│   └────────────────────────────┬─────────────────────────────────┘  │
│                                │                                    │
└────────────────────────────────┼────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │    Windows Network     │
                    │       Stack            │
                    └────────────────────────┘
```

### IoC (Indicators of Compromise) Tespit Akışı

```
Gelen Paket
    │
    ▼
┌─────────────────┐
│  WFP Callout    │◄── FWPS_LAYER_INBOUND_IPPACKET_V4
│  EquexClassify  │
└────────┬────────┘
         │
         ├─► Özel IP mi? (127.x, 224.x, 0.0.0.0) ──► PERMIT
         │
         ├─► Blacklist'te mi? ──► BLOCK + ABSORB
         │
         └─► Controller'a forward (ring buffer'a yaz)
                    │
                    ▼
            ┌───────────────┐
            │ User-Mode     │
            │ Analiz        │
            └───────┬───────┘
                    │
        ┌───────────┼───────────┬────────────┬─────────────┐
        ▼           ▼           ▼            ▼             ▼
   Port Scan   Brute Force   ICMP Flood   Malformed    Web Attack
        │           │           │            │             │
        └───────────┴───────────┴────────────┴─────────────┘
                                 │
                                 ▼
                          IOCTL_EQUEX_BLOCK_IP
                                 │
                                 ▼
                        Kernel Blacklist'e Ekle
```

---

## 🛠️ Derleme (Build)

### Gereksinimler

| Araç | Minimum Sürüm | Notlar |
|------|---------------|--------|
| **Windows** | 10 (1809+) / 11 | Kernel 1903+ önerilir |
| **Visual Studio** | 2022 | "Desktop development with C++" workload |
| **WDK** | 10.0.22621+ | [Windows Driver Kit](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk) |
| **SDK** | 10.0.22621+ | VS ile birlikte |
| **Test ortamı** | — | VM veya izole test makinesi **ZORUNLU** |

### Adım 1: WDK Kurulumu

1. [Visual Studio 2022 Community](https://visualstudio.microsoft.com/) indirin
2. Kurulum sırasında **"Desktop development with C++"** ve **"Windows Driver
   Kit (WDK)"** workload'larını işaretleyin
3. Kurulum sonrası doğrulama:

```cmd
where cl
where msbuild
where signtool
```

Üçü de sonuç dönmeli.

### Adım 2: User-Mode Controller Derleme

Developer Command Prompt'ta:

```cmd
cd controller
cl /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS ^
   /Fe:controller.exe ^
   main.c ^
   ws2_32.lib advapi32.lib
```

Ya da kök dizindeki `build-controller.bat` scriptini çalıştırın.

### Adım 3: Kernel Driver Derleme

**Kernel sürücüleri `cl.exe` ile doğrudan derlenemez.** Visual Studio'da
**Empty WDM Driver** projesi oluşturup `equexnet_driver.c`'yi içine ekleyin:

1. Visual Studio → **File → New → Project**
2. **"Empty WDM Driver"** (WDK şablonu) seçin
3. Proje adı: `EquexDriver`
4. `equexnet_driver.c` dosyasını projeye ekleyin
5. **Configuration:** `Release` + `x64`
6. **Build → Build Solution** (`Ctrl+Shift+B`)

Çıktı: `driver/x64/Release/EquexDriver.sys`

---

## 🧪 Test İmzalama (Test Signing)

Windows 10/11 x64'te imzasız sürücü **yüklenmez**. Test ortamında bunun için
**test imzalama modu** ve **test sertifikası** kullanılır.

### Adım 1: Test Sertifikası Oluşturun

**Yönetici olarak** Developer Command Prompt açın:

```cmd
cd driver\x64\Release

makecert -r -pe -ss PrivateCertStore -n "CN=EquexTest" EquexTest.cer

signtool sign /v /s PrivateCertStore /n EquexTest /t http://timestamp.digicert.com EquexDriver.sys

certutil -addstore Root EquexTest.cer
certutil -addstore TrustedPublisher EquexTest.cer
```

### Adım 2: Test Signing'i Aktif Edin

```cmd
bcdedit /set testsigning on
```

**Sistemi yeniden başlatın.** Masaüstünde sağ altta **"Test Modu"** yazısı
görünür.

> ⚠️ Test signing modunu **işiniz bittiğinde kapatmayı unutmayın:**
> ```cmd
> bcdedit /set testsigning off
> ```

---

## 🚀 Kurulum ve Kullanım

### Adım 1: Sürücüyü Yükleyin

**Yönetici** olarak CMD açın:

```cmd
sc create EquexNet type= kernel binPath= "C:\path\to\EquexDriver.sys"
sc start EquexNet
```

Doğrulama:

```cmd
sc query EquexNet
```

**Çıktı:**
```
SERVICE_NAME: EquexNet
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
```

### Adım 2: Controller'ı Çalıştırın

**Yönetici** olarak:

```cmd
controller.exe
```

Karşınıza şu çıktı gelecek:

```
=====================================================
 EQUEXNET ANALYZER v2.0 - STABLE KERNEL CONTROLLER
=====================================================
[+] BFE (Base Filtering Engine) calisiyor.
[+] Kernel driver handle acildi.
[+] WFP baslatildi.

Sistem aktif.
 [S] Kernel + controller istatistik
 [B] Auto block ac/kapa
 [U] Tum kernel blocklarini temizle
 [R] Kernel istatistiklerini sifirla
 [Q] Cikis
```

### Adım 3: Test Edin

Farklı bir terminalden **nmap** gibi bir araçla port taraması başlatın:

```cmd
nmap -sS -p 1-1000 192.168.1.34
```

Controller'ın çıktısında şunu görmelisiniz:

```
[ALARM] PORT SCAN: 192.168.1.34 (15 port)
[KERNEL BLOCK] 192.168.1.34
 Sebep: Port scan tespiti
```

### Klavye Kısayolları

| Tuş | İşlev |
|-----|-------|
| `S` | Kernel + controller istatistiklerini göster |
| `B` | Otomatik kernel block aç/kapa |
| `U` | Tüm kernel blocklarını temizle |
| `R` | Kernel istatistiklerini sıfırla |
| `Q` | Çıkış (temiz shutdown) |

### Adım 4: Kaldırma

```cmd
# Controller'ı kapat (Q tuşu)

# Sürücüyü durdur
sc stop EquexNet

# Sürücüyü sil
sc delete EquexNet
```

---

## 📁 Proje Yapısı

```
equexnet-kernel/
│
├── driver/                       # 🔧 KERNEL-MODE
│   ├── equexnet_driver.c         # Ana sürücü kodu (WFP + ring buffer + blacklist)
│   ├── equexnet.inf              # Kurulum bilgisi (WDK build için)
│   └── EquexDriver.vcxproj       # Visual Studio projesi
│
├── controller/                   # 🎮 USER-MODE
│   └── main.c                    # Konsol controller
│
├── docs/
│   ├── ARCHITECTURE.md           # Detaylı mimari dokümantasyonu
│   └── screenshots/
│       ├── controller-running.png
│       ├── kernel-block.png
│       └── debugview-output.png
│
├── build-controller.bat          # Controller derleme scripti
├── install-driver.bat            # Sürücü kurulum scripti (test imzalama)
├── .gitignore                    # Build çıktılarını engeller
├── LICENSE.md                    # Eğitim amaçlı lisans
└── README.md                     # Bu dosya
```

---

## 🔧 Teknik Detaylar

### IOCTL Arayüzü

| IOCTL | Kod | Açıklama |
|-------|-----|----------|
| `IOCTL_EQUEX_GET_PACKET` | `0x800` | Ring buffer'dan paket oku |
| `IOCTL_EQUEX_BLOCK_IP` | `0x801` | IP'yi blacklist'e ekle |
| `IOCTL_EQUEX_UNBLOCK_IP` | `0x802` | IP'yi blacklist'ten çıkar |
| `IOCTL_EQUEX_START_WFP` | `0x803` | WFP engine başlat |
| `IOCTL_EQUEX_STOP_WFP` | `0x804` | WFP engine durdur |
| `IOCTL_EQUEX_GET_STATS` | `0x805` | Kernel istatistikleri |
| `IOCTL_EQUEX_CLEAR_STATS` | `0x806` | İstatistikleri sıfırla |

### WFP Katmanı

- **Layer:** `FWPS_LAYER_INBOUND_IPPACKET_V4`
- **Action:** `FWP_ACTION_CALLOUT_TERMINATING`
- **Sublayer weight:** `0xFFFF` (en yüksek öncelik)
- **Filter flag:** `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`

### Blacklist Hash Tablosu

```c
hashIndex = FNV1a(ipAddress) & 0x3FF;  // 1024 bucket
```

- **Hash fonksiyonu:** FNV-1a 32-bit
- **Collision handling:** Chained list
- **Bucket count:** 1024
- **Max entry:** 512 IP

### Ring Buffer

- **Boyut:** 256 entry × 2048 byte = ~512 KB
- **Tür:** Lock-free single-producer single-consumer
- **Senkronizasyon:** `KSPIN_LOCK` + `KeMemoryBarrier`
- **Overflow:** `DroppedPackets` sayacı artırılır

### Tespit Eşikleri

| Saldırı Tipi | Eşik | Pencere |
|--------------|------|---------|
| Port Scan | 15 port | 10 sn |
| Brute Force | 20 deneme | 30 sn |
| ICMP Flood | 80 paket | 3 sn |

### Lifecycle Koruması

- **`ExInitializeRundownProtection`** — classify callback'leri için
- **`ExWaitForRundownProtectionRelease`** — unload sırasında aktif callback'leri
  bekler
- **`FastMutex`** — WFP init/cleanup atomikliği

---

## ⚠️ Bilinen Sınırlamalar

- 🚧 **Paket yakalama** şu an devre dışı (`EQUEX_ENABLE_PACKET_CAPTURE = 0`) —
  WFP lifecycle stabilitesi doğrulandıktan sonra aktif edilecek
- 🚧 **Sadece IPv4** destekleniyor (`INBOUND_IPPACKET_V4`)
- 🚧 **Sadece INBOUND katmanı** — outbound filtering yok
- 🚧 **Test imzalı** — production dağıtım için EV sertifikası gerekir
- 🚧 **Imza tabanlı** payload tespiti — heuristic/ML yok

---

## 🧪 Test Ortamı

Proje aşağıdaki ortamlarda test edilmiştir:

- ✅ Windows 10 22H2 (x64, VM)
- ✅ Windows 11 23H2 (x64, VM)
- ✅ VMware Workstation 17 + Hyper-V
- ✅ WDK 10.0.22621, MSVC 2022 v17.14

---

## 🚧 Yol Haritası

- [x] WFP callout entegrasyonu
- [x] Ring buffer (lock-free)
- [x] FNV-1a hash blacklist
- [x] Port scan / brute-force / ICMP flood tespiti
- [x] Web payload analizi (SQLi/XSS/path traversal)
- [x] Rundown protection ile safe unload
- [ ] Paket yakalamayı aktif et (MDL chain)
- [ ] IPv6 desteği (`INBOUND_IPPACKET_V6`)
- [ ] Outbound filtering
- [ ] GeoIP bazlı otomatik block
- [ ] SIEM entegrasyonu (Syslog/CEF export)
- [ ] ETW (Event Tracing for Windows) çıktı
- [ ] ETW-based real-time event feed

---

## 📸 Ekran Görüntüleri

### Controller Çalışırken

![Controller Running](docs/screenshots/controller-running.png)

### Kernel Block Alarmı

![Kernel Block](docs/screenshots/kernel-block.png)

### DebugView Kernel Çıktısı

![DebugView](docs/screenshots/debugview-output.png)

---

## 🤝 Katkıda Bulunma

Bu proje kişisel bir portfolyo projesidir. Öneri ve geri bildirim için:

- 📧 E-posta: **software@sametkok.info**
- 🐛 Issue: [GitHub Issues](https://github.com/Eqe34/equexnet-kernel/issues)
- 🔒 Güvenlik açıkları: Lütfen **private** kanaldan bildirin

**Kod katkısı kabul edilir**, ancak:

1. WDK ile derlenebilir olmalı
2. Test imzalama modunda BSOD üretmemeli
3. Kernel-mode kod olduğu için **code review zorunludur**

---

## 📜 Lisans

**Educational Use License** — Detaylar için [`LICENSE.md`](LICENSE.md) dosyasına
bakın.

> ⚠️ Ticari kullanım, production ortamında kurulum ve izinsiz ağlarda kullanım
> **yasaktır**.

---

## 👨‍💻 Geliştirici

<div align="center">

**Samet KÖK**

Bilgisayar Programcılığı (Okul Birincisi)  
Tokat Gaziosmanpaşa Üniversitesi — Erbaa MYO

[![Portfolyo](https://img.shields.io/badge/Portfolyo-sametkok.com-blue?style=flat-square)](https://sametkok.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Samet%20KÖK-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/samet-k%C3%B6k-0624ba354/)
[![GitHub](https://img.shields.io/badge/GitHub-Eqe34-181717?style=flat-square&logo=github)](https://github.com/Eqe34)

</div>

---

<div align="center">

### ⭐ Bu proje işinize yaradıysa yıldız vermeyi unutmayın!

**Sorumlu güvenlik araştırması yapın. 🛡️**

</div>
