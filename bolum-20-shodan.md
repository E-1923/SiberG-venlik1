
# Bölüm 20: Shodan – Webcam, IoT, Servis vb. Arama Motoru

## 🔍 Shodan Nedir?

Shodan, internete bağlı cihazları ve servisleri tarayan bir arama motorudur.

### Tarayabildiği Cihazlar

- Web sunucuları
- Güvenlik kameraları (IP, CCTV)
- Akıllı ev cihazları (IoT)
- SCADA sistemleri
- Açık veritabanları
- RDP / SSH erişimi açık sunucular

---

## 📌 Shodan’ın Temel Özellikleri

### 1️⃣ Açık Port ve Servis Tespiti

| Port | Servis | Açıklama |
|------|--------|----------|
| 21   | FTP    | Anonim FTP sunucuları |
| 22   | SSH    | SSH açık sistemler |
| 80   | HTTP   | Web sunucuları |
| 443  | HTTPS  | SSL analizleri |
| 3306 | MySQL  | Açık veritabanları |
| 3389 | RDP    | Uzak masaüstü sistemleri |

```bash
shodan search "port:22 country:TR"
shodan search "product:Apache country:DE"
```

### 2️⃣ Zayıf Şifreli Sistemleri Bulma

```bash
shodan search "default password"
shodan search "Server: SQ-WEBCAM"
```

### 3️⃣ Açık Veritabanları

```bash
shodan search "MongoDB Server Information port:27017"
shodan search "product:MySQL country:US"
```

### 4️⃣ SCADA Sistemleri

```bash
shodan search "port:502 product:modbus"
shodan search "SCADA"
```

---

## ⚙️ Shodan Kullanımı

### Web Arayüzü

🔗 https://www.shodan.io

### CLI ile Kullanım

```bash
pip install shodan
shodan init API_KEY
```

#### Komut Örnekleri

```bash
shodan host 8.8.8.8
shodan search "port:3389 country:TR"
shodan search "ssl"
```

---

## 🎦 Açık IP Kameraları Tespit Etme

```bash
shodan search "port:554 product:webcam"
shodan search "port:80 product:IP Camera"
```

### Güvenlik Önerileri

- Varsayılan şifreleri değiştirin
- VPN/güvenlik duvarı ile koruyun

---

## 🔎 Shodan Filtreleri

### Filtreleme Örnekleri

```bash
port:80
country:TR
city:Istanbul
net:192.168.1.0/24
org:TurkTelekom
hostname:*.edu.tr
os:Linux
product:Apache
product:MySQL version:5.7
```

### Filtreleri Kombinlemek

```bash
port:22 country:TR
port:80 city:Istanbul product:Apache
```

---

## 🔐 Zafiyet Tespiti

### CVE ile Arama

```bash
shodan search "vuln:CVE-2023-0669"
shodan search "product:Microsoft IIS" vuln:*
```

### Varsayılan Şifreli Cihazlar

```bash
shodan search "admin:admin" port:23
shodan search "root:root" port:22
```

### Exploit Edilebilir Servisler

```bash
shodan search "port:445 os:windows"     # EternalBlue
shodan search "port:3389 has_screenshot:true" # BlueKeep
```

---

## 💻 Gelişmiş CLI Komutları

### JSON Formatında Servis Alma

```bash
shodan search --fields ip_str,port,org,hostnames "port:443" --limit 10
```

### Sonuçları Dosyaya Kaydetme

```bash
shodan search "port:3306" --limit 100 > mysql_servers.txt
```

---

## ✅ Özet

- IP, port, cihaz, servis, ülke ve şehir filtrele
- CVE ve sürüm bazlı zafiyet taraması yap
- CLI ile otomasyon ve JSON çıktılar
- Shodan’ı güvenlik testleri ve keşif amaçlı kullan

