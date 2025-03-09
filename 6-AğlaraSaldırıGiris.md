# 💻 Network Penetration (Ağ Sızma Testi) Nedir?
Network Penetration Testing (Ağ Sızma Testi), bir sistemin veya ağın güvenlik açıklarını tespit etmek için yapılan kontrollü saldırı simülasyonudur. Siber güvenlik uzmanları, bu testleri gerçekleştirerek güvenlik açıklarını keşfeder ve kötü niyetli saldırganlardan önce düzeltmelerin yapılmasını sağlar.

## 🔹 1️⃣ Network Penetration Testinin Amacı
- ✅ Ağ sistemlerindeki güvenlik açıklarını belirlemek
- ✅ Yetkisiz erişim yollarını test etmek
- ✅ Firewall, IDS/IPS gibi güvenlik sistemlerinin dayanıklılığını ölçmek
- ✅ DDoS ve MITM gibi saldırılara karşı sistemin savunmasını incelemek
- ✅ Sızma yollarını belirleyerek sistem yöneticilerine rapor sunmak

## 🔹 2️⃣ Network Penetration Testi Adımları
Bir ağ sızma testi genellikle 5 aşamadan oluşur:

### 1️⃣ Keşif (Reconnaissance & OSINT)
- Hedef sistem hakkında açık kaynak istihbarat (OSINT) toplanır.
- WHOIS sorguları, Shodan, Netcraft, Google Dorking gibi teknikler kullanılır.

### 2️⃣ Tarama (Scanning)
- Ağda açık portlar ve servisler belirlenir.
- **Kullanılan araçlar:**
  - `Nmap` (Port tarama)
  - `Netcat` (Ağ bağlantı testi)
  - `Masscan` (Hızlı port tarama)

### 3️⃣ Güvenlik Açığı Tespiti (Vulnerability Analysis)
- Sistemlerin zafiyetleri tespit edilir.
- **Kullanılan araçlar:**
  - `Nessus`, `OpenVAS`, `Nikto`, `Wapiti`

### 4️⃣ Sızma (Exploitation)
- Güvenlik açıkları aktif olarak sömürülerek sisteme sızılmaya çalışılır.
- **Kullanılan araçlar:**
  - `Metasploit` (Zafiyet sömürme aracı)
  - `SQLmap` (Veritabanı saldırıları için)
  - `Hydra`, `John the Ripper` (Brute-force saldırıları)

### 5️⃣ Raporlama ve Güvenlik Önlemleri
- Test sonuçları raporlanır ve düzeltme önerileri sunulur.
- Ağ yöneticileri, sistemdeki güvenlik açıklarını kapatarak saldırılara karşı korunma sağlar.

## 🔹 3️⃣ Network Penetration Testi Türleri
- 🟢 **Black Box Test:** Hiçbir bilgi verilmeden, hacker gibi dışarıdan saldırı senaryosu oluşturulur.
- 🟡 **Gray Box Test:** Saldırgana kısmi erişim veya kullanıcı bilgileri sağlanır.
- 🔴 **White Box Test:** Tüm sistem bilgileri sağlanarak iç tehditleri test etmek için yapılır.

## 🔹 4️⃣ Kullanılan Araçlar
### 🛠 Ağ Keşfi & Tarama:
- `Nmap` (Ağ haritalama ve port tarama)
- `Wireshark` (Paket analiz aracı)
- `Shodan` (İnternete açık sistemleri taramak için)

### 🛠 Güvenlik Açığı Analizi:
- `Nessus`, `OpenVAS` (Ağ güvenlik açıklarını tespit etmek için)
- `Nikto` (Web sunucu güvenlik açıklarını analiz etmek için)

### 🛠 Sızma Araçları:
- `Metasploit` (Zafiyetleri sömürmek için)
- `Hydra`, `Medusa` (Brute-force saldırıları için)
- `SQLmap` (SQL Injection testleri için)

## 📌 Özet
- ✅ Network Penetration Testing, sistem ve ağ güvenlik açıklarını tespit etmek için yapılan etik hackleme testidir.
- ✅ Keşif, tarama, analiz, sömürü ve raporlama aşamalarını içerir.
- ✅ `Nmap`, `Metasploit`, `Wireshark`, `Hydra` gibi araçlar kullanılır.
- ✅ Şirketler ve kurumlar, sızma testlerini düzenli olarak yaptırarak güvenliklerini güçlendirmelidir.

---

# 🔹 MAC Adresi Nedir?
**MAC (Media Access Control) adresi**, bir cihazın ağ arayüz kartına (Ethernet veya Wi-Fi) üretici tarafından atanan benzersiz bir kimlik numarasıdır.
- 📌 Her ağ kartının kendine özel bir MAC adresi vardır ve bu adres değiştirilemez (fakat yazılımsal olarak sahte MAC oluşturulabilir).

## 📌 1️⃣ MAC Adresi Formatı
- MAC adresi **48 bit uzunluğunda olup 12 karakter** (6 çift hexadecimal sayı) ile gösterilir.
- **Örnek MAC adresleri:**
  - `00:1A:2B:3C:4D:5E`
  - `00-1A-2B-3C-4D-5E`
  - `001A.2B3C.4D5E`

- 📌 **İlk 6 hane:** Üretici firmasını gösterir (Organizationally Unique Identifier - OUI).
- 📌 **Son 6 hane:** Cihaza özel olarak atanmış benzersiz bir numaradır.

✅ **Örnek Üreticiler:**
- `00:1A:2B → Cisco`
- `34:DE:1A → Apple`
- `A4:B1:C1 → Intel`

🔍 **MAC adresinin üreticisini öğrenmek için:**
- 🔗 [https://macvendors.com/](https://macvendors.com/)
## 📌 2️⃣ MAC Adresi Nerede Kullanılır?

### ✅ Yerel Ağ İletişimi (LAN/WLAN):
- MAC adresleri yalnızca yerel ağ içinde kullanılır.
- Bir cihaz başka bir cihazla aynı ağda iletişim kurarken IP yerine MAC adresini kullanır.

### ✅ ARP Protokolü:
- IP adresini MAC adresine dönüştürmek için ARP (Address Resolution Protocol) kullanılır.

### ✅ Ağ Güvenliği & Filtreleme:
- MAC adresine dayalı erişim kontrolü (MAC Filtering) ile belirli cihazlar engellenebilir veya ağlara izin verilebilir.

### ✅ Ağ İzleme & Penetrasyon Testleri:
- Wireshark gibi analiz araçları MAC adreslerini kullanarak ağ trafiğini inceleyebilir.

### ✅ İnternet Servis Sağlayıcıları (ISP):
- Bazı internet sağlayıcıları kullanıcıları MAC adresiyle tanımlayabilir.

---

## 📌 3️⃣ MAC Adresi Nasıl Öğrenilir?

### 💻 Windows:
**Komut İstemi'ni (CMD) aç ve şu komutu yaz:**
```bash
ipconfig /all
```
- "Fiziksel Adres" olarak gösterilir.

### 🐧 Linux / macOS:
**Terminalde şu komutu çalıştır:**
```bash
ifconfig
```
veya
```bash
ip link show
```
- Wi-Fi & Ethernet adaptörlerinin MAC adreslerini listeler.

---

## 📌 4️⃣ MAC Adresi Değiştirilebilir mi?
Evet, MAC adresi yazılımsal olarak sahte (spoof) hale getirilebilir, ancak cihazın orijinal MAC adresi fiziksel olarak değiştirilemez.

### 🛠️ Linux’ta MAC Adresi Değiştirme:
```bash
sudo ifconfig wlan0 down
sudo macchanger -r wlan0  # Rastgele MAC atar
sudo ifconfig wlan0 up
```
> **Not:** `wlan0` kablosuz ağ adaptörü içindir, kendi arayüz ismini öğrenmek için `ifconfig` veya `ip a` komutunu kullanabilirsin.

---

## 📌 5️⃣ MAC vs IP Adresi Farkı

| **Özellik**  | **MAC Adresi** | **IP Adresi** |
|-------------|--------------|--------------|
| **Tanım**  | Cihazın ağ kartına özel kimlik numarası | Cihazın ağ üzerindeki adresi |
| **Değişebilir mi?**  | Donanımsal olarak sabit ama yazılımsal olarak değiştirilebilir | Dinamik veya statik olarak değişebilir |
| **Kapsam**  | Sadece yerel ağ içinde geçerlidir | İnternet ve LAN’da kullanılır |
| **Kullanım Alanı**  | Yerel ağ iletişimi (LAN, WLAN) | Cihazlar arası geniş ağ iletişimi (WAN, İnternet) |

---

## 📌 Özet
✅ MAC adresi, ağ kartına özgü 48 bit uzunluğunda benzersiz bir adrestir.
✅ Cihazların yerel ağda iletişim kurmasını sağlar (IP’ye gerek olmadan).
✅ Wireshark, Nmap, ARP gibi araçlarla tespit edilebilir.
✅ MAC adresi yazılımsal olarak değiştirilebilir (spoofing), ancak fiziksel olarak değiştirilemez.

---

## 📡 Monitor ve Managed Modları Nedir?

Wi-Fi ağ kartları, iki farklı çalışma modu kullanır:
1️⃣ **Managed Mode (Yönetimli Mod)**
2️⃣ **Monitor Mode (İzleme Modu)**

Bu modlar, bir kablosuz ağ kartının veri iletimini ve alımını nasıl yönettiğini belirler.

### 1️⃣ Managed Mode (Yönetimli Mod) 🏠
📌 Günlük olarak kullandığımız moddur ve Wi-Fi ağına bağlanmak için kullanılır.

✅ **Ne yapar?**
- Kablosuz erişim noktasına (AP) bağlanır.
- Sadece kendisine yönlendirilmiş paketleri alır (Diğer cihazların trafiğini göremez).
- İnternete erişim sağlar ve veri iletimi yapar.

✅ **Ne zaman kullanılır?**
- Normal Wi-Fi bağlantılarında (örneğin, evde veya kafede Wi-Fi'ye bağlanırken).

---

### 2️⃣ Monitor Mode (İzleme Modu) 🔎
📌 Kablosuz ağ kartının tüm trafiği görebilmesini sağlayan özel bir moddur.

✅ **Ne yapar?**
- Hedef Wi-Fi ağına bağlanmadan havadaki tüm kablosuz paketleri yakalar.
- Şifrelenmemiş ağların trafiğini analiz edebilir.
- Paket analiz araçlarıyla (Wireshark, airodump-ng) kullanılabilir.

✅ **Ne zaman kullanılır?**
- Ağ güvenlik testleri (Pentest, Sniffing, Packet Capture) için.
- Kablosuz ağ trafiğini izlemek için (Wireshark, tcpdump gibi araçlarla).

> **❗ Not:**
> - Tüm Wi-Fi kartları monitor modunu desteklemez.
> - Şifreli ağların paketlerini görmek için ek olarak şifre kırma işlemi gereklidir.

---

## 📌 Monitor Mode Nasıl Açılır? (Linux - Aircrack-ng Kullanımı)

1️⃣ **Wi-Fi kartını kapat**
```bash
sudo ifconfig wlan0 down
```
2️⃣ **Monitor Mode’a al**
```bash
sudo iwconfig wlan0 mode monitor
```
3️⃣ **Wi-Fi kartını tekrar aç**
```bash
sudo ifconfig wlan0 up
```
💡 **Alternatif:**
Aircrack-ng paketi içindeki `airmon-ng` komutu da kullanılabilir:
```bash
sudo airmon-ng start wlan0
```

---

## 📌 Managed vs Monitor Mode Karşılaştırması

| **Özellik**  | **Managed Mode** | **Monitor Mode** |
|-------------|---------------|--------------|
| **Bağlantı**  | Erişim noktasına bağlanır | Ağa bağlanmadan veri dinler |
| **Paket Alımı**  | Sadece kendi verilerini alır | Tüm kablosuz trafiği yakalar |
| **Kullanım Alanı**  | Günlük Wi-Fi bağlantıları | Ağ güvenliği ve analiz |
| **Gereksinim**  | Standart Wi-Fi kartı yeterli | Monitor mod destekli Wi-Fi kartı gerekir |
| **Araçlar**  | Normal internet kullanımı | Wireshark, Airodump-ng, Kismet |

---

## 📌 Özet
✅ **Managed Mode**, normal Wi-Fi bağlantıları için kullanılır.
✅ **Monitor Mode**, kablosuz ağ trafiğini analiz etmek için kullanılır.
✅ **Monitor Mode**, penetrasyon testlerinde ve ağ güvenliği analizlerinde kullanılır.

