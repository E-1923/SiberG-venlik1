
# 📚 Bölüm 28: Network Teorisi

---

## 📌 OSI Modeli Nedir?

OSI (Open Systems Interconnection) modeli, farklı bilgisayar sistemlerinin birbiriyle iletişim kurmasını sağlamak için oluşturulmuş katmanlı bir ağ modelidir. ISO (International Organization for Standardization) tarafından geliştirilmiştir ve 7 katmandan oluşur.

### 📜 OSI Katmanları

| Katman | Adı                   | Görevi                                            | Örnek Protokoller / Cihazlar                   |
|--------|------------------------|--------------------------------------------------|------------------------------------------------|
| 7      | Uygulama (Application) | Kullanıcıya en yakın katmandır.                  | HTTP, FTP, DNS, SMTP, POP3                     |
| 6      | Sunum (Presentation)   | Veriyi sıkıştırır, şifreler, formatlar.          | SSL/TLS, JPEG, MP3, ASCII                      |
| 5      | Oturum (Session)       | Bağlantıyı başlatır, yönetir, sonlandırır.       | NetBIOS, SQL, SSH                              |
| 4      | Taşıma (Transport)     | Uçtan uca veri aktarımı sağlar.                  | TCP, UDP                                       |
| 3      | Ağ (Network)           | Yönlendirme ve IP adresleme yapar.               | IP, ICMP, ARP, Router                          |
| 2      | Veri Bağlantısı        | MAC adresleme ve hata kontrolü.                  | Ethernet, Wi-Fi, Switch                        |
| 1      | Fiziksel (Physical)    | Fiziksel bağlantı (sinyal, kablo, cihaz).        | Kablo, Modem, Hub                              |

---

## 🔍 OSI Katmanlarının Detayları

### 1️⃣ Fiziksel Katman
- Elektrik sinyalleri, kablolar, modem vb.
- Teknolojiler: Wi-Fi, Bluetooth, DSL

### 2️⃣ Veri Bağlantısı Katmanı
- Veri çerçevelere dönüştürülür, MAC ile yönlendirilir.
- Protokoller: Ethernet, PPP, 802.11

### 3️⃣ Ağ Katmanı
- Routing yapılır, hedefe IP ile veri ulaştırılır.
- Cihaz: Router
- Protokoller: IP, ICMP, RIP, BGP

### 4️⃣ Taşıma Katmanı
- TCP: Güvenilir
- UDP: Hızlı ama güvenilmez
- Port yönetimi, akış kontrolü

### 5️⃣ Oturum Katmanı
- Bağlantı başlatma, yönetim, sonlandırma
- Protokoller: NetBIOS, SSH

### 6️⃣ Sunum Katmanı
- Şifreleme, sıkıştırma, veri formatlama
- Protokoller: SSL/TLS, ASCII, JPEG

### 7️⃣ Uygulama Katmanı
- Kullanıcının etkileşimde olduğu katman
- Protokoller: HTTP, FTP, SMTP, DNS

---

## 🔁 OSI vs TCP/IP Modeli

| OSI Modeli     | TCP/IP Modeli     |
|----------------|--------------------|
| 7. Uygulama    | Uygulama           |
| 6. Sunum       | Uygulama           |
| 5. Oturum      | Uygulama           |
| 4. Taşıma      | Taşıma             |
| 3. Ağ          | İnternet           |
| 2. Veri Bağ.   | Ağ Erişimi         |
| 1. Fiziksel    | Ağ Erişimi         |

- OSI: Teorik model
- TCP/IP: Gerçek ağlarda yaygın kullanım

---

## 🔢 Binary (İkili Sistem)

### Tanım:
- 0 ve 1’lerden oluşan sistem (Base-2)
- Donanım ve dijital işlemler bu sistemle yapılır

### Örnek:
- 5 (desimal) = 101 (binary)

### Binary'den Desimal'e:
- 1011 = 8 + 0 + 2 + 1 = **11**

### Desimal'den Binary'e:
- 27 = 11011

---

## ⚙️ Bit & Byte

| Ölçü        | Değer               |
|-------------|---------------------|
| 1 Bit       | 0 veya 1            |
| 1 Byte      | 8 Bit               |
| 1 KB        | 1024 Byte           |
| 1 MB        | 1024 KB             |
| 1 GB        | 1024 MB             |
| 1 TB        | 1024 GB             |

- ASCII, Unicode, Hexadecimal gibi özel gösterimler vardır.

---

## 🌐 IP Adresi

### Türleri:
- IPv4 (32-bit) → 192.168.1.1
- IPv6 (128-bit) → 2001:db8:...

### Sınıflar:
| Sınıf | Aralık                    | Kullanım           |
|-------|----------------------------|--------------------|
| A     | 1.0.0.0 – 126.255.255.255 | Büyük ağlar        |
| B     | 128.0.0.0 – 191.255.255.255| Orta ölçekli ağlar |
| C     | 192.0.0.0 – 223.255.255.255| Küçük ağlar        |

### IP Türleri:
- Özel (Private): Yerel ağ
- Genel (Public): İnternet
- Statik ve Dinamik IP

---

## 📈 Host Hesaplama

Formül:
```
Toplam Host = 2^(32 - Subnet Mask) - 2
```

### Örnek:
- /24: 254 host
- /26: 62 host
- /30: 2 host

---

## 📡 TCP vs UDP

| Özellik        | TCP                                | UDP                               |
|----------------|-------------------------------------|------------------------------------|
| Bağlantı       | Var (Connection-Oriented)          | Yok (Connectionless)              |
| Hata Kontrolü  | ✅ Var                              | ❌ Yok                             |
| Hız            | Daha yavaş                         | Daha hızlı                        |
| Kullanım       | HTTP, FTP, SMTP                     | Oyunlar, DNS, VoIP                |

---

## 🔄 TCP Three-Way Handshake

1. **SYN** – Client bağlantı ister
2. **SYN-ACK** – Server cevap verir
3. **ACK** – Client onaylar

Sonuç: Bağlantı kurulmuştur ✅

---

