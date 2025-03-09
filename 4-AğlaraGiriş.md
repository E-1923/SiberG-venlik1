# 📌 İnternet Ağları Nasıl Çalışır?

## 💡 İnternet Ağı Nedir?

İnternet ağı, cihazların (bilgisayarlar, telefonlar, sunucular) birbirleriyle veri alışverişi yapmasını sağlayan bir sistemdir. Bu sistem, farklı ağ bileşenleri ve protokoller aracılığıyla çalışır.

## 🔹 1. İnternetin Temel Bileşenleri

### ✅ Cihazlar (Hosts & Clients)
- Bilgisayarlar, telefonlar, sunucular, IoT cihazları
- Her cihaz IP adresi kullanarak internete bağlanır.

### ✅ Modem ve Router (Yönlendirici)
- **Modem:** İnternet Servis Sağlayıcısından (ISP) gelen sinyali çözümler.
- **Router:** Veriyi farklı cihazlara yönlendirir ve IP adresleriyle çalışır.

### ✅ IP Adresi ve DNS (Alan Adı Sistemi)
- **IP adresi:** Cihazları internet üzerinde tanımlayan numaralardır.
- **DNS (Domain Name System):** Alan adlarını IP adreslerine çevirir.
- Örneğin, `google.com` yerine `142.250.180.14` kullanılır.

### ✅ Sunucular (Servers)
- Web siteleri, uygulamalar ve hizmetler sunucular üzerinde barınır.
- Örneğin, Google'ın sunucuları milyonlarca kullanıcıya yanıt verir.

### ✅ Ağ Protokolleri (TCP/IP, HTTP, HTTPS, FTP)
- **TCP/IP:** İnternetin temel protokolü, veri iletimini sağlar.
- **HTTP/HTTPS:** Web sitelerine erişmek için kullanılır.
- **FTP:** Dosya transferi için kullanılır.

## 🔹 2. İnternette Veri Nasıl İletilir?

1. Kullanıcı, `www.google.com` yazıp Enter’a basar.
2. DNS sunucusu, `google.com` alan adını IP adresine çevirir.
3. Tarayıcı, Google'ın sunucusuna HTTP isteği gönderir.
4. Google sunucusu, yanıt olarak web sayfasını döndürür.
5. Veri paketleri kullanıcının cihazına ulaşır ve sayfa yüklenir.

Bu işlem milisaniyeler içinde gerçekleşir.

## 🔹 3. TCP/IP ve OSI Modeli

### ✅ TCP (Transmission Control Protocol)
- Veri paketlerini sıralı ve güvenilir şekilde iletir.

### ✅ IP (Internet Protocol)
- Veriyi doğru IP adresine yönlendirir.

### ✅ OSI Modeli
1. **Fiziksel:** Kablolar, Wi-Fi, donanım bağlantıları
2. **Veri Bağı:** MAC adresleri, Ethernet protokolleri
3. **Ağ:** IP adresleri ve yönlendirme (Routing)
4. **Taşıma:** TCP/UDP, veri paketlerinin güvenliği
5. **Oturum:** Cihazlar arasında bağlantı yönetimi
6. **Sunum:** Veri şifreleme ve formatlama
7. **Uygulama:** HTTP, FTP, e-posta protokolleri

## 🔹 VPN ve DNS Nedir?

### 🛡️ VPN (Virtual Private Network) Nedir?
- **VPN**, internet trafiğini şifreleyerek anonimlik ve güvenlik sağlar.

### 📂 VPN Nasıl Çalışır?
1. Cihaz, VPN sunucusuna bağlanır.
2. Tüm internet trafiği şifrelenir ve VPN sunucusu üzerinden yönlendirilir.
3. VPN sunucusu, kullanıcının IP adresini değiştirerek anonimlik sağlar.

### 🔹 DNS (Domain Name System) Nedir?
- **DNS**, alan adlarını IP adreslerine çeviren bir sistemdir.
- Örneğin, `www.google.com` → `142.250.180.14`

### 🔹 Popüler DNS Servisleri
- **Google DNS:** `8.8.8.8 / 8.8.4.4`
- **Cloudflare DNS:** `1.1.1.1`
- **OpenDNS:** `208.67.222.222`

## 🔹 Linux'ta VPN Kullanımı

### OpenVPN Kurulumu
#### Debian/Ubuntu:
```bash
sudo apt update && sudo apt install openvpn -y
```
#### Arch Linux:
```bash
sudo pacman -S openvpn
```

### OpenVPN Bağlantısı
```bash
sudo openvpn --config /path/to/your-config.ovpn
```
Bağlantının başarılı olup olmadığını kontrol etmek için:
```bash
curl ifconfig.me
```

## 🔹 Linux'ta DNS Değiştirme

### Terminal Üzerinden Geçici DNS Değiştirme
```bash
sudo systemd-resolve --set-dns=8.8.8.8 --interface=eth0
```

### Kalıcı DNS Değiştirme
1. **Dosyayı aç:**
```bash
sudo nano /etc/resolv.conf
```
2. **DNS ekleyin:**
```ini
nameserver 1.1.1.1
nameserver 8.8.8.8
```
3. **Hizmeti yeniden başlat:**
```bash
sudo systemctl restart systemd-resolved
```

DNS değişikliğini doğrulamak için:
```bash
nslookup google.com
```

