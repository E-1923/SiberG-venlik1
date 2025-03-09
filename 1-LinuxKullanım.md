# Linux Rehberi

## 📌 1. Linux Nedir?
✔ Açık kaynaklı, özgür bir işletim sistemidir.  
✔ Debian, Ubuntu, Arch, Fedora, CentOS, Kali Linux gibi farklı dağıtımları vardır.  
✔ Terminal (komut satırı) kullanımı önemlidir.

---

## 📌 2. Linux Terminal Temel Komutları
### 📌 Dizinler ve Dosya İşlemleri
```bash
pwd               # Bulunduğun dizini gösterir
ls                # Mevcut dizindeki dosyaları listeler
cd /home/user     # Dizin değiştirir
mkdir yeni_klasor # Yeni klasör oluşturur
rmdir eski_klasor # Boş klasörü siler
rm dosya.txt      # Dosya siler
rm -rf klasor     # Klasörü ve içeriğini siler
cp dosya.txt /tmp # Dosyayı kopyalar
mv dosya.txt /tmp # Dosyayı taşır
```
### 📌 Dosya İçeriğini Görüntüleme
```bash
cat dosya.txt     # Dosyanın içeriğini gösterir
less dosya.txt    # Sayfa sayfa görüntüleme
head -n 10 dosya  # İlk 10 satırı gösterir
tail -n 10 dosya  # Son 10 satırı gösterir
```
### 📌 Kullanıcı İşlemleri
```bash
whoami            # Hangi kullanıcı olarak giriş yaptığını gösterir
who              # Sistemde açık kullanıcıları listeler
su root          # Root kullanıcısına geçiş
sudo apt update  # Yönetici izinleriyle komut çalıştırma
passwd           # Şifre değiştirme
```
### 📌 Sistem Bilgisi
```bash
uname -a         # Çekirdek sürümünü gösterir
df -h            # Disk alanı bilgisi
free -m          # RAM kullanımını gösterir
uptime           # Sistemin çalışma süresini gösterir
top              # Çalışan işlemleri listeler
```
### 📌 Ağ İşlemleri
```bash
ip a             # IP adreslerini görüntüleme
ping google.com  # Bağlantı testi
netstat -tulnp   # Açık portları listeler
wget url         # Dosya indirir
```
### 📌 Paket Yönetimi (Debian/Ubuntu için)
```bash
sudo apt update          # Depoları günceller
sudo apt upgrade         # Güncellemeleri yükler
sudo apt install vim     # Yeni yazılım yükler
sudo apt remove firefox  # Paketi kaldırır
```
### 📌 İzinler ve Yetkilendirme
```bash
chmod 777 dosya.txt      # Tüm izinleri verir
chown user:user dosya.txt # Kullanıcı sahipliğini değiştirir
ls -l                   # Dosya izinlerini görüntüler
```

---

## 📌 3. Linux Dosya Sistemi ve Yapısı
### 📌 Linux’ta kök dizin (/) altındaki önemli klasörler:
```
/home/ → Kullanıcı klasörleri
/root/ → Root kullanıcısının ana dizini
/etc/ → Sistem ayar dosyaları
/var/ → Loglar ve değişken veriler
/tmp/ → Geçici dosyalar
/bin/ ve /sbin/ → Temel sistem komutları
```

---

## 📌 4. Linux’ta Servis Yönetimi
```bash
systemctl start apache2      # Servisi başlat
systemctl stop apache2       # Servisi durdur
systemctl restart apache2    # Servisi yeniden başlat
systemctl enable apache2     # Sistem açılışında çalışmasını sağla
```

---

## 📌 5. Linux’ta İşlemleri Yönetmek
```bash
ps aux                     # Çalışan tüm işlemleri listeler
kill -9 1234               # PID’si 1234 olan işlemi zorla sonlandır
pkill firefox              # Firefox işlemini sonlandır
```

---

## 📌 6. Linux’ta Root Yetkisi (Sudo) Kullanımı
```bash
sudo apt update      # Yönetici izniyle güncelleme yapar
sudo su              # Root’a geçiş yapar
```

---

## 📌 7. Linux’ta Güvenlik
✔ Güçlü parolalar kullan  
✔ Gereksiz servisleri kapat (`systemctl stop <servis>`)  
✔ Kullanıcı yetkilerini kontrol et (`chmod`, `chown`)  
✔ Firewall (`iptables`, `ufw`) kullan  
```bash
sudo ufw enable            # Firewall'u etkinleştir
sudo ufw allow 22/tcp      # SSH erişimine izin ver
sudo ufw deny 80/tcp       # HTTP erişimini engelle
sudo ufw status            # Aktif kuralları göster
```

---

## 📌 8. Linux’ta SSH Kullanımı
### 📌 Başka bir makineye bağlanmak için:
```bash
ssh user@remote_ip
```
### 📌 Dosya kopyalama (SCP ile):
```bash
scp dosya.txt user@remote_ip:/hedef_dizin
```

---

## 📌 9. Linux Kullanmayı Öğrenmek İçin Kaynaklar
### 📌 Linux Terminal Pratikleri
- OverTheWire – Bandit (CTF) → [OverTheWire](https://overthewire.org/wargames/bandit/)
- Explainshell → Komutları açıklayan site [Explainshell](https://explainshell.com/)

---
