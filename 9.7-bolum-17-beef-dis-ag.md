
# Bölüm 17: Sahte Oyun ile Dış Ağ Saldırıları (BeEF Kullanımı)

## 1️⃣ BeEF Kurulumu

BeEF'i dış ağda çalıştırmak için bir sunucuya ihtiyacınız olacak.

### BeEF'i İndir ve Kur

```bash
git clone https://github.com/BeefProject/beef.git
cd beef
bundle install
```

### BeEF’i Başlat

```bash
./beef
# Panel: http://127.0.0.1:3000/ui/panel
```

---

## 2️⃣ IP ve Port Yapılandırması

- VPS kullanıyorsanız, genel IP adresinizi öğrenin.
- Yerel ağdaysanız, dış IP’nizi öğrenmek için: [https://whatismyip.com](https://whatismyip.com)
- Varsayılan BeEF portu: `3000`

---

## 3️⃣ Port Yönlendirme (Router Üzerinden)

1. Yönlendiricinize bağlanın: `192.168.1.1`
2. Dış port 3000'i iç IP'deki BeEF sunucusuna yönlendirin.
3. Güvenlik duvarınızda bu portun açık olduğundan emin olun.

---

## 4️⃣ Sunucu Güvenliği

- **HTTPS kullanın**: SSL sertifikası ile şifreleme sağlayın.
- **Firewall**: Gereksiz portları kapatın.
- **SSH güvenliği**: Brute force'a karşı sınırlandırın.
- **Güçlü şifreler** kullanın.

---

## 5️⃣ BeEF’i Dış IP ile Başlat

```bash
./beef
# Tarayıcıdan erişim: http://<Dış-IP>:3000/ui/panel
```

### BeEF Yapılandırma (config.yaml)

```yaml
ip: '0.0.0.0'     # Tüm IP'lerden gelen bağlantılara izin ver
port: '3000'
```

---

## 6️⃣ Payload ile Tarayıcı Bağlama

- BeEF panelinden "hook" edilmiş tarayıcıları görüntüleyin.
- XSS veya güvenlik açığı kullanarak payload’ı hedefe enjekte edin.
- Başarılı payload sonrası tarayıcı panele bağlanır.

---

## 7️⃣ Dinamik DNS (Opsiyonel)

Statik IP’niz yoksa, DDNS servisi kullanabilirsiniz.

### Popüler DDNS Servisleri:

- **No-IP**: [https://www.noip.com](https://www.noip.com)
- **DynDNS**

No-IP kullanımı:

- IP adresiniz değişse bile alan adınız sabit kalır.
- Oyun sunucuları, uzaktan erişim ve güvenlik kameraları için uygundur.

---

## 🔚 Özet

- BeEF kurulumu ve dış IP ile çalıştırılması
- Port yönlendirme ve güvenlik önlemleri
- Payload kullanarak hedef tarayıcıyı bağlama
- Statik IP yoksa No-IP gibi servislerle çözüm
