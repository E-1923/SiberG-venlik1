
# Bölüm 18: SETOOLKIT (Social Engineering Toolkit)

SET, sosyal mühendislik saldırılarını simüle etmek için kullanılan açık kaynaklı bir sızma testi aracıdır.

## 🎯 Temel Özellikler

- Phishing (Oltalama)
- Payload enjeksiyonu
- Sahte web siteleri oluşturma
- USB keylogger
- Credential harvesting

---

## 🔧 Modüller

### 1️⃣ Spear-Phishing Attacks

Hedefe özel sahte e-posta gönderimi:

- E-posta phishing
- Web tabanlı saldırılar (Web Attack)

### 2️⃣ Website Attack Vectors

- **Credential Harvester**: Sahte giriş sayfaları
- **Web Jacking**: Gerçek siteye benzer sahte arayüzler

### 3️⃣ Infectious Media Generator

- USB ile zararlı yazılım yayma
- **USB Keylogger**: Tuş vuruşlarını kaydetme

### 4️⃣ Social Engineering Attacks

- Fake virus alert vb. manipülatif saldırılar

### 5️⃣ Wireless Attacks

- **Evil Twin Attack**: Sahte Wi-Fi ağı ile kullanıcı kandırma

### 6️⃣ Payloads

- Metasploit ile entegre payload üretimi
- Çalıştırılabilir zararlılar (.exe, .apk)

### 7️⃣ Mass Mailer

- Toplu phishing e-posta gönderimi

### 8️⃣ SMS Spoofing

- Sahte SMS ile sosyal mühendislik

### 9️⃣ DNS Spoofing

- Hedefin DNS isteklerini manipüle ederek sahte siteye yönlendirme

---

## ✉️ Fake Mail Gönderme

### 1️⃣ Temp Mail ile

1. [https://temp-mail.org](https://temp-mail.org) adresine git
2. Geçici e-posta al, test gönderimi yap

### 2️⃣ Kendi E-posta Adresinle

- SMTP başlıklarını değiştirerek
- Bazı servisler bunu kısıtlar

### 3️⃣ SMTP Yazılımları ile

- `sendmail`, `msmtp`, `sendemail` gibi araçlar

---

## 💻 sendEmail Aracı ile SMTP Üzerinden E-posta Gönderimi

### 1️⃣ Kurulum

#### Debian/Ubuntu

```bash
sudo apt update
sudo apt install sendemail
```

#### CentOS/RHEL

```bash
sudo yum install sendemail
```

### 2️⃣ Temel Kullanım

```bash
sendemail -f sender@example.com -t receiver@example.com \
-u "Test Subject" -m "This is a test email." \
-s smtp.gmail.com -xu sender@example.com -xp yourpassword
```

### Parametre Açıklamaları

- `-f`: Gönderen
- `-t`: Alıcı
- `-u`: Konu
- `-m`: Mesaj içeriği
- `-s`: SMTP sunucusu
- `-xu`: SMTP kullanıcı adı
- `-xp`: SMTP şifre

### 3️⃣ Ekstra Seçenekler

- `-o tls=yes`: TLS ile gönderim
- `-cc` / `-bcc`: CC ve BCC adresleri

### 4️⃣ Bash Script ile Kullanım

```bash
#!/bin/bash
sendemail -f sender@example.com -t receiver@example.com \
-u "Automated Email" -m "This is an automated email." \
-s smtp.gmail.com -xu sender@example.com -xp yourpassword
```

---

## 🔚 Özet

SET aracıyla:

- Sosyal mühendislik saldırıları otomatikleştirilebilir
- E-posta/sms spoofing yapılabilir
- USB ile fiziksel saldırılar simüle edilebilir
- Phishing sayfaları kolayca üretilebilir
