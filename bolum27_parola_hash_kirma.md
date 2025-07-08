
# 📚 Bölüm 27: Parola / Hash Kırma

Parola veya hash kırma, bir parolanın veya şifrelenmiş halinin (hash) orijinal değerine geri döndürülmesi işlemidir. Genellikle siber güvenlik uzmanları, etik hackerlar ve penetrasyon test uzmanları tarafından güvenlik açıklarını test etmek için kullanılır.

## 🔐 Hash Nedir?

Hash, bir verinin tek yönlü olarak belirli bir algoritma ile şifrelenmiş halidir.

- MD5, SHA-1, SHA-256 gibi algoritmalar kullanılır.
- Hash fonksiyonları geri döndürülemez şekilde çalışır.
- Ancak bazı saldırı teknikleriyle kırılabilirler.

## 🛠️ Parola / Hash Kırma Yöntemleri

### 1. Brute Force (Kaba Kuvvet)
- Tüm olası kombinasyonları tek tek dener.
- Zaman alıcıdır ama kısa/zayıf parolalarda etkilidir.

### 2. Wordlist (Sözlük Saldırısı)
- Yaygın parola listeleri ile hash çözülmeye çalışılır.

### 3. Rainbow Table (Gökkuşağı Tablosu)
- Önceden hesaplanmış hash-parola eşleşme tablolarını kullanır.

### 4. Hash Collision (Çakışma Saldırısı)
- Aynı hash değerine sahip farklı girdiler hedeflenir.
- MD5 ve SHA-1 gibi eski algoritmalara karşı etkilidir.

### 5. Salting ve Peppering
- Hash’e rastgele veri (salt) eklenerek kırılma zorlaştırılır.
- Salt bilinmeden hash’in kırılması zordur.

## 🛡️ Savunma Yöntemleri

- Karmaşık ve uzun parolalar
- İki faktörlü kimlik doğrulama (2FA)
- Güçlü algoritmalar (SHA-256, bcrypt, yescrypt)
- Salt ve pepper kullanımı

## 🐧 Linux'ta Parola Hashleme

- Parolalar `/etc/shadow` dosyasında saklanır.
- SHA-512, bcrypt, yescrypt gibi algoritmalar kullanılır.

### 💡 Hash Formatları

| Prefix | Algoritma      |
|--------|----------------|
| `$1$`  | MD5            |
| `$5$`  | SHA-256        |
| `$6$`  | SHA-512        |
| `$y$`  | yescrypt       |
| `$2a$` / `$2b$` | bcrypt |

## 🪟 Windows'ta Parola Hashleme

- Hash'ler `C:\Windows\System32\Config\SAM` dosyasında saklanır.
- Erişim için admin yetkisi gerekir.

### Hash Türleri

#### 🧱 LM Hash (Eski ve Zayıf)
- Küçük harfe duyarsız
- 7 karakterlik iki parçaya bölünür
- Rainbow table ile kolayca kırılır

#### 🔐 NTLM Hash (Modern)
- MD4 ile şifrelenir, salt içermez
- Pass-the-Hash saldırılarına karşı savunmasız

#### 💪 NTLMv2 (Geliştirilmiş)
- HMAC-MD5 kullanır
- Daha güvenli ama zayıf parolalara karşı kırılabilir

## 📁 Linux Hash’lerini Toplama Yöntemleri

### 1. `/etc/shadow` Dosyasını Okuma
```bash
sudo cat /etc/shadow
```

### 2. `unshadow` ile birleştirme
```bash
unshadow /etc/passwd /etc/shadow > hashlist.txt
```

### 3. RAM'den Çekme (`pypykatz`, `gcore`)

### 4. Ağdan Çekme (MITM, `responder`, `tcpdump`)

### 5. Pass-the-Hash ile Kimlik Doğrulama
```bash
pth-smbclient -U "admin%HASH" //host/share
```

## 🔍 Hashcat Nedir?

Hashcat, hash kırmak için en hızlı araçlardan biridir. GPU desteklidir.

### Hashcat Saldırı Türleri

| Tür             | Kod  |
|----------------|------|
| MD5            | 0    |
| NTLM           | 1000 |
| SHA-512        | 1800 |
| bcrypt         | 3200 |
| NetNTLMv2      | 5600 |

### Wordlist Saldırısı
```bash
hashcat -m 1000 -a 0 hash.txt rockyou.txt
```

### Brute-Force Saldırısı
```bash
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l
```

### Hybrid Saldırısı
```bash
hashcat -m 1000 -a 6 hash.txt rockyou.txt ?d?d?d
```

## 🧪 SHA-512 Nedir?

- SHA-2 ailesindendir, 512-bit uzunluğundadır.
- Güçlü ve çakışmalara dayanıklıdır.
- SSL, blockchain, parola koruma gibi alanlarda kullanılır.

### SHA-512 Hash Örneği:
```bash
echo -n "ChatGPT" | sha512sum
```

## 🧩 ZIP Şifresi Kırma

### 1. `fcrackzip` ile Wordlist
```bash
fcrackzip -u -D -p rockyou.txt dosya.zip
```

### 2. Brute-Force
```bash
fcrackzip -u -c a -l 4-8 dosya.zip
```

### 3. `zip2john` + John the Ripper
```bash
zip2john dosya.zip > hash.txt
john --wordlist=rockyou.txt hash.txt
```

### 4. Hashcat
```bash
hashcat -m 13600 -a 3 hash.txt ?l?l?l?l?l?l
```

## 📌 Özet Tablolar

### Linux Hash Toplama Yöntemleri

| Yöntem                | Araçlar               | Avantaj         | Dezavantaj      |
|-----------------------|-----------------------|------------------|------------------|
| `/etc/shadow`         | `cat`, `unshadow`     | Doğrudan erişim  | Root yetkisi gerekir |
| RAM’den               | `pypykatz`, `gcore`   | Açık parolalar   | Dump işlemi gerekir |
| Ağ üzerinden          | `responder`, `tcpdump`| Uzak sistemler   | Ağ erişimi gerekir |
