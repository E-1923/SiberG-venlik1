
# Bölüm 21: Web Sitesi Bilgi Toplama

## 🔎 Maltego Nedir?

Maltego, OSINT (açık kaynak istihbaratı) ve siber keşif için kullanılan güçlü bir araçtır.

### 📌 Özellikleri

- Kişi, e-posta, domain, IP ve sosyal medya analizi
- Görsel grafiklerle veri ilişkilerini görselleştirme
- Otomatik transform'lar ile bilgi toplama

### 🔧 Kullanımı

1. Maltego’yu indir, kur ve hesap oluştur.
2. "New Graph" ile analiz başlat.
3. Varlık ekle (IP, domain, kişi vs.).
4. Sağ tık → Transform çalıştır.
5. Grafik analizi yap ve raporla.

---

## 🌐 Netcraft ile Bilgi Toplama

Netcraft, web güvenliği ve altyapı analizinde kullanılan bir çevrimiçi araçtır.

🔹 Site sahibi, hosting, DNS, SSL, CMS bilgilerini sağlar  
🔹 Tarayıcı uzantısı phishing algılar  
🔹 [https://www.netcraft.com](https://www.netcraft.com)

---

## 🌐 Reverse IP Lookup (Ters IP Araması)

Bir IP'ye bağlı domainleri keşfetme yöntemidir.

### 🔧 Online Araçlar

- https://viewdns.info/reverseip/
- https://securitytrails.com/

### 🔧 CLI Komutları

```bash
host -t ptr [IP]
nslookup [IP]
dig -x [IP]
```

### 🔧 Shodan ile

```bash
shodan host [IP]
```

---

## 👤 WHOIS Sorgusu

Alan adının sahibini, kayıt tarihi ve sunucu bilgilerini öğrenmek için kullanılır.

### 🔧 Online Servisler

- https://whois.domaintools.com
- https://whois.com
- https://whois.icann.org

### 🔧 Komut Satırı

```bash
whois example.com
```

---

## 🤖 robots.txt Nedir?

Botlara hangi sayfaların taranabileceğini belirleyen yapılandırma dosyasıdır.

### Örnek:

```plaintext
User-agent: *
Disallow: /admin/
```

---

## 🗂️ Dizin Tarama Araçları

### DirBuster

```bash
dirbuster
```

### Dirsearch

```bash
git clone https://github.com/maurosoria/dirsearch.git
python3 dirsearch.py -u https://example.com -e php,html,js
```

### Gobuster

```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list.txt
```

---

## 🌐 Subdomain Keşfi

### Amass

```bash
sudo apt install amass
amass enum -d example.com
```

### Subfinder

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
subfinder -d example.com
```

### Assetfinder

```bash
go install github.com/tomnomnom/assetfinder@latest
assetfinder --subs-only example.com
```

### crt.sh (Tarayıcı)

🔗 https://crt.sh/?q=example.com

### Google Dork

```makefile
site:*.example.com -www
```

### Knockpy

```bash
git clone https://github.com/guelfoweb/knock.git
cd knock
pip3 install -r requirements.txt
python3 knockpy.py example.com
```

---

## 🧰 Subbrute Kullanımı

```bash
git clone https://github.com/TheRook/subbrute.git
cd subbrute
python subbrute.py example.com
```

### Özel Wordlist:

```bash
python subbrute.py -w custom_wordlist.txt example.com
```

### MassDNS ile birlikte:

```bash
python subbrute.py -r resolvers.txt example.com
```

---

## 📌 Özet

- Maltego ile grafik tabanlı OSINT çalışması
- Netcraft ile site altyapısı analizleri
- WHOIS, Reverse IP, robots.txt ile manuel keşif
- Dirsearch, gobuster ile gizli dizin tarama
- Amass, Subfinder, Subbrute ile subdomain keşfi
