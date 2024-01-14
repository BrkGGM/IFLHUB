# IFLHUB 
Okulum için yaptığım bir itiraf websitesinden birazcık fazlası.

## Özellikler 
Websitesi 5 farklı ana bölüm içerir bunlar şunlardır :

### Hesabım
Kişi kullanıcı adını değiştirebilir ya da kendine başka bir 'takma ad' koyabilir. Hesabı hakkında genel bilgilere ulaşabilir.

### İtiraf Gönder 
Websitesine girdiğinizde çıkan ilk sayfa eğer hesabınız yok ise hesapsız itiraf kısmına atar eğer hesabınız varsa iki seçenek sunar anonim veya normal itiraf.

### İtiraflar
İtirafları okuyup, yorum yapıp, beğenebilirsiniz.

### Sohbet
Sohbet edebilirsiniz.

### Eğlence
Haftanın müziğini, shipleri, anketleri oylayabilirsiniz. Ya da ship ve anket gönderebilirsiniz.

### Hesap sistemi
Velilerin girmesin engellemek için 'Kayıt Kodu' sistemi vardır. Kullanıcılar kullanıcı adı belirledikten sonra 'takma ad' belirleyebilirler.

### Admin yönetimi
Adminler için kullanması kolay bir admin menüsü vardır.

## Kendi bilgisayarınızda nasıl çalıştırırsınız?
Python3'ün son sürümünü kurun. [Buradan indirebilirsiniz](https://www.python.org/downloads/). Uyarı kurarken altta bir kutucuk olucak PATH'e eklemek istiyor musunuz diye ona evet deyin! 
Gerekenler kütüphaneleri kurun :

Windows:
```
pip install -r requirements.txt
```

Mac OS & Linux:
```
pip3 install -r requirements.txt
```

Database oluşturmak için db_olustur.py'yi çalıştırın daha sonra database yapısında bir güncelleme yaparsanız db_guncelle.py'yi çalıştırın. Sonra app.py'yi çalıştırın ve hazırsınız 127.0.0.1:5000'e giderek websitesini görüntüleyebilirsiniz!

