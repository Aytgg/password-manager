# Password Manager

Şirket içi kullanım için uçtan uca şifreli, çevrimdışı öncelikli parola
yöneticisi. Asıl kullanım senaryosu, şirket sunucuları, VPN ya da internet
erişimi kesildiğinde de parolalara ulaşabilmektir.

- **Masaüstü uygulaması:** [Tauri 2](https://tauri.app). Arayüz React ve
  TypeScript ile yazıldı; bütün kriptografi Rust tarafında çalışır.
- **Sunucu:** [Convex](https://convex.dev). Yalnızca şifreli veri, paketlenmiş
  anahtarlar ve paylaşım kuralları saklanır.
- **Kimlik doğrulama:** [Convex Auth](https://labs.convex.dev/auth). Özel bir
  credentials sağlayıcısı ve davet tabanlı kayıt kullanılır.

## İçindekiler

1. [Temel ilkeler](#temel-ilkeler)
2. [Kullanılan algoritmalar](#kullanılan-algoritmalar)
3. [Anahtar hiyerarşisi](#anahtar-hiyerarşisi)
4. [Parola, giriş ve yerel kasa](#parola-giriş-ve-yerel-kasa)
5. [Kayıtların şifrelenmesi](#kayıtların-şifrelenmesi)
6. [Paylaşım: kişiler ve departmanlar](#paylaşım-kişiler-ve-departmanlar)
7. [Erişimin kaldırılması](#erişimin-kaldırılması)
8. [Davet ve kayıt](#davet-ve-kayıt)
9. [Çevrimdışı çalışma](#çevrimdışı-çalışma)
10. [Bellekteki gizli veriler](#bellekteki-gizli-veriler)
11. [Sunucunun gördüğü veriler](#sunucunun-gördüğü-veriler)
12. [Bilinen sınırlamalar](#bilinen-sınırlamalar)
13. [Geliştirme](#geliştirme)

## Temel ilkeler

- **Sunucu hiçbir parolayı çözemez.** Başlık, kullanıcı adı ve parola cihazda
  şifrelenir; Convex'e yalnızca şifreli hali gider.
- **Tek parola.** Kullanıcının hem girişte hem kasayı açarken kullandığı tek
  bir parolası vardır. Bu parola cihazdan çıkmaz; sunucuya yalnızca ondan
  türetilmiş ve kasayı açmaya yetmeyen bir giriş anahtarı gider.
- **Çevrimdışı öncelikli.** Daha önce giriş yapılmış bir cihazda kasa
  internetsiz açılır. Kayıtlar cihazdaki şifreli önbellekten görüntülenir ve
  kopyalanır.
- **Açık parola React'e girmez.** Parola kopyalanırken Rust tarafında çözülüp
  doğrudan sistem panosuna yazılır.

## Kullanılan algoritmalar

| Amaç | Algoritma | Parametreler |
|---|---|---|
| Paroladan anahtar türetme | Argon2id (v0x13) | 64 MiB bellek, 3 iterasyon, 4 paralellik, 32 bayt çıktı |
| Key separation | HKDF-SHA256 | Her amaç için ayrı `info` etiketi |
| Simetrik şifreleme | AES-256-GCM | 12 bayt rastgele nonce, gerektiğinde AAD |
| Key wrapping | X25519 ECDH + HKDF-SHA256 + AES-256-GCM | Her paket için yeni ephemeral anahtar |
| Kimlik anahtarları | X25519 | Kullanıcı, departman ve geçici davet kimlikleri |
| Sunucuda giriş anahtarı özeti | SHA-256 | Constant-time karşılaştırma |
| Gizli anahtar deposu | IOTA Stronghold | Snapshot anahtarı ana anahtardan HKDF ile türetilir |

Kullanılan Rust crate'leri: `argon2`, `aes-gcm`, `x25519-dalek`, `hkdf`,
`sha2`, `zeroize`, `tauri-plugin-stronghold`.

Bütün etiketler (`info`, AAD, salt önekleri) `password-manager/...` biçiminde
sürüm numarası taşır. Biçim değişirse eski veriyle karışmaz.

## Anahtar hiyerarşisi

```
Kullanıcı parolası + e-posta
        │  Argon2id (salt = SHA-256("password-manager/kdf-salt/v2:" + e-posta)[..16])
        ▼
   Stretched key (32 B)
        ├── HKDF "password-manager/auth/v2" ──► auth_secret ──► Convex Auth (sunucu yalnızca SHA-256'sını saklar)
        └── HKDF "password-manager/kek/v2"  ──► KEK (cihazdan çıkmaz)
                                                  │ AES-256-GCM
                                                  ▼
                                        Ana anahtar (rastgele 32 B) ── master-key.json
                                          ├── HKDF ──► Stronghold snapshot anahtarı ── vault.hold
                                          │              └── X25519 kimlik özel anahtarı (+ varsa geçici davet kimliği)
                                          ├── AES-256-GCM ──► vault-owner.json (e-posta + sunucu kullanıcı kimliği)
                                          └── HKDF "password-manager/items-cache-key/v1" ──► önbellek anahtarı ── items-cache.json

Kimlik anahtarı (X25519)
   ├── Doğrudan paylaşılan kayıtların DEK'leri
   └── Departman özel anahtarları (X25519) ──► departmanla paylaşılan kayıtların DEK'leri

Kayıt DEK'i (rastgele 32 B, kayıt başına)
   ├── AES-256-GCM ──► meta veri (başlık, kullanıcı adı)
   └── AES-256-GCM ──► gizli değer (parola)
```

## Parola, giriş ve yerel kasa

### Anahtar türetme

Kullanıcı parolası ve normalleştirilmiş e-posta (boşluklar kırpılır, küçük
harfe çevrilir) Argon2id'den bir kez geçirilir. Çıktı HKDF ile iki bağımsız
anahtara ayrılır:

- **`auth_secret`:** sunucuya giriş için gönderilir.
- **`kek`:** yerel ana anahtarı şifreler.

İki anahtar aynı kaynaktan farklı etiketlerle türetildiği için sunucu
`auth_secret`'ı bilse bile `kek`'e ulaşamaz. Parolayı tahmin etmeye çalışan
biri ise her tahmin için Argon2id maliyetini ödemek zorundadır.

Salt e-postadan türetilir. Böylece yeni bir cihaz, sunucuya hiçbir şey sormadan
aynı `auth_secret`'ı üretebilir.

### Sunucu girişi

Convex Auth'un özel credentials sağlayıcısı ([convex/auth.ts](convex/auth.ts))
`auth_secret`'ı yalnızca 64 karakterlik hex biçiminde kabul eder; ham parola
reddedilir. Sunucu bu değerin SHA-256 hash'ini saklar ve constant-time
karşılaştırır. Değer yüksek entropili olduğu için hızlı bir özet yeterlidir.
Başarısız giriş denemeleri Convex Auth tarafından sınırlandırılır.

Oturum token'ları Convex deployment'ının `JWT_PRIVATE_KEY` anahtarıyla
imzalanır ve yine Convex tarafından doğrulanır. Dışarıdan bir kimlik
sağlayıcısı kullanılmaz.

### Yerel kasa

Her hesabın kasası `app_data_dir/vaults/<SHA-256(e-posta)[..32]>/`
klasöründedir:

| Dosya | İçerik | Koruma |
|---|---|---|
| `master-key.json` | Ana anahtar | `kek` ile AES-256-GCM |
| `vault.hold` | Stronghold snapshot: X25519 kimlik özel anahtarı | Ana anahtardan HKDF ile türetilen snapshot anahtarı |
| `vault-owner.json` | E-posta ve sunucudaki kullanıcı kimliği | Ana anahtar ile AES-256-GCM, AAD `password-manager-vault-owner-binding:v2` |
| `items-cache.json` | Çevrimdışı önbellek | Önbellek anahtarı ile AES-256-GCM, AAD kullanıcıya bağlı |

Kasa açılırken sırasıyla şunlar yapılır:

1. Paroladan `kek` türetilir.
2. Ana anahtar çözülür. Parola yanlışsa GCM doğrulaması başarısız olur.
3. Kasa sahibi bilgisi, girilen e-postayla karşılaştırılır.
4. Stronghold açılır ve kimlik anahtarı yüklenir.

Bu adımların hiçbiri internet gerektirmez. Bağlantı varsa aynı `auth_secret`
ile arka planda sunucuya giriş yapılır.

### Parola değişikliği

Ana anahtar değişmez; yalnızca onu koruyan `kek` değişir. Sırası şöyledir:

1. Mevcut parola yerelde doğrulanır.
2. Ana anahtar yeni `kek` ile şifrelenir ve sonuç bellekte bekletilir.
3. Sunucu mevcut `auth_secret`'ı doğrulayıp yenisini kaydeder.
4. Yeni `master-key.json` diske yazılır. Geçici bir dosyaya yazılıp tek adımda
   yerine taşındığı için yarıda kalan bir yazma eski dosyayı bozmaz.

Böylece sunucu ile cihaz birbirinden ayrışmaz. Diğer cihazlardaki oturumlar
kapatılır. Stronghold, kimlik anahtarı ve sunucudaki şifreli veriler
etkilenmez.

## Kayıtların şifrelenmesi

Her kaydın kendine ait rastgele bir **DEK**'i (32 bayt) vardır. Kayıt iki ayrı
şifreli alan taşır; kaydın önceki halleri de ayrı satırlarda aynı DEK ile
şifrelenir:

| Alan | İçerik | AAD |
|---|---|---|
| `metadata` | `{ "title", "username" }` JSON | `password-manager/item/v1/metadata:{sahipId}:{kayıtId}` |
| `secret` | Parola baytları | `password-manager/item/v1/secret:{sahipId}:{kayıtId}` |
| `itemHistory.entry` | Önceki hal: `{ "title", "username", "password" (base64), "replacedAt" }` JSON | `password-manager/item/v1/history:{sahipId}:{kayıtId}` |

Alanların ayrı olması sayesinde liste görüntülenirken parolaların kendisi
çözülmez. AAD şifreli veriyi sahibine ve kayıt kimliğine bağlar: sunucu bir
kaydın şifreli verisini başka bir kayda taşırsa çözme başarısız olur.

### Geçmiş

Kayıtta herhangi bir şey (başlık, kullanıcı adı ya da parola) değiştiğinde
önceki hali `itemHistory` tablosuna yeni bir satır olarak eklenir. Sayı ya da
boyut sınırı yoktur; her satır ayrı şifrelendiği için tek bir alanın boyut
sınırına takılmaz.

Geçmiş kaydın DEK'i ile şifreli olduğu için kaydı açabilen herkes (sahip,
doğrudan yetkililer, departman üyeleri, yöneticiler) geçmişi de açabilir. Her
rekey'de bütün geçmiş satırları yeni DEK'e taşınır; erişimi kaldırılan kişi
geçmişi de açamaz. Sunucu rekey'i ancak mevcut her geçmiş satırı tam bir kez
(yeni DEK ile) ve en fazla bir yeni satırla gönderildiğinde kabul eder; böylece
geçmiş silinemez ya da değiştirilemez. Arayüz eski başlığı, kullanıcı adını
ve neyin değiştiğini gösterir; eski parolalar gösterilmez ve kopyalanamaz
(yalnızca "parola değişti" bilgisi için saklanır).

Kayıt kimliği (`item-<32 hex>`) istemcide rastgele üretilir. Bu sayede
çevrimdışı oluşturulan kayıtlar çakışmadan gönderilebilir ve aynı kayıt
tekrar gönderilirse sunucu mevcut kaydı döndürür.

Sınırlar: başlık en fazla 200, kullanıcı adı en fazla 320 karakter; parola en
fazla 4096 bayt.

### Key wrapping

DEK, erişimi olan her alıcının X25519 açık anahtarına ayrı ayrı paketlenir
([src-tauri/src/crypto/key_wrap.rs](src-tauri/src/crypto/key_wrap.rs)):

1. Her paket için yeni bir ephemeral X25519 anahtar çifti üretilir.
2. Alıcının açık anahtarıyla ECDH yapılır.
3. Shared secret HKDF-SHA256 (`info = "password-manager/dek-wrap/v1"`) ile
   paketleme anahtarına çevrilir.
4. DEK, AES-256-GCM ile şifrelenir.

Pakette yalnızca ephemeral açık anahtar, nonce ve şifreli DEK bulunur. Aynı DEK
iki kez paketlense bile sonuçlar birbirinden farklıdır.

### Düzenleme

Düzenlemeyi yalnızca kaydın sahibi yapabilir. Her düzenleme yeni bir DEK ile
yapılır ve erişimi olan herkese (kişiler ve departmanlar) yeniden paketlenir.
Böylece daha önce erişimi kaldırılmış birinin elinde kalan eski DEK, yeni
parolayı açamaz. Sunucu düzenlemeyi yalnızca güncel `keyVersion` ile ve
eksiksiz alıcı listesiyle kabul eder.

## Klasörler

Parolalar klasörlerde düzenlenir (`folders` tablosu). Her klasörün
`parentId`'si üst klasörünü gösterir; yoksa kök klasördür. Kaydın
`folderId`'si yoksa kayıt kökte durur. Klasörler en fazla 20 seviye iç içe
olabilir ve aynı klasör altında aynı adla iki klasör olamaz.

- **Görünürlük:** Klasör ağacı şirket genelidir; herkes bütün klasörleri
  görür ve kendi kayıtlarını istediği klasöre koyabilir.
- **Yönetim:** Klasörleri yalnızca yöneticiler ve departman yöneticileri
  oluşturur. Yöneticiler her klasörü, departman yöneticileri yalnızca kendi
  oluşturduklarını yeniden adlandırır, taşır, siler ve altına klasör açar.
  Kaydı klasörler arasında kaydın sahibi (ya da bir yönetici) taşır.
- **Silme:** Klasör silinince içindeki kayıtlar ve alt klasörler bir üst
  klasöre (kök klasörse köke) taşınır; hiçbir kayıt silinmez.
- Klasör adları sunucuda **şifrelenmeden** saklanır. Klasör yetkileri sonraki
  adımda eklenecek; şimdilik yetkilendirme kayıt bazındadır.

## Paylaşım: kişiler ve departmanlar

Bir kayda iki yoldan erişilebilir:

- **Doğrudan:** DEK alıcının kendi açık anahtarına paketlidir (`itemAccess`).
- **Departman üzerinden:** DEK departmanın açık anahtarına paketlidir
  (`itemDepartmentAccess`); departmanın özel anahtarı da alıcıya paketlidir
  (`departmentKeys`). İstemci önce departman anahtarını, sonra DEK'i açar.

### Departman anahtarları

Her departmanın bir X25519 anahtar çifti vardır. Özel anahtar şu kişilere
paketlenir:

- departmanın bütün üyelerine,
- bütün yöneticilere (admin).

Yöneticilerin her departmanın anahtarını tutması, yeni üyelere ve davet edilen
kullanıcılara anahtar verilirken kimsenin beklemesini önler: işlemi yapan
yöneticinin cihazı o anda paketlemeyi yapar.

Bu tasarımın sonuçları:

- Bir kayıt departmanla paylaşıldığında yalnızca tek bir paket üretilir.
  Departmana sonradan katılan kişi de departmanın bütün kayıtlarına erişir ve
  kayıt sahibinin çevrimiçi olması gerekmez.

### Yöneticiler

Yöneticiler **bütün kayıtları** (kişisel olanlar dahil) görür: her kaydın DEK'i
bütün yöneticilerin açık anahtarına da doğrudan paketlenir. Paketleri, kayda
doğrudan erişimi olan herhangi bir istemci (genellikle sahibin ya da başka bir
yöneticinin cihazı) arka planda üretir. Yöneticilikten çıkarılan ya da devre
dışı bırakılan kişinin paketleri silinir ve kayıtlar yeniden şifrelenir.

### Departman silme

Departman silinirken departmandaki her kullanıcı için ya başka bir departmana
taşıma ya da devre dışı bırakma seçilir (herkese tek seçimle de
uygulanabilir). Taşınan kullanıcının eski departman anahtarı kaldırılır. Devre
dışı bırakılan kullanıcı silinmez: giriş yapamaz, anahtar paketleri kaldırılır,
kendi parolaları durur; departmanı boşalır ve yeniden etkinleştirilmeden önce
bir departman seçilir.
Departmanla yapılan paylaşımlar kalkar ve o kayıtlar yeniden şifrelenir.

### Arka plan işleri

Anahtar dağıtımı istemcilerin arka planda yaptığı işlerle yürür
([src/KeySync.tsx](src/KeySync.tsx)). Sunucu kurala göre yapılması gerekenleri
listeler ([convex/keys.ts](convex/keys.ts), `items.pendingWork`):

| İş | Kim yapar | Ne zaman |
|---|---|---|
| Departman anahtarı oluşturma | Yönetici | Departman ilk oluşturulduğunda |
| Departman anahtarı dağıtma | Anahtarı tutan herkes | Yeni üye, yeni yönetici, davet, anahtar değişikliği |
| Departman anahtarı yenileme | Anahtarı tutan herkes | Bir anahtar sahibi çıkarıldığında |
| Kayıt anahtarı dağıtma | Kayda doğrudan erişimi olan herkes | Yeni yetki verildiğinde |
| Kaydı yeniden şifreleme | Kayıt sahibi | Erişim kaldırıldığında |

Bu işler genellikle değişikliği yapan kişinin cihazında birkaç saniye içinde
tamamlanır. Sunucu her gönderilen paketin kurala uyduğunu (örneğin alıcının
gerçekten yetkili olduğunu) ve sürümlerin güncel olduğunu doğrular. Yenileme
işlemlerinde paket listesinin eksiksiz olmasını da şart koşar.

## Erişimin kaldırılması

Erişim kaldırıldığında yetki kuralı silinir, ilgili anahtar paketleri hemen
silinir ve sunucu artık o kişiye kaydı vermez. Ancak kişi DEK'i daha önce
görmüş olabilir. Bu yüzden:

- **Kişiye doğrudan verilen erişim kaldırılırsa:** kayıt yeniden şifrelenmek
  üzere işaretlenir (`needsRekey`). Sahibin cihazı yeni bir DEK üretir ve kalan
  alıcılara paketler.
- **Departmandan biri çıkarılırsa, devre dışı bırakılırsa ya da yöneticilikten
  alınırsa:** departman anahtarı yenilenmek üzere işaretlenir
  (`needsRotation`). Anahtarı tutan biri yeni bir departman anahtarı üretir,
  kalan sahiplere dağıtır ve departmana paketlenmiş bütün DEK'leri yeni
  anahtara taşır. Departmanla paylaşılan kayıtlar ayrıca yeniden şifrelenmek
  üzere işaretlenir.

Yeniden şifreleme, kişinin **daha önce gördüğü** parolayı unutturamaz. Kritik
durumlarda parolanın kendisi değiştirilmelidir; arayüz bunu hatırlatır.

## Davet ve kayıt

### Davet kodu

Davet kodu **yöneticinin cihazında** üretilir
([src-tauri/src/vault/invite.rs](src-tauri/src/vault/invite.rs)). Sunucu kodun
kendisini hiç görmez.

- **Biçim:** 12 karakter, `XXXX-XXXX-XXXX`. Alfabe karışması kolay karakterleri
  (0/O, 1/I/L) içermeyen 31 karakterdir; bu yaklaşık 59 bit eder. Eşit dağılım
  için rejection sampling kullanılır.
- **Kodun türetilmesi:** kod, Argon2id ile gerilir. Parametreler girişteki
  gibidir; salt `SHA-256("password-manager/invite-salt/v1:" + e-posta)[..16]`.
  Çıktı HKDF ile ikiye ayrılır:
  - **Geçici kimlik anahtarı** (`invite-identity/v1`): X25519 özel anahtarı.
  - **Doğrulayıcı** (`invite-verifier/v1`).
- **Sunucuya gidenler:** yalnızca geçici açık anahtar ve doğrulayıcının
  SHA-256 özeti. Sunucunun kodu tahmin etmeye çalışması her deneme için
  Argon2id maliyeti gerektirir.
- **Süre:** davet 24 saat, 3 gün ya da 7 gün geçerli olabilir.

### Kayıttan önce paylaşım

Davet edilen kullanıcının bir açık anahtarı olduğu için, kullanıcı kaydolmadan
önce de ona kayıt paylaşılabilir ve departman anahtarı paketlenebilir. Kullanıcı
kaydolduğunda başka hiç kimsenin çevrimiçi olması gerekmez.

### Kayıt ve kalıcı anahtara geçiş

1. Kullanıcı e-posta, davet kodu ve yeni parolasını girer.
2. İstemci doğrulayıcıyı türetir ve `signUp` ile birlikte gönderir; sunucu
   özeti karşılaştırır. Kod tek kullanımlıktır.
3. Cihazda kasa ve kalıcı X25519 kimlik anahtarı oluşturulur. Geçici kimlik,
   taşıma bitene kadar Stronghold'da saklanır; bağlantı koparsa taşıma sonraki
   girişte devam eder.
4. Geçici anahtara paketlenmiş her şey (kayıt DEK'leri ve departman
   anahtarları) çözülüp kalıcı anahtara yeniden paketlenir ve tek bir sunucu
   işlemiyle (`users.rotateKey`) değiştirilir. Sunucu listenin eksiksiz
   olmasını şart koşar.
5. Geçici kimlik silinir.

Davet yenilenirse eski geçici anahtara ait paketler silinir. Departman
anahtarlarını yöneticinin cihazı hemen yeniden paketler; kişiye doğrudan
paylaşılanları ise paylaşan kişi çevrimiçi olduğunda paketler.

### İlk yönetici

Henüz yönetici yokken ilk yönetici `ADMIN_BOOTSTRAP_CODE` ortam değişkenindeki
kodla kaydolur. Bu durumda kod sunucuya düz gönderilir. Bu güvenlidir, çünkü
yönetici yokken sistemde henüz hiçbir davet de yoktur. İstemci bunu
`auth.bootstrapAvailable` sorgusuyla öğrenir. Bir yönetici oluştuktan sonra
bootstrap kodu kabul edilmez.

## Çevrimdışı çalışma

### Önbellek

Sunucudaki kayıtlar (zaten şifreli halleriyle ve erişim yollarıyla), paylaşım
dizini ve bekleyen işlemler `items-cache.json` dosyasında tutulur
([src-tauri/src/vault/cache.rs](src-tauri/src/vault/cache.rs),
[src/vaultData.ts](src/vaultData.ts)):

- **Önbellek anahtarı:** ana anahtardan HKDF ile türetilir
  (`password-manager/items-cache-key/v1`).
- **Şifreleme:** AES-256-GCM, AAD
  `password-manager/items-cache/v1:{kullanıcıId}`. Başka bir hesabın dosyası
  kopyalansa bile açılmaz.
- **Yazma:** önce geçici bir dosyaya yazılır, sonra tek adımda yerine taşınır.

İçindeki kayıtlar kendi DEK'leriyle şifreli kaldığı için dosya iki katmanlı
korunur. Bağlantı varken önbellek sunucudan güncellenir: yeni ve değişen
kayıtlar yazılır, silinen ya da erişimi kaldırılan kayıtlar önbellekten de
çıkar.

### Çevrimdışıyken yapılabilenler

| İşlem | Çevrimdışı |
|---|---|
| Kasayı açma, listeyi görme, parola kopyalama | ✅ |
| Yeni kayıt | ✅ Kuyruğa alınır |
| Yetki verme / kaldırma | ✅ Kuyruğa alınır |
| Düzenleme, silme | ❌ Yalnızca çevrimiçi |
| Kullanıcı yönetimi, parola değişikliği, ilk giriş | ❌ Yalnızca çevrimiçi |

Kuyruktaki işlemler arayüzde "Bekleyen N işlem" bölümünde listelenir ve bağlantı
gelince sırayla gönderilir:

- Sunucu bir yetkilendirmeyi reddederse (örneğin kişi bu arada devre dışı
  bırakıldıysa) işlem atılır ve kullanıcıya bildirilir.
- Yeni kayıt hiçbir zaman atılmaz; gönderilemezse tekrar denenir.

Çevrimiçi durumu Convex WebSocket bağlantısının gerçek durumundan okunur.

## Bellekteki gizli veriler

- **Silinme:** anahtarlar ve çözülmüş veriler `Zeroizing` türlerinde tutulur ve
  bırakılınca bellekten silinir.
- **Otomatik kilit:** kasa 5 dakika hareketsizlikten sonra kilitlenir; Rust
  tarafındaki bir izleyici de bunu denetler. Kilitlemede Stronghold'un çözülmüş
  durumu temizlenir ve sunucu oturumu kapatılır, böylece kasa kilitliyken
  cihazda geçerli bir token kalmaz. Çevrimdışıyken token'lar yerel depodan
  silinir.
- **Pano:** kopyalanan parola 30 saniye sonra, pano hâlâ aynı içeriği
  taşıyorsa temizlenir.
- **Arayüze dönen tek gizli değer:** `auth_secret`. Arka planda sunucuya
  yeniden bağlanmak için kasa açık olduğu sürece bellekte tutulur. Kasayı
  açmaya yetmez.

## Sunucunun gördüğü veriler

Şifreli ve sunucunun **çözemediği** veriler: kayıt başlıkları, kullanıcı
adları, parolalar, bütün DEK'ler ve özel anahtarlar.

Sunucunun **düz metin** olarak gördüğü veriler (erişim kurallarını
uygulayabilmesi için gerekli):

- kullanıcıların e-postası, adı, rolü, departmanı ve durumu,
- departman adları,
- açık anahtarlar,
- kim hangi kayda, hangi departmanla erişiyor bilgisi (paylaşım grafiği),
- kayıt sahibi, zaman damgaları ve sürüm numaraları,
- giriş anahtarının ve davet doğrulayıcısının SHA-256 özetleri.

## Bilinen sınırlamalar

- **Açık anahtarlar doğrulanmıyor.** İstemci, paylaşım yaparken sunucunun
  verdiği açık anahtarlara güveniyor. Ele geçirilmiş bir sunucu, bir
  kullanıcının ya da departmanın açık anahtarını kendi anahtarıyla
  değiştirirse sonradan yapılan paylaşımları okuyabilir. Planlanan çözüm, açık
  anahtarların yönetici anahtarıyla imzalanması.
- **Kayıtlar imzalı değil.** Sunucu sahte bir kayıt ekleyebilir. Var olan
  kayıtları okuyamaz ve değiştiremez; değiştirilmiş şifreli veri AAD ve GCM
  doğrulamasından geçmez.
- **Rollback:** `keyVersion` AAD'ye dahil değil. Sunucu bir kaydın
  daha eski bir şifreli halini geri yükleyebilir.
- **Çoklu cihaz desteklenmiyor.** Kimlik anahtarı yalnızca oluşturulduğu
  cihazda duruyor. İkinci bir cihazda giriş yapılınca yeni bir kimlik üretilir
  ve sunucudaki açık anahtar değişir. Bu işlem kullanıcının bütün anahtar
  paketlerini siler, kendi kayıtlarındaki sahip paketleri de dahil:
  - Başkalarının paylaştığı kayıtlar ve departman anahtarları, anahtar
    sahiplerinin cihazlarınca yeniden paketlenir.
  - **Kimseyle paylaşılmamış kişisel kayıtlar ise iki cihazda da açılamaz hale
    gelir.** İlk cihazın önbelleği de bir sonraki eşitlemede bunları siler.

  Planlanan çözüm, kimlik anahtarının paroladan türetilen anahtarla şifrelenmiş
  bir yedeğinin sunucuda tutulması. O zamana kadar her hesap tek cihazda
  kullanılmalı.
- **Kayıttan önceki paylaşımlar:** davet kodunu bilen biri (kodu üreten
  yönetici ya da kodu ele geçiren), kullanıcı kaydolmadan önce yapılan
  paylaşımları açabilir. Kod bu yüzden güvenli bir kanaldan iletilmeli. Kayıt
  anında kalıcı anahtara geçildiği için sonraki paylaşımlar etkilenmez.
- **Çevrimdışı yetki kaldırma:** yetki kaldırma ancak bağlantı gelince etkili
  olur. Erişimi kaldırılan kişi, kendi cihazı eşitlenene kadar oradaki kopyayı
  görmeye devam edebilir.
- **Başka cihazda değiştirilen parola:** bir cihazda parola değiştirilirse
  diğer cihazdaki yerel kasa eski parolayla açılmaya devam eder. O cihaz
  internete bağlanınca sunucu eski parolayı reddeder; şimdilik yalnızca uyarı
  gösterilir.

## Geliştirme

### Gereksinimler

Node.js, Rust (1.90+), Tauri 2 ve bir Convex deployment'ı.

### Ortam değişkenleri

`.env.local` (Vite):

```
VITE_CONVEX_URL=...
```

Convex deployment'ı (`npx convex env set`):

| Değişken | Açıklama |
|---|---|
| `JWT_PRIVATE_KEY`, `JWKS` | Convex Auth oturum token'larını imzalar ve doğrular. `npx @convex-dev/auth` ile üretilir. Her deployment'ın kendi anahtarı olmalı. |
| `ADMIN_BOOTSTRAP_CODE` | İlk yöneticinin kayıt kodu. Yönetici oluştuktan sonra kaldırılabilir. |

### Komutlar

```bash
npm install
npx convex dev        # şema ve fonksiyonları geliştirme deployment'ına yükler
npm run tauri dev     # masaüstü uygulamasını başlatır
npm test              # Convex testleri (convex-test + Vitest)
cd src-tauri && cargo test   # Rust kriptografi ve kasa testleri
```

### Kod yapısı

| Yol | İçerik |
|---|---|
| `src-tauri/src/crypto/` | KDF, AES-GCM, X25519 key wrapping, ana anahtar |
| `src-tauri/src/vault/` | Kayıt şifreleme, departman ve davet anahtarları, önbellek, kasa dosyaları, oturum |
| `src-tauri/src/storage/` | Stronghold anahtar deposu ve kimlik anahtarları |
| `convex/` | Şema, erişim kuralları, kimlik doğrulama, anahtar iş listeleri ve testler |
| `src/` | React arayüzü, arka plan anahtar eşitlemesi (`KeySync`), çevrimdışı veri katmanı (`vaultData`) |
