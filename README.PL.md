# DNS-shield

<p align="center"><img src="docs/logo.png" alt="Logo DNS-shield" width="160"></p>

> Ten plik to pełne polskie tłumaczenie [`README.md`](README.md). W razie
> rozbieżności wersja angielska jest wersją nadrzędną.

Mały, samodzielnie hostowany bloker reklam/trackerów DNS działający w całej
sieci, uruchamiany w Dockerze. Robi to samo co
[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) - działa jako
resolver DNS Twojej sieci i odrzuca zapytania do domen reklamowych/trackerów -
ale ze znacznie mniejszym, łatwym do zweryfikowania kodem i **bez żadnych
wbudowanych połączeń z jakąkolwiek usługą chmurową firm trzecich**.

Zobacz [`docs/features.html`](docs/features.html) - skategoryzowaną mapę
wszystkich funkcji tego projektu (otwórz w przeglądarce po sklonowaniu
repozytorium albo pobierz bezpośrednio z GitHub).

## Zrzuty ekranu

| Logi | Statystyki |
| --- | --- |
| ![Przeglądarka logów zapytań](docs/screenshots/logs.png) | ![Zakładka Stats](docs/screenshots/stats.png) |

| Ustawienia - DNS i serwery nadrzędne | Ustawienia - grupy klientów |
| --- | --- |
| ![Ustawienia DNS](docs/screenshots/settings-dns.png) | ![Grupy klientów](docs/screenshots/client-groups.png) |

| Lista dozwolonych / zablokowanych | Wstrzymanie blokowania |
| --- | --- |
| ![Lista dozwolonych i zablokowanych](docs/screenshots/allow-deny.png) | ![Pasek wstrzymania blokowania](docs/screenshots/pause-bar.png) |

| Zablokowani klienci | Ustawienia - Threat intelligence |
| --- | --- |
| ![Edytor zablokowanych klientów](docs/screenshots/blocked-clients.png) | ![Ustawienia threat intelligence](docs/screenshots/settings-threat-intel.png) |

| Wyskakujące okno Enrich |
| --- |
| ![Wynik wzbogacenia z historią wyszukiwań i przyciskiem blokowania hosta](docs/screenshots/enrich-popup.png) |

## Dlaczego nie użyć po prostu AdGuard Home?

### Czym faktycznie jest AdGuard Home i jak działa

AdGuard Home to sinkhole DNS / filtrujące proxy DNS z interfejsem webowym,
w skrócie:

1. Kierujesz na niego swój router lub urządzenia jako serwer DNS.
2. Dla każdego zapytania sprawdza domenę względem list filtrów (list w
   formacie hosts i AdBlock, odświeżanych z podanych przez Ciebie lub
   AdGuard adresów URL) oraz reguł zezwoleń/blokad dla poszczególnych
   użytkowników.
3. Trafienia są obsługiwane lokalnie (NXDOMAIN lub `0.0.0.0`); wszystko
   inne jest przekazywane do resolverów nadrzędnych, opcjonalnie przez
   DNS-over-HTTPS/TLS/QUIC.
4. W tym samym pliku binarnym, za panelem webowym, dostarcza też DHCP,
   kontrolę rodzicielską, "bezpieczne przeglądanie" oraz statystyki/logi
   zapytań.

### Skąd bierze się obawa o "wyciek danych"

Sama *podstawowa* funkcja blokowania reklam nie wymaga "dzwonienia do
domu", ale kilka innych funkcji AdGuard Home domyślnie komunikuje się z
własną infrastrukturą AdGuard - i to właśnie ludzie mają na myśli, mówiąc
o "wycieku":

- **Safe Browsing / Kontrola rodzicielska** wysyłają (zahaszowane,
  przycięte do prefiksu) zapytanie o *każdą odwiedzaną domenę* do własnego
  API chmurowego AdGuard (`family.adguard-dns.com` / endpoint bezpiecznego
  przeglądania AdGuard), gdy te funkcje są włączone - czyli kopia metadanych
  Twojego przeglądania opuszcza Twoją sieć i trafia do firmy trzeciej.
- **Sprawdzanie aktualizacji** cyklicznie odpytuje serwery AdGuard w
  poszukiwaniu nowych wydań.
- **Domyślne listy filtrów i domyślny nadrzędny resolver DNS-over-HTTPS**
  (własny serwer DoH AdGuard, `dns.adguard-dns.com`) kierują Twój ruch DNS
  i odświeżanie list przez infrastrukturę zarządzaną przez AdGuard, o ile
  jawnie ich nie zmienisz.
- To obszar bliski telemetrii, nawet jeśli tak się go nie nazywa: nawet
  funkcje typu opt-in bywają w niektórych wydaniach domyślnie włączone, a
  narzędzie samodzielnie hostowane, którego zadaniem jest "widzieć każdą
  domenę, jaką odwiedza Twoja sieć", to dokładnie ten rodzaj
  oprogramowania, w którym każde połączenie wychodzące do firmy trzeciej
  zasługuje na szczególną uwagę.

Nic z tego nie czyni AdGuard Home złośliwym oprogramowaniem - producent
dokumentuje te funkcje - ale dla narzędzia, które widzi dosłownie każdą
domenę, jaką rozwiązuje każde urządzenie w Twojej sieci, "zaufaj domyślnie
chmurze producenta" to rozsądna rzecz, której warto unikać.

### Co DNS-shield robi inaczej

DNS-shield implementuje ten sam podstawowy mechanizm (sinkhole DNS + listy
filtrów + interfejs webowy), ale z założenia utrzymuje go **wyłącznie
lokalnie**:

- Jedyne połączenia wychodzące, jakie kiedykolwiek wykonuje, to: (a)
  żądania do adresów URL list blokad, które *Ty* konfigurujesz, (b)
  zapytania do serwerów nadrzędnych, które *Ty* konfigurujesz, (c)
  zapytanie o reputację przez threat-intel
  (VirusTotal/AbuseIPDB/AlienVault OTX i inne) - zabezpieczone kluczem API
  *oraz* osobnym przełącznikiem "Enable public lookups", domyślnie
  wyłączonym, a nawet wtedy uruchamiane tylko w momencie kliknięcia
  "Enrich" dla konkretnej domeny/IP; zobacz
  [Wzbogacanie threat-intel](#wzbogacanie-threat-intel-virustotal--abuseipdb--alienvault-otx--i-inne)
  poniżej, w tym opcję skierowania Enrich na własną, samodzielnie
  utrzymywaną usługę reputacji - oraz (d) e-mail do serwera SMTP, który
  *Ty* konfigurujesz, domyślnie wyłączony, uruchamiany tylko gdy
  [wykrywanie anomalii](#lokalne-wykrywanie-anomalii) jest włączone i coś
  znajdzie; zobacz [Powiadomienia](#powiadomienia) poniżej. Nie ma
  żadnego domyślnego punktu końcowego zarządzanego przez AdGuard i nic nie
  łączy się samo z siebie.
- Brak zapytań chmurowych do safe-browsing/kontroli rodzicielskiej, brak
  pingów sprawdzających aktualizacje, brak analityki, brak jakiejkolwiek
  telemetrii.
- Cały stan - konfiguracja, buforowane listy blokad, statystyki/log
  zapytań, wyniki wzbogacania, wykryte anomalie - znajduje się na
  zamontowanym woluminie `./data`: lokalna baza SQLite dla konfiguracji
  (`config.db`), jedna dla logu zapytań (`stats.db`), jedna dla wyników
  wzbogacania (`enrichment.db`), jedna dla alertów
  [wykrywania anomalii](#lokalne-wykrywanie-anomalii) (`anomalies.db`),
  plus zbuforowane pliki list. Nic nie jest wysyłane nigdzie indziej, a
  każdą z tych baz możesz samodzielnie otworzyć dowolnym klientem SQLite,
  by zweryfikować dokładnie, co jest przechowywane.
- Każde ustawienie jest konfigurowalne z poziomu panelu - nie trzeba
  edytować pliku YAML i restartować, by zmienić resolver nadrzędny lub
  listę blokad.
- Wystarczająco mały, by faktycznie przeczytać go od początku do końca;
  zobacz [Architektura](#architektura) poniżej - dokładny opis, co robi
  każdy plik.

To celowo **nie** jest próba pełnego zastąpienia AdGuard Home - brak
serwera DHCP, brak DoQ, brak kontroli na poziomie aplikacji. To podzbiór "blokuj
reklamy/trackery w całej sieci z kontenera Docker, bez niczego opuszczającego
moją sieć, o co nie prosiłem", plus te elementy kontroli rodzicielskiej na
poziomie DNS, które pasują do tego podzbioru: wymuszone SafeSearch/tryb
ograniczony oraz listy blokad kategorii ograniczone do grupy klientów (zobacz
[Kontrola rodzicielska / SafeSearch](#kontrola-rodzicielska--safesearch)).

## Szybki start

```bash
git clone <to repozytorium>
cd DNS-shield
docker compose up -d --build
```

Przy pierwszym uruchomieniu `./data/config.db` jest zasiewane z
`config/config.example.yaml`. Otwórz `http://<host>:3000` - trafisz na
publiczny, tylko-do-odczytu widok (trend zapytań + najczęściej blokowane
domeny, bez logowania) z linkiem "Sign in". Zaloguj się domyślnymi danymi
`admin` / `changeme`, **zmień hasło** (Settings -> General -> "Your
account") i skieruj DNS urządzenia na `<host>:53`, by to przetestować.

Aby używać tego w całej sieci, ustaw to jako serwer DNS w ustawieniach DHCP
routera (lub na poszczególnych urządzeniach).

Po zalogowaniu panel ma cztery zakładki (zapamiętywane między
przeładowaniami): **Logs** - przeglądarka logu zapytań; **Anomalies** -
wszystko, co oznaczył lokalny detektor anomalii lub Twoje reguły alertów;
**Stats** - karty podsumowania, najczęściej blokowane domeny, najczęściej
odpytywane domeny ogółem, najbardziej aktywni klienci, podział wg typu
zapytania oraz podział "blocked by" (która lista blokad/reguła odpowiada za
najwięcej blokad); oraz **Settings** - wszystko inne (ustawienia
DNS/webowe, konta użytkowników, serwery nadrzędne, listy blokad, listy
dozwolonych/zablokowanych, grupy klientów, importer AdGuard Home i "Delete
all logged queries" pod Logging & blocklist refresh). Pasek wstrzymania
blokowania na górze widoczny jest wyłącznie dla kont administratora - zobacz
**Konta wieloużytkownikowe, role i widok publiczny** poniżej.

## Konfiguracja

Każde ustawienie można edytować z poziomu panelu, w sekcji **Settings** -
do codziennego użytku nie trzeba edytować żadnego pliku. Settings jest
podzielone na podzakładki tematyczne: **General** (interfejs webowy, kopia
zapasowa konfiguracji), **DNS** (podstawowy resolver, serwery nadrzędne,
routing per domena, rekordy niestandardowe), **Logging** (retencja,
wykluczone domeny/klienci), **Threat intelligence**, **Import** (AdGuard
Home / Pi-hole), **Blocklists** (źródła, sugerowane listy, źródła listy
dozwolonych, harmonogram odświeżania), **Own lists** (lista dozwolonych,
lista zablokowanych, lista zablokowanych regex), **Clients** (zablokowani
klienci, grupy klientów) oraz **Cleans** (cache odpowiedzi DNS, usunięcie
wszystkich zalogowanych zapytań).

Pod maską aktywna konfiguracja znajduje się w `./data/config.db` (SQLite),
a pełna kopia jest eksportowana do `./data/config.backup.yaml` co 12 godzin
(i raz przy każdym starcie), wyłącznie jako czytelna dla człowieka kopia
zapasowa/materiał referencyjny:

```yaml
dns:
  listen_address: "0.0.0.0"
  listen_port: 53
  upstreams: ["1.1.1.1:53", "9.9.9.9:53"]   # dowolna liczba - zobacz niżej
  upstream_timeout_seconds: 3.0
  upstream_strategy: "in_order"  # lub "fastest" / "most_stable" / "race" - zobacz niżej
  upstream_stats_window_minutes: 15
  block_mode: "nxdomain"                     # lub "null_ip"
  blocked_ipv4: "0.0.0.0"        # używane gdy block_mode to "null_ip"
  blocked_ipv6: "::"              # to samo, dla AAAA
  block_page_enabled: false      # serwuj lokalną stronę "zablokowano" - zobacz niżej
  block_page_port: 80
  block_ipv6: false             # true: odpowiadaj na zapytania AAAA pusto zamiast przekazywać
  block_non_latin: false        # true: blokuj domeny cyrylica/arabski/CJK/itd. - zobacz niżej
  regex_denylist_enabled: false  # eksperymentalne - zobacz Lista zablokowana regex niżej
  cache_enabled: true            # cache w pamięci odpowiedzi z serwerów nadrzędnych, wg ich TTL
  cache_max_entries: 10000
  cache_min_ttl_seconds: 0        # dolny limit stosowany do buforowanych TTL
  cache_max_ttl_seconds: 3600     # górny limit stosowany do buforowanych TTL
  resolve_client_names: false    # odwrotny DNS dla IP klientów, wyłącznie do wyświetlania (zobacz niżej)
  client_name_resolver: ""       # np. "192.168.1.1:53" - Twój router, nie serwer nadrzędny do filtrowania
  client_name_cache_seconds: 3600

blocklists:
  refresh_interval_hours: 24
  sources:
    - name: "StevenBlack Unified Hosts"
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      enabled: true
  allow_sources: []   # ten sam format, ale nadpisują listy blokad - zobacz niżej

allowlist: []   # zawsze rozwiązywane normalnie, nawet jeśli pasuje do listy blokad
denylist: []    # zawsze blokowane, nawet jeśli nie ma ich na liście blokad
denylist_regex: []   # eksperymentalna lista blokad regex, zobacz niżej - wyłączona, chyba że regex_denylist_enabled
blocked_clients: []   # IP/CIDR z KAŻDYM zapytaniem blokowanym - zobacz niżej

dns_rewrites: []   # niestandardowe lokalne rekordy A/AAAA - zobacz niżej

domain_upstreams: []   # kieruj konkretne domeny do konkretnych resolwerów - zobacz niżej

client_groups: []   # nadpisania per IP/CIDR, zobacz niżej

web:
  listen_address: "0.0.0.0"
  listen_port: 3000
  theme: "navy"           # 8 palet, pary ciemny/jasny - zobacz Motywy kolorystyczne niżej

# Konta panelu - zobacz "Konta wieloużytkownikowe, role i widok publiczny"
# poniżej. Przy pierwszym uruchomieniu (lub przy aktualizacji z wersji, która
# miała tylko web.username/web.password powyżej), jedno konto administratora
# jest tworzone tutaj automatycznie, z hasłem przekonwertowanym na hash bcrypt.
# users: []

logging:
  level: "INFO"             # poziom logowania Pythona; tylko w YAML, nie w panelu
  retention_days: 30       # jak długo wpisy logu zapytań są przechowywane w stats.db
  ignored_domains: []      # nigdy nie logowane, ale nadal normalnie rozwiązywane/blokowane
  ignored_clients: []      # to samo, wg IP/CIDR klienta

enrichment:                    # ustawienia threat-intel - zobacz Wzbogacanie threat-intel niżej
  public_enabled: false         # główny przełącznik dla kluczy poniżej - domyślnie wyłączony
  virustotal_api_key: ""
  abuseipdb_api_key: ""
  otx_api_key: ""
  greynoise_api_key: ""
  shodan_api_key: ""
  urlhaus_api_key: ""
  rdap_enabled: false
  crtsh_enabled: false
  local_enabled: false           # własna usługa reputacji - zobacz niżej
  local_url: ""
  local_api_key: ""
```

Ten przykładowy plik (`config/config.example.yaml`) ma znaczenie tylko przy
*pierwszym* uruchomieniu na świeżym woluminie danych, albo w celu
odzyskania po wyczyszczeniu `config.db` - zobacz
[Bezpośrednia edycja pliku konfiguracyjnego](#bezpośrednia-edycja-pliku-konfiguracyjnego)
poniżej.

### Szyfrowane połączenie z serwerem nadrzędnym (DNS-over-TLS / DNS-over-HTTPS)

Każdy wpis `upstreams` może być poprzedzony prefiksem, by zaszyfrować odcinek
między DNS-shield a tym resolwerem, ukrywając treść zapytania przed czymkolwiek
podsłuchującym po drodze (np. Twoim ISP) - sam operator serwera nadrzędnego
nadal widzi, o co pytasz, tak samo jak w zwykłym DNS:

```yaml
dns:
  upstreams:
    - "dot://1.1.1.1"                          # DNS-over-TLS
    - "doh://cloudflare-dns.com/dns-query"     # DNS-over-HTTPS
    - "https://dns.quad9.net/dns-query"        # DNS-over-HTTPS, pełny URL też działa
```

Zwykłe wpisy `host:port` używają UDP z automatycznym ponowieniem przez TCP,
jeśli odpowiedź jest obcięta. Ta sekcja dotyczy wyłącznie odcinka *do
serwera nadrzędnego* - DNS-shield zawsze nasłuchuje też zwykłego DNS od
klientów Twojej sieci LAN na porcie 53, plus opcjonalnie DoH/DoT dla
klientów chcących zaszyfrowanego połączenia do samego DNS-shield; zobacz
[DNS-over-HTTPS / DNS-over-TLS dla klientów](#dns-over-https--dns-over-tls-dla-klientów)
poniżej.

### Wiele serwerów nadrzędnych i strategia wyboru

`dns.upstreams` przyjmuje dowolną liczbę resolwerów - wszystkie są zawsze
dostępne jako rezerwa, gdyby wcześniejsze zawiodły. `dns.upstream_strategy`
wybiera, który jest próbowany *jako pierwszy* dla każdego zapytania - albo,
dla `race`, wszystkie naraz:

- `in_order` (domyślnie) - próbuj w podanej kolejności, od góry do dołu.
- `fastest` - próbuj tego, który ma najniższy średni czas odpowiedzi w
  ostatnich `upstream_stats_window_minutes` (domyślnie 15).
- `most_stable` - próbuj tego, który ma najmniej awarii / najbardziej
  spójny czas odpowiedzi w tym oknie, faworyzując niezawodność nad surową
  szybkość.
- `race` ("Wszystkie naraz - FIFO") - wyślij zapytanie jednocześnie do
  każdego skonfigurowanego serwera nadrzędnego i odpowiedz klientowi tym,
  który odpowie pierwszy; reszta nadal działa w tle wyłącznie po to, by ich
  opóźnienie/sukces nadal był rejestrowany, ale ich odpowiedź jest
  odrzucana. Najniższe możliwe opóźnienie kosztem odpytywania każdego
  serwera nadrzędnego przy każdym pojedynczym żądaniu (więcej ruchu
  wychodzącego, a każdy serwer nadrzędny widzi każde zapytanie, nie tylko
  to, które "wygrało").

Wątek w tle sprawdza kondycję każdego skonfigurowanego serwera nadrzędnego
co 2 minuty (niezależnie od tego, który jest faktycznie używany przez
ruch), więc statystyki - widoczne w panelu, w tabeli Settings -> Upstream
DNS servers - pozostają aktualne nawet dla serwera, którego strategia
przestała wybierać, i może zostać ponownie wybrany, jeśli się poprawi. To
sprawdza wyłącznie hosty serwerów nadrzędnych już obecne w Twojej
konfiguracji.

### Wyłączanie serwera nadrzędnego bez jego usuwania

Każdy skonfigurowany serwer nadrzędny ma własny przycisk Disable/Enable w
panelu, w tabeli Settings -> Upstream DNS servers - pozostaje na liście (i w
tabeli statystyk kondycji), ale jest pomijany przy faktycznym rozwiązywaniu
zapytań, więc nie tracisz adresu ani jego historii z pliku
konfiguracyjnego/importu, usuwając go całkowicie. Pod maską to po prostu
poprzedza wpis znakiem `#` w `dns.upstreams` (lub
`domain_upstreams[].upstreams` / `client_groups[].upstreams`, jeśli
wyłączasz jeden z nich tam) - ta sama konwencja co ręczne zakomentowanie
linii w polu tekstowym "jeden na linię" nad tabelą, lub w ręcznie
edytowanym pliku konfiguracyjnym.

### DNSSEC

`dns.dnssec_enabled` (Settings -> DNS, domyślnie wyłączone) sprawia, że
DNS-shield ustawia bit DNSSEC OK (`DO`) w każdym przekazywanym zapytaniu i
sprawdza flagę `AD` (Authenticated Data) w odpowiedzi. To jest obsługa
DNSSEC **oparta na zaufaniu do serwera nadrzędnego**, nie niezależna
walidacja kryptograficzna: DNS-shield nie parsuje samodzielnie rekordów
RRSIG/DNSKEY/DS ani nie przechodzi łańcucha zaufania (to duża ilość
mechanizmów kryptograficznych, których ten projekt nie podejmuje) - polega
na tym, że serwer nadrzędny już dokonał walidacji i prosi go, by to
potwierdził. Skieruj go na walidujący publiczny resolwer (1.1.1.1, 9.9.9.9
i 8.8.8.8 domyślnie walidują), żeby miało to jakiekolwiek znaczenie -
serwer nadrzędny, który nie waliduje, po prostu nigdy nie ustawi `AD`, i ta
funkcja nie ma niczego do sprawdzenia.

Ponieważ sprawdzanie statusu domeny nie powinno oznaczać ponownej weryfikacji
przy każdym pojedynczym zapytaniu o nią, wyniki są trzymane w małym cache w
pamięci, niezależnym od zwykłego cache odpowiedzi DNS - `{domena: (bezpieczna,
wygasa o)}` - z własnym TTL, `dns.dnssec_cache_seconds` (domyślnie 3600). Ma
to znaczenie, ponieważ zapytanie odpowiedziane ze *zwykłego* cache odpowiedzi
w ogóle nie trafia do ścieżki kodu przekazującej, więc bez osobnego cache
DNS-shield nie miałby pojęcia, czy zbuforowana odpowiedź była kiedykolwiek
uwierzytelniona przez DNSSEC; dedykowany cache jest wypełniany wyłącznie
przy żywym połączeniu z serwerem nadrzędnym i to z niego czytane są liczniki
`dnssec.cached_domains` w `GET /api/status` (`secure`/`insecure`). To
obserwowalność, nie egzekwowanie - niezabezpieczony/niepodpisany wynik jest
normalny dla dużej części domen, które w ogóle nie podpisują swojej strefy,
więc DNS-shield nie blokuje ani w żaden inny sposób nie traktuje inaczej
niepodpisanych odpowiedzi; walidujący serwer nadrzędny już sam odmawia
(SERVFAIL) zwrócenia odpowiedzi, której podpis nie przechodzi weryfikacji,
zanim DNS-shield w ogóle ją zobaczy.

Wyłączenie tego ustawienia z powrotem (lub pozostawienie go wyłączonym)
przywraca dokładnie wcześniejsze zachowanie - zapytania są pakowane i
przekazywane bez dodawania rekordu EDNS0, bez dodatkowego kosztu.

### Nazwy hostów serwerów nadrzędnych i list blokad są zawsze rozwiązywalne i nigdy nie logowane

Jakakolwiek nazwa hosta potrzebna serwerowi nadrzędnemu `dot://`/`doh://` do
rozwiązania przez DNS (np. `dns.nextdns.io`), lub host adresu URL subskrypcji
listy blokad/dozwolonych (np. `raw.githubusercontent.com`), jest
automatycznie zwolniony z każdego mechanizmu blokowania - ponad nawet
ręczny wpis na liście zablokowanych, a obejście wstrzymania blokowania nie
musiałoby go nawet sprawdzać - i pominięty w logu zapytań domyślnie. Nie
jest potrzebna żadna konfiguracja: jest to wyprowadzane bezpośrednio z
`dns.upstreams`, `domain_upstreams[].upstreams`,
`client_groups[].upstreams` oraz każdego adresu URL
`blocklists.sources`/`blocklists.allow_sources`, za każdym razem gdy jest
sprawdzane, więc pozostaje poprawne, gdy którekolwiek z nich się zmieni.
Celem jest uniemożliwienie przypadkowego zablokowania DNS-shield dostępu do
własnego serwera nadrzędnego lub własnych list blokad (przypadkowe
trafienie listy blokad na którąkolwiek z tych nazw hostów byłoby inaczej
awarią spowodowaną samemu sobie - zablokowanie własnego źródła listy blokad jest
szczególnie paskudne, ponieważ po cichu zatrzymałoby wszystkie odświeżenia
list), oraz utrzymanie tego stałego wyszukiwania w tle poza logiem
przeznaczonym do tego, do czego faktycznie łączą się Twoje urządzenia.

Trzy publiczne hosty threat-intel (VirusTotal/AbuseIPDB/OTX i inne - zobacz
[Wzbogacanie threat-intel](#wzbogacanie-threat-intel-virustotal--abuseipdb--alienvault-otx--i-inne)
poniżej) są traktowane tak samo, ale **tylko po włączeniu
`enrichment.public_enabled`** - dopóki ten przełącznik jest wyłączony, nie
ma powodu, by DNS-shield się z nimi łączył, więc celowo nie ma dla nich
też stałego zwolnienia. Host Twojego własnego, lokalnego punktu końcowego
wzbogacania jest zwalniany niezależnie, kiedy tylko `enrichment.local_enabled`
jest włączone i ustawiony jest adres URL.

### Routing DNS per domena i per klient

`domain_upstreams` kieruje konkretne domeny do konkretnych resolwerów,
niezależnie od tego, który klient pyta - np. domeny wewnętrzne/firmowe,
które zna tylko Twój własny serwer DNS:

```yaml
domain_upstreams:
  - name: "Sieć wewnętrzna"
    domains: ["corp.local", "internal.example"]
    upstreams: ["192.168.1.1:53"]
```

Wpis `client_groups` może też mieć własną listę `upstreams`, używaną dla
zapytań tego klienta zamiast listy globalnej (np. przekierowanie DNS
klienta VPN przez inny resolwer). Kolejność pierwszeństwa, gdy może pasować
kilka reguł: pasująca reguła `domain_upstreams` wygrywa jako pierwsza
(routing domenowy zwykle jest twardym wymogiem technicznym), potem własne
`upstreams` dopasowanej grupy klientów, na końcu globalne `dns.upstreams`.

### Niestandardowe rekordy DNS ("rewrites")

`dns_rewrites` odpowiada na nazwę hosta adresem IP wybranym przez Ciebie,
całkowicie lokalnie - bez zapytania do serwera nadrzędnego, bez udziału
listy blokad. Przydatne dla wewnętrznych nazw hostów, o których Twój
publiczny DNS nie ma pojęcia:

```yaml
dns_rewrites:
  - name: "nas.home"
    type: "A"
    value: "192.168.1.10"
```

Rewrite pasuje do nazwy i jej subdomen (więc `printer.nas.home` też się
rozwiązuje, z powyższego wpisu), wyłącznie A/AAAA - bez podążania za CNAME,
by ta operacja pozostała płaskim wyszukiwaniem, które zawsze się kończy.
Jest sprawdzany *po* blokowaniu, nie przed: w pełni zablokowany klient lub
już zablokowana domena nadal zachowuje się jak zablokowana niezależnie od
jakiegokolwiek rewrite - rewrite jest odpowiedzią, nie zwolnieniem.
Zarządzaj rewrite'ami z panelu (Settings -> Custom DNS records) lub
edytując listę bezpośrednio.

### Formaty list blokad i sugerowane listy

Źródła list blokad występują w trzech powszechnych formatach, a listy w
świecie rzeczywistym nie są wszystkie takie same - niektóre nawet mieszają
je w jednym pliku:

- **format pliku hosts**: `0.0.0.0 ads.example.com`
- **format AdBlock/uBlock**: `||ads.example.com^`
- **zwykła lista domen**: `ads.example.com`

DNS-shield automatycznie wykrywa format każdej linii podczas pobierania
źródła, więc możesz wskazać dowolne z trzech (lub źródło, które je
miesza), bez konieczności ręcznego wyboru. Tabela Blocklists w panelu
pokazuje wykryty format pod liczbą domen każdego źródła - np. "hosts file
(0.0.0.0/127.0.0.1 domain)" lub "mixed formats (...)" dla źródła, które
faktycznie łączy więcej niż jedną składnię (pojedyncza zabłąkana linia się
nie liczy - raportowane jest to tylko przy prawdziwym mieszaniu).

Źródła AdBlock/uBlock mogą też zawierać linie wyjątków `@@||domain^` - wiele
popularnych list ich używa, by wyłączyć subdomenę spod szerszej reguły
wcześniej w tym samym pliku. DNS-shield je respektuje: domena dopasowana
przez regułę wyjątku własnego źródła jest traktowana tak, jakbyś sam ją
dodał do listy dozwolonych, więc nigdy nie jest blokowana przez to źródło.
Dla własnych, dodatkowych `blocklist_sources` grupy klientów, wyjątek
zwalnia tylko tę grupę, tak samo jak blokowanie grupy jest wyłącznie
addytywne (zobacz niżej). Zobacz
[Ograniczenia](#ograniczenia--plany-na-przyszłość) - co celowo *nie* jest
interpretowane ze składni AdBlock, i dlaczego.

Sekcja Blocklists ma też tabelę **Suggested lists**: krótką, ustaloną
listę wbudowaną w sam DNS-shield (nic nie jest pobierane, by ją zbudować) -
StevenBlack's Unified Hosts, własny filtr DNS AdGuard, garść rekomendowanych
("odhaczonych") list [Firebog](https://firebog.net), aktywnie utrzymywane
listy Multi PRO, Threat Intelligence Feeds oraz Newly Registered Domains
[HaGeZi](https://github.com/hagezi/dns-blocklists) (zobacz niżej), lista
[1Hosts (Lite)](https://github.com/badmojr/1Hosts) badmojr oraz lista
skoncentrowana na oszustwach DurableNapkin. Kliknięcie Add po prostu
wypełnia za Ciebie zwykły formularz dodawania źródła; lista jest wtedy
pobierana, a stąd może zostać wyłączona lub usunięta dokładnie tak samo
jak każde źródło wpisane ręcznie. Wpis znika z Suggested lists po dodaniu -
nie ma już nic do zasugerowania - więc lista pokazuje zawsze tylko to,
czego jeszcze nie dodałeś. Ten sam katalog jest też oferowany per grupa
klientów, w zakładce Clients (zobacz
[Kontrola rodzicielska](#kontrola-rodzicielska--safesearch) powyżej).

### Nowo zarejestrowane domeny (NRD)

Produkty korporacyjne do bezpieczeństwa DNS (Infoblox BloxOne Threat
Defense nazywa to "Newly Observed Domains", a to standardowa funkcja Cisco
Umbrella i podobnych) blokują lub oznaczają każdą domenę zarejestrowaną w
ciągu ostatnich mniej więcej 7-30 dni, na podstawie obserwacji, że kampanie
phishingowe i malware'owe w zdecydowanej większości rejestrują domenę i
wykorzystują ją w ciągu dni - zanim domena istnieje miesiąc, jest już poza
oknem, w którym ta technika cokolwiek wyłapuje. To realna, skuteczna
technika, która nie wymaga uczenia maszynowego ani subskrypcji na żywy feed
do zaimplementowania - to po prostu kolejna lista domen, więc podpina się
pod dokładnie ten sam mechanizm `blocklists.sources`/`blocklist_sources`,
co wszystko inne w tej sekcji. Katalog Suggested lists zawiera dokładnie w
tym celu **HaGeZi Newly Registered Domains (7-day)**.

Przeczytaj to jednak przed włączeniem - to prawdziwy kompromis, nie darmowa
wygrana:

- **Jest ogromna.** Codziennie na świecie rejestrowanych jest ok. 2,8
  miliona domen, a lista jest odświeżana codziennie. Załadowana kosztuje
  mniej więcej **650 MB RAM** (zmierzone bezpośrednio - zobacz
  [Współbieżność](#współbieżność) - jak listy blokad są trzymane w całości
  w pamięci jako `frozenset`, dla dopasowania w czasie O(1), i ile to
  kosztuje ogólnie). Na hoście o ograniczonych zasobach, sam ten fakt może
  być powodem, by ją pominąć - a jeśli uruchamiasz kilka
  [procesów roboczych DNS](#współbieżność), każdy ładuje własną,
  niezależną kopię.
- **Blokuje też legalne, nowe strony.** Zupełnie nowy produkt SaaS, osobisty
  blog znajomego, startup, który właśnie wystartował - wszystkie
  nieodróżnialne od domeny phishingowej wyłącznie po dacie rejestracji, i
  wszystkie zablokowane przez ich pierwszy tydzień. To zaakceptowany koszt
  tej techniki w każdym produkcie, który ją dostarcza, nie błąd tej
  implementacji.

Biorąc pod uwagę oba te fakty, rozważ dodanie jej jako własnego, dodatkowego
wpisu `blocklist_sources` konkretnej grupy klientów (powiedzmy, własnych
urządzeń świadomego bezpieczeństwa administratora), zamiast listy globalnej,
żeby koszt fałszywych trafień ponosiło tylko to, co sam zdecydowałeś
zaakceptować - to samo rozumowanie co przy listach kategorii kontroli
rodzicielskiej powyżej. Oferowane jest tylko okno 7-dniowe; HaGeZi publikuje
też okna 14/21/28/35-dniowe pod
[github.com/hagezi/nrd](https://github.com/hagezi/nrd), jeśli chcesz dodać
jedno ręcznie, ale wartość bezpieczeństwa spada gwałtownie wraz z wiekiem
domeny, podczas gdy koszt pamięci pozostaje równie duży, więc nie są tu
sugerowane.

[Lokalne wykrywanie anomalii](#lokalne-wykrywanie-anomalii) DNS-shield
pokrywa już pokrewną technikę korporacyjną - scoring entropii heurystyki
`domain_burst` oznacza klienta szybko odpytującego wiele wyglądających na
algorytmicznie wygenerowane, wysokoentropijnych domen, ten sam wzorzec DGA
(Domain Generation Algorithm), który analityka ML BloxOne jest zbudowana,
by wykrywać dla ruchu command-and-control malware - więc ten element już
istnieje niezależnie od jakiejkolwiek subskrypcji listy.

### Lista zablokowana regex (eksperymentalna)

`denylist_regex` blokuje każde zapytanie o nazwę pasującą do wyrażenia
regularnego Pythona, sprawdzane przez `re.search()` względem pełnej nazwy -
np. `^ads?[0-9]*\.` wyłapuje subdomeny w stylu `ad.`/`ad1.`/`ads2.` we
wszystkich domenach naraz, coś, czego zwykły wpis listy
zablokowanej domena/subdomena nie potrafi wyrazić. Jest domyślnie
wyłączona (`dns.regex_denylist_enabled`) i oznaczona w panelu jako
eksperymentalna nie bez powodu: każdy włączony wzorzec jest sprawdzany
względem **każdego pojedynczego zapytania**, więc koszt CPU na zapytanie
rośnie wraz z liczbą wzorców. Wzorce są kompilowane raz i buforowane w
pamięci - nigdy nie kompilowane ponownie na zapytanie - ale samo
dopasowywanie to nadal realna praca, więc jest to pomyślane dla garści
ręcznie wybranych reguł, nie pełnej listy. Nieprawidłowy wzorzec jest
odrzucany z błędem przy próbie dodania, zamiast być po cichu pomijany
później. Zarządzaj tym z panelu (Settings -> Regex denylist) lub edytując
`denylist_regex` bezpośrednio.

### Nazwy hostów klientów (odwrotny DNS)

Ustaw `dns.client_name_resolver` na IP swojego **routera** (nie jeden z
serwerów nadrzędnych filtrujących reklamy - to router faktycznie zna nazwy
klientów DHCP) i `dns.resolve_client_names: true`, a log zapytań i lista
klientów w panelu pokażą np. `laptop-jan.lan (192.168.1.50)` zamiast
samego surowego IP. Rozwiązywanie odbywa się w wątku w tle i jest
wyłącznie pomocą wyświetlania - nigdy nie opóźnia odpowiedzi na faktyczne
zapytanie klienta, i nic nie jest zapisywane na dysk (tylko cache w
pamięci, `dns.client_name_cache_seconds`).

### Polityki per klient/grupa

`client_groups` pozwala nadpisać globalną politykę dla konkretnych
klientów - np. bardziej restrykcyjna lista zablokowanych dla urządzeń
dzieci, albo całkowite wyłączenie filtrowania dla NAS-a/serwera, który się
psuje, gdy domeny są blokowane. Wygrywa pierwsza pasująca grupa; klient,
który nie pasuje do żadnej grupy, po prostu dostaje politykę globalną
powyżej. Wpis `match` może być adresem IP/CIDR (domyślnie), adresem MAC
jako `mac:AA:BB:CC:DD:EE:FF`, lub rozwiązaną nazwą hosta jako `host:nazwa`
(lub `host:*.sufiks` dla dopasowania sufiksu):

```yaml
client_groups:
  - name: "Dzieci"
    match: ["192.168.1.50", "192.168.1.0/28"]
    enabled: true
    allowlist: []
    denylist: ["strona-dla-doroslych.example"]
    blocklist_sources:
      - name: "Dodatkowa lista bezpieczna dla dzieci"
        url: "https://example.org/extra-blocklist.txt"
        enabled: true
  - name: "Goście"
    match: ["192.168.1.200/29"]
    enabled: false   # przepuszczanie: brak blokowania reklam/trackerów dla tej grupy
  - name: "Telefony"
    match: ["mac:AA:BB:CC:DD:EE:FF", "host:tablet-dzieci"]
    enabled: true
```

Dopasowanie `mac:` czyta tabelę ARP jądra (`/proc/net/arp`) - zawiera ona
tylko wpisy urządzeń, z którymi host DNS-shield faktycznie rozmawiał na
warstwie łącza, i jest wypełniana rzeczywistymi wpisami LAN tylko wtedy,
gdy kontener współdzieli sieć hosta (`network_mode: host` w
`docker-compose.yml`, lub konfiguracja macvlan); domyślna sieć bridge w
dostarczonym `docker-compose.yml` widzi tylko swój własny bridge, więc
wzorce `mac:` niczego tam nie dopasują. Dopasowanie `host:` używa tego
samego cache rozwiązanych nazw hostów co `dns.resolve_client_names`
powyżej i wymaga włączenia tego ustawienia - nazwa hosta klienta jest
znana dopiero po zakończeniu rozwiązywania dla niego przynajmniej raz,
więc zupełnie pierwsze zapytanie od nowego klienta nie może pasować do
wzorca `host:`.

Kolejność pierwszeństwa dla zapytania od dopasowanego klienta: lista
zablokowanych grupy > globalna lista zablokowanych > lista dozwolonych
grupy > globalna lista dozwolonych > `enabled: false` grupy (brak
filtrowania w ogóle) > listy blokad > własne, dodatkowe
`blocklist_sources` grupy. Lista zablokowanych wygrywa z listą dozwolonych
na obu poziomach, więc jawny wpis blokujący jest naprawdę "zawsze
zablokowany", nawet dla domeny, która też jest na liście dozwolonych (np.
po Unblock w logu zapytań, co dodaje domenę do listy dozwolonych - ponowne
ręczne zablokowanie tej samej domeny nadal działa); lista dozwolonych
wygrywa tylko z *listami blokad* (subskrybowanymi listami), co jest głównym
powodem, by w ogóle coś dodawać do listy dozwolonych. Zarządzaj grupami (i
ich listami dozwolonych/zablokowanych per grupa) z panelu lub edytując tę
listę bezpośrednio.

Własne `blocklist_sources` grupy to jej własne subskrybowane listy (te same
formaty hosts/AdBlock/plain i zachowanie pobierania/parsowania/buforowania
co globalna sekcja Blocklists), pobierane i dopasowywane *dodatkowo do*
globalnej listy blokad dla klientów w tej grupie - nigdy jako zamiennik.
Jest to celowo jednokierunkowe: grupa może stać się tylko *bardziej
restrykcyjna* niż domyślna (np. dodatkowa lista treści dla dorosłych ponad
zwykłymi listami reklam/trackerów dla grupy urządzeń dzieci). Chęć
posiadania *lżejszej* listy dla grupy jest już pokryta przez istniejącą
listę dozwolonych per grupa i przełącznik przepuszczania `enabled: false`
powyżej. Zarządzaj dodatkowymi źródłami grupy z jej karty w panelu, w
zakładce Clients, tuż pod jej listami dozwolonych/zablokowanych.

### Kontrola rodzicielska / SafeSearch

Dwa mechanizmy na poziomie DNS pokrywają obszar kontroli rodzicielskiej,
jaki resolwer DNS faktycznie może osiągnąć - oba są opt-in i oba budują na
`client_groups` powyżej, zamiast dodawać osobny podsystem:

- **Wymuszone SafeSearch / tryb ograniczony**: `dns.safe_search_enabled: true`
  (Settings -> DNS) przepisuje faktyczną odpowiedź A/AAAA dla własnych
  nazw hostów wyszukiwania/wideo Google, Bing, DuckDuckGo, YouTube i
  Yandex na udokumentowaną przez każdego dostawcę nazwę hosta
  wymuszającą tryb bezpieczny (np. `forcesafesearch.google.com`,
  `restrict.youtube.com`), rozwiązywaną na żywo przez skonfigurowane
  serwery nadrzędne i buforowaną dokładnie jak każda inna odpowiedź.
  Dotknięte są tylko konkretne nazwy hostów wyszukiwania/wideo
  (`google.<tld>`, `www.google.<tld>`, `youtube.com`, `bing.com`,
  `duckduckgo.com`, `yandex.ru`/`.com` i kilka odpowiedników) - inne
  subdomeny tej samej domeny (`mail.google.com`, `accounts.google.com`,
  `drive.google.com`) rozwiązują się normalnie, więc to nie dotyka
  niczego poza samą powierzchnią wyszukiwania/wideo. Grupa klientów może
  nadpisać ustawienie globalne własnym "nadpisaniem SafeSearch" (zakładka
  Clients, na karcie każdej grupy): zawsze włączone, zawsze wyłączone, lub
  dziedzicz ustawienie globalne - zwykły sposób, by wymusić je dla grupy
  urządzeń dzieci niezależnie od domyślnego ustawienia w całej sieci.
- **Listy blokad kategorii przez grupy klientów**: istniejący mechanizm
  `blocklist_sources` per grupa (powyżej) to też sposób na dodanie
  blokowania treści dla dorosłych, hazardu czy mediów społecznościowych
  wyłącznie dla konkretnych klientów. Selektor Suggested lists panelu na
  karcie każdej grupy zawiera kategorię "Parental control" - aktywnie
  utrzymywane listy HaGeZi NSFW, Gambling, Social Networks, Anti-Piracy i
  Fake/Scam-Sites - obok tego samego selektora w globalnej zakładce
  Blocklists, jeśli chcesz zastosować jedną z nich w całej sieci.

Żaden z tych mechanizmów nie widzi wewnątrz ruchu HTTPS ani nie inspekcjonuje
treści strony - to kontrola na poziomie DNS (która nazwa hosta rozwiązuje
się do czego), nie filtr treści ani produkt nadzorowanego przeglądania.
Technicznie sprawny nastolatek, który zmieni serwer DNS swojego urządzenia
albo użyje VPN, obchodzi to wszystko, tak samo jak w przypadku każdej
kontroli rodzicielskiej opartej na DNS (włącznie z AdGuard Home i Pi-hole) -
połącz to z blokowaniem przez router wychodzącego DNS-over-HTTPS/TLS do
firm trzecich i wymuszeniem całego DNS w sieci LAN przez DNS-shield, jeśli
faktycznie musi to działać.

Trzeci element, również opt-in per grupa: **harmonogram godziny snu**, który
blokuje każde zapytanie od klientów danej grupy podczas jednego lub więcej
okien czasowych - "brak internetu 22:00-07:00" zamiast "brak treści dla
dorosłych". Ustaw go z karty grupy w zakładce Clients (jedno okno: dni +
czas start/koniec, plus własna checkbox włączająca) lub przez
`client_groups[].schedule`:

```yaml
client_groups:
  - name: "Dzieci"
    match: ["192.168.1.50"]
    schedule:
      enabled: true
      timezone: ""            # puste = czas lokalny kontenera (ustaw TZ w docker-compose.yml)
      windows:
        - days: [0, 1, 2, 3, 4, 5, 6]   # poniedziałek=0 .. niedziela=6
          start: "22:00"
          end: "07:00"
```

Okno jest sprawdzane względem klientów grupy przy każdym zapytaniu -
wygrywa nawet z własną listą dozwolonych grupy, gdy jest aktywne (sens
blokady godziny snu jest taki, że jest całkowita), tak samo jak
`blocked_clients` wygrywa ze wszystkim poza `enabled: false`.
`start`/`end` mogą przechodzić przez północ (`22:00`-`07:00` powyżej
obejmuje dwa dni kalendarzowe); flaga `enabled` wyłącza całość bez utraty
zapisanego okna i domyślnie jest wyłączona dla grupy, która jej nie
ustawia, więc jest to w pełni opt-in.

### Całkowite blokowanie klienta

`blocked_clients` to osobny, silniejszy mechanizm niż wszystko powyżej:
IP/CIDR (lub wzorzec `mac:`/`host:`, ta sama składnia co `client_groups.match`
powyżej) tutaj oznacza, że *każde* zapytanie jest blokowane, dla *każdej*
domeny - "brak jakiejkolwiek komunikacji z tym hostem" zamiast reguły
ograniczonej do domeny. Ma priorytet nad `client_groups` i nad każdym
wpisem dozwolonych/zablokowanych per domena, choć wstrzymane okno
blokowania (zobacz niżej) nadal to omija, tak jak wszystko inne.

Przycisk panelu **Block host** robi to za Ciebie - obok każdego IP klienta,
gdziekolwiek jest pokazane (log zapytań, tabela "Top querying clients" w
zakładce Stats, oraz
[wyskakujące okno Enrich](#wzbogacanie-threat-intel-virustotal--abuseipdb--alienvault-otx--i-inne)
dla wyszukiwania IP) - i zmienia się na **Unblock host**, gdy dany klient
jest już zablokowany. Settings -> "Blocked clients" pokazuje wszystko
aktualnie zablokowane i pozwala dodawać lub usuwać wpisy (włącznie z
zakresami CIDR) ręcznie:

```yaml
blocked_clients:
  - "192.168.1.50"
  - "192.168.1.0/28"
```

### Blokowanie docelowego IP, nawet dla domeny z listy dozwolonych

`blocked_answer_ips` (Settings -> Own lists -> "Blocked destination IPs")
jest sprawdzane po faktycznym rozwiązaniu zapytania, względem każdego
adresu A/AAAA w odpowiedzi - niezależnie od tego, czy sama domena jest na
liście dozwolonych. Wpis na liście dozwolonych domeny chroni wyłącznie
przed dopasowaniem po *nazwie domeny* (listy blokad, `denylist`, lista
zablokowana regex); nigdy nie miał gwarantować, że jakikolwiek IP, do
którego ta domena akurat teraz się rozwiązuje, jest bezpieczny, a
przejęta lub poddana rebindingowi domena może w każdej chwili rozwiązać
się do innego, złośliwego IP, bez zmiany swojej nazwy. Ta lista wyłapuje
ten przypadek: dodaj tu znany-zły IP/CIDR, a każde zapytanie rozwiązujące
się do niego zostanie zablokowane (NXDOMAIN/null_ip, tak samo jak każda
inna blokada), nawet dla domeny, którą jawnie dodałeś do listy dozwolonych.
Sprawdzane przy każdym serwowaniu, włącznie z odpowiedziami z cache, więc
dodanie wpisu tutaj obowiązuje natychmiast, bez czekania na wygaśnięcie
TTL. Nie dotyczy
[niestandardowych rekordów DNS ("rewrites")](#niestandardowe-rekordy-dns-rewrites) -
to adresy IP, które sam skonfigurowałeś, nie coś, co DNS-shield rozwiązał z
internetu.

```yaml
blocked_answer_ips:
  - "203.0.113.5"
  - "203.0.113.0/24"
```

Poza listą ręczną, "Malicious-IP lists" w tej samej sekcji pozwala
subskrybować adres URL tak samo jak Blocklists: jeden IP lub CIDR na
linię (`#`/`!`/`;` dla komentarzy, wszystko inne parsowane automatycznie -
większość publicznych feedów threat-intel z adresami IP już tak wygląda),
pobierane/buforowane/odświeżane wg tego samego harmonogramu
`blocklists.refresh_interval_hours` co listy blokad domen, z tym samym
mechanizmem awaryjnym powrotu do ostatniej dobrej zbuforowanej kopii przy
błędzie pobierania. Dopasowanie jest O(1) dla dokładnego IP i krótkim
liniowym przeszukiwaniem dla zakresów CIDR, obliczane raz na odświeżenie,
a nie na zapytanie, więc duży subskrybowany feed nie dodaje narzutu per
zapytanie.

```yaml
blocked_answer_ip_sources:
  - name: "Przykładowy feed threat-intel"
    url: "https://example.org/malicious-ips.txt"
    enabled: true
```

### Wyłączanie IPv6

Jeśli Twoja sieć nie używa IPv6, włącz `dns.block_ipv6` (panel: Settings ->
DNS -> "Disable IPv6"). Zapytania AAAA dostają wtedy natychmiast pustą
odpowiedź `NOERROR` - nie NXDOMAIN, co błędnie powiedziałoby klientowi
dual-stack, że cała nazwa nie istnieje - więc klienci od razu przechodzą na
IPv4, zamiast najpierw czekać na przekroczenie limitu czasu połączenia
IPv6. To całkowicie pomija listę blokad i serwer nadrzędny dla zapytań
AAAA, i nie są one też zapisywane w logu zapytań - przy wyłączonym IPv6,
każde urządzenie pyta o AAAA dla wszystkiego, więc logowanie ich byłoby
tylko szumem przy każdym pojedynczym wyszukiwaniu.

### Blokowanie domen w skryptach innych niż łaciński

`dns.block_non_latin` (panel: Settings -> DNS -> "Block non-Latin-script
domains") blokuje domeny używające cyrylicy, arabskiego, CJK, hangul,
greckiego, hebrajskiego, tajskiego, dewanagari lub podobnych pism, po
zdekodowaniu ich etykiet punycode/IDNA z powrotem do Unicode. Zwykłe domeny
ASCII i akcentowane łacińskie (`café.fr`, `münchen.de`) nigdy nie są
dotknięte - tylko znaki spoza pisma łacińskiego to wyzwalają. Globalna
lista dozwolonych/lista grupy zawsze nadpisuje to, jeśli potrzebujesz
konkretnego wyjątku. Domyślnie wyłączone.

### Cache odpowiedzi DNS

`dns.cache_enabled` (domyślnie włączone) trzyma rozwiązane odpowiedzi w
pamięci, kluczowane wg domeny+typu rekordu, tak długo, jak mówi ich własny
TTL - ograniczone między `cache_min_ttl_seconds` a `cache_max_ttl_seconds`
(przydatne, jeśli jakiś serwer nadrzędny zwraca nietypowo krótkie/długie
TTL, którym nie ufasz) i ograniczone do `cache_max_entries` z wypieraniem
LRU. Powtórne wyszukiwanie czegoś, co nadal jest w cache, jest odpowiadane
natychmiast, bez przekazywania do serwera nadrzędnego w ogóle - niższe
opóźnienie i mniej ruchu wychodzącego dla nazw hostów CDN/reklam/trackerów,
które stanowią większość powtarzalnego ruchu. Wyłącznie pamięć procesu:
nic nie jest zapisywane na dysk i po restarcie jest znowu pusty. Zakładka
Stats pokazuje aktualną liczbę wpisów i współczynnik trafień; Settings ->
DNS answer cache ma przycisk "Clear cache", by opróżnić go na żądanie
(np. zaraz po zmianie serwerów nadrzędnych, by przestać serwować cokolwiek
odpowiedziane przez starego).

### Lokalna strona "zablokowano"

Przy `dns.block_mode: "null_ip"`, zablokowana domena normalnie po prostu
przekracza limit czasu lub odmawia połączenia na `blocked_ipv4` -
technicznie poprawne, ale niezbyt informatywne dla tego, kto na to trafił.
Włącz `dns.block_page_enabled`, a sam DNS-shield zaserwuje małą stronę
"ta domena jest zablokowana" zamiast tego: skieruj `blocked_ipv4` na
własny, osiągalny adres IP LAN tego hosta, a zwykłe żądanie HTTP dla
zablokowanej domeny wyląduje na `dns.block_page_port` (domyślnie 80) i
dostanie stronę nazywającą domenę (odczytaną wprost z nagłówka `Host`
żądania) **i powód blokady** - która subskrypcja listy blokad pasowała,
ręczny wpis na liście zablokowanych, albo sam klient będący zablokowanym -
sprawdzone w ten sam sposób co ikona (i) logu zapytań, względem Twojej
*aktualnej* konfiguracji, a nie tego, co było prawdą w momencie, gdy
oryginalnie udzielono odpowiedzi DNS.

To działa wyłącznie dla zwykłego HTTP. **HTTPS nie może pokazać strony w
ten sposób** - przeglądarka odrzuca sprawdzenie certyfikatu, zanim w ogóle
wyśle żądanie, co jest fundamentalnym ograniczeniem blokowania na poziomie
DNS, a nie czymś do obejścia tutaj; robienie tego oznaczałoby terminowanie
TLS certyfikatem, któremu klient nie ufa, czyli MITM, czego ten projekt
celowo nie robi. Domyślnie wyłączone; zmiana któregokolwiek pola wymaga
restartu kontenera, tak samo jak adres/port nasłuchu DNS.

Uruchamiane w Dockerze: kontener domyślnie publikuje tylko 53/udp, 53/tcp i
3000/tcp - odkomentuj mapowanie portów w `docker-compose.yml` (pasujące do
ustawionego `block_page_port`), by faktycznie dotrzeć tutaj z innych
urządzeń w Twojej sieci.

### Przeglądarka logu zapytań, szybkie blokowanie i szybkie ukrywanie

Sekcja **Query log** panelu przeszukuje pełną, zachowaną historię (nie
tylko kilka ostatnich wpisów) - filtruj wg fragmentu domeny, fragmentu
klienta (IP lub rozwiązana nazwa), typu rekordu, zablokowane/dozwolone
oraz zakresu czasu, z paginacją przez "Load more". Każdy wiersz ma przycisk
**Block**/**Unblock** (który akurat pasuje do bieżącego stanu wiersza) oraz
przycisk **Hide**.

Block dodaje domenę do globalnej listy zablokowanych; Unblock cofa
cokolwiek spowodowało zablokowanie tego konkretnego zapytania - usuwa
ręczny wpis listy zablokowanej, jeśli to z tego powodu (lista zablokowanych
zawsze wygrywa z listą dozwolonych - zobacz
[Polityki per klient/grupa](#polityki-per-klientgrupa) - więc pozostawienie
nieaktualnego wpisu na liście zablokowanych inaczej po cichu by to
udaremniło), i też dodaje domenę do globalnej listy dozwolonych, co
nadpisuje dopasowanie z listy blokad. Hide dodaje domenę do
`logging.ignored_domains` (zobacz niżej) - skrót do tej samej czynności co
w Settings, minus pisanie. Istniejące wiersze dla tej domeny znikają z
aktualnie wyświetlanej strony natychmiast, dla informacji zwrotnej, ale
tylko przyszłe zapytania faktycznie przestają być logowane - Hide nie
usuwa niczego już zapisanego w `stats.db` i nie wpływa na rozwiązywanie/
blokowanie, tylko na to, co pokazuje się w tym logu.

**Delete all logged queries** (Settings -> Cleans) usuwa każdy wiersz z
`stats.db` - pełny reset logu zapytań, nie filtrowane usunięcie.
Nieodwracalne; panel najpierw prosi o potwierdzenie.

Zablokowany wiersz pokazuje też ikonę (i) - najedź na nią, by zobaczyć
dokładnie, dlaczego to zapytanie zostało zablokowane: która subskrypcja
listy blokad pasowała (wg nazwy), ręczny wpis listy zablokowanej (globalny
lub konkretnej grupy klientów), lub filtr skryptu innego niż łaciński.
Jest to obliczane w momencie zapytania i zapisywane per wiersz (kolumna
`reason` w `stats.db`, wypełniona wstecznie jako `null` dla wierszy
zalogowanych przed istnieniem tej funkcji - najechanie nic nie pokazuje
dla tych wierszy).

Każda domena i adres klienta w logu ma też obok siebie przycisk **Copy**,
by skopiować dokładną wartość do schowka (np. do wklejenia w wyszukiwanie,
regułę zapory sieciowej, albo zgłoszenie), bez konieczności ręcznego
zaznaczania tekstu. Adres klienta dostaje też przycisk **Block host** -
zobacz [Całkowite blokowanie klienta](#całkowite-blokowanie-klienta) powyżej.

Gdy jest znany, faktyczny adres A/AAAA zwrócony klientowi dla tego
zapytania pokazuje się tuż pod jego domeną (np. `→ 93.184.216.34`), z
własnymi przyciskami Copy i Enrich - inny cel wyszukiwania niż sama
domena, więc jego wynik Enrich jest niezależny (reputacja domeny to nie to
samo pytanie, co jakikolwiek IP, do którego akurat teraz się rozwiązała).
Jest to null IP dla zapytania zablokowanego trybem `null_ip`, IP rewrite'a,
IP trafienia w cache, lub pierwszy rekord A/AAAA w prawdziwej odpowiedzi z
serwera nadrzędnego (wszelkie przeskoki CNAME są pomijane) - i jest
całkowicie pominięty dla blokady NXDOMAIN lub typu zapytania bez adresu
(MX, TXT, ...), gdzie nie ma nic do pokazania. Zapisywane per wiersz
(kolumna `answer_ip` w `stats.db`, wypełniona wstecznie jako `null` dla
wierszy zalogowanych przed istnieniem tej funkcji - nic się nie pokazuje
dla tych wierszy).

### Zakładka Stats

Wykres **Query trend** otwiera zakładkę: łączna liczba zapytań vs.
zablokowane w czasie, z filtrem zakresu (ostatnie 24 godziny, 7 dni lub 30
dni), który po stronie serwera na nowo grupuje tę samą historię `stats.db`
(odpowiednio punkty godzinowe/6-godzinne/dzienne), zamiast po prostu
przycinać to, co ostatnie zapytanie już pobrało. Najedź (lub przeciągnij
dotykiem na telefonie) na dowolny punkt, by zobaczyć dokładną liczbę w tym
momencie. Żadne nowe dane nie są zbierane dla tego - to ten sam log
zapytań, który już czyta każda inna tabela w tej zakładce, po prostu
zagregowany inaczej.

Karty dla łącznej liczby/zablokowanych zapytań, współczynnika blokowania,
liczby domen na liście blokad, wpisów cache i współczynnika trafień cache,
plus pięć tabel obliczonych z pełnej zachowanej historii w `stats.db` (nie
tylko tego, co aktualnie widać gdzie indziej): **Top blocked domains**,
**Top queried domains** (wszystko, blokowane i dozwolone - przydatne do
wypatrywania, z czym urządzenie faktycznie się łączy), **Top querying
clients** (najbardziej aktywne urządzenie w sieci), **Query types**
(podział wg A/AAAA/CNAME/...) oraz **Blocked by** (która konkretna
subskrypcja listy blokad lub reguła odpowiada za najwięcej blokad - te
same powody co ikona (i) logu zapytań, tylko zagregowane). Wszystko to
aktualizuje się na żywo co 10 sekund wraz z resztą panelu. Tak jak log
zapytań, tabele domen/klientów mają przycisk **Copy** przy każdym wierszu,
a wiersze klientów dostają też przycisk **Block host**.

### Wzbogacanie threat-intel (VirusTotal / AbuseIPDB / AlienVault OTX / i inne)

Każda domena i adres IP pokazane w zakładkach Query log i Stats mają też
przycisk **Enrich**, który sprawdza reputację tego wskaźnika przez
[VirusTotal](https://www.virustotal.com/), [AbuseIPDB](https://www.abuseipdb.com/),
[AlienVault OTX](https://otx.alienvault.com/) i/lub usługę reputacji własną -
skonfigurowaną w Settings -> Threat intelligence.

**Uruchamia się to wyłącznie po kliknięciu.** Nie ma skanowania w tle,
automatycznego wyszukiwania dla każdego zapytania, harmonogramu ani
wyszukiwania wywołanego wczytaniem panelu lub rozwiązaniem zapytania DNS -
kliknięcie Enrich to jedyny sposób, w jaki kiedykolwiek wykonywane jest
połączenie wychodzące do którejkolwiek z tych usług, i tylko dla
pojedynczego wskaźnika, który kliknąłeś.

Sam przycisk jest wyszarzony i nieklikalny, z podpowiedzią wyjaśniającą
dlaczego, dopóki przynajmniej jedno źródło nie jest faktycznie użyteczne -
więc nie ma nic do przypadkowego kliknięcia, zanim cokolwiek skonfigurujesz.

**Usługi publiczne (VirusTotal/AbuseIPDB/OTX)** potrzebują dwóch rzeczy,
zanim Enrich którąkolwiek z nich wywoła: klucza API (klucze darmowego
poziomu działają) *oraz* przełącznika **"Enable public lookups"** w
Settings, który jest **domyślnie wyłączony**. To celowa druga bramka ponad
kluczem - te trzy to jedyna kategoria połączeń wychodzących w tym
projekcie, które opuszczają Twoją własną sieć, a DNS-shield istnieje
konkretnie dlatego, że inny bloker DNS wykonał dokładnie taki rodzaj
połączenia bez pytania (zobacz
[Dlaczego nie użyć po prostu AdGuard Home?](#dlaczego-nie-użyć-po-prostu-adguard-home)
powyżej) - więc samo zapisanie klucza nigdy nie zaczyna niczego nigdzie
wysyłać; trzeba też przełączyć przełącznik. Skonfigurowanie klucza, gdy
przełącznik jest wyłączony, nie jest zmarnowane: wyskakujące okno nadal
pokazuje to źródło jako "disabled", a nie "not configured", więc możesz
przygotować je z wyprzedzeniem i przełączyć, gdy będziesz gotowy.
AbuseIPDB nie ma punktu końcowego do wyszukiwania domen, więc jest pomijany
(nie traktowany jako błąd) dla celów będących domenami i odpytywany
wyłącznie dla celów będących adresami IP; VirusTotal i OTX obsługują oba.

**Pięć kolejnych publicznych źródeł** stoi obok tych trzech, pod tym samym
przełącznikiem i tą samą bramką wymagającą darmowego klucza:
[GreyNoise](https://www.greynoise.io/) i [Shodan](https://www.shodan.io/)
(oba wyłącznie dla IP) dodają klasyfikację skanowania internetu (czy ten
adres to szum, znana, nieszkodliwa usługa biznesowa, czy coś aktywnie
złośliwego) oraz rekonesans eksponowanych usług (otwarte porty, znane CVE,
tagi nadużyć); [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch, działa dla
domen i IP, wymaga darmowego Auth-Key z ich strony) sprawdza, czy dany
wskaźnik hostował znane złośliwe adresy URL, na żywo lub historycznie.
**Wiek domeny RDAP** i **transparentność certyfikatów
[crt.sh](https://crt.sh/)** to dwa wyjątki od wymogu posiadania klucza API
w ogóle - obie wyłącznie dla domen, obie darmowymi publicznymi
wyszukiwaniami bez konta czy klucza, kontrolowane wyłącznie własnym
przełącznikiem on/off (nadal za przełącznikiem publicznych wyszukiwań,
ponieważ nadal są to połączenia z firmami trzecimi). RDAP oznacza domenę
zarejestrowaną podejrzanie niedawno - ten sam instynkt co przy
[wykrywaniu typosquattingu](#wykrywanie-typosquattingu) powyżej, świeża
rejestracja obok nazwy zbliżonej do marki to klasyczny sygnał phishingu -
a crt.sh po prostu raportuje, ile certyfikatów i unikalnych nazw subdomen
jest zarejestrowanych dla tej domeny, dla Twojej własnej wiedzy. Wszystkie
osiem publicznych źródeł degraduje się w ten sam sposób: pomijane (nie
jako błąd) dla typu celu, którego nie obsługują, pokazywane jako wyłączone
podczas gdy przełącznik publicznych wyszukiwań jest wyłączony, pokazywane
jako nieskonfigurowane podczas gdy ich własny klucz/przełącznik jest
wyłączony, oraz pokazywane jako nieudane z powodem w prostym języku, jeśli
samo wywołanie się nie powiedzie (zły klucz, limit zapytań, brak danych w
rejestrze, niedostępność).

Linia statusu zapisanego klucza w Settings pokazuje jego pierwszy i
ostatni znak (np. `a***********f`) zamiast po prostu "configured" -
wystarczy, by rozpoznać, *który* klucz jest zapisany (powiedzmy, jeśli
trzymasz więcej niż jedno konto VirusTotal), bez wysyłania pełnej wartości
z powrotem do Twojej przeglądarki; sam klucz jest maskowany po stronie
serwera i nigdy nie wraca w pełni po zapisaniu.

**Twoja własna, lokalna usługa** nie ma takiego przełącznika - to nie
połączenie z firmą trzecią, to infrastruktura, którą sam uruchamiasz i
sam na nią skierowałeś. Włącz **"Enable your own (local) reputation
service"** i podaj adres URL (np. coś w Twojej własnej sieci LAN lub
narzędzie samodzielnie hostowane); DNS-shield wysyła `POST` z JSON
`{"target": "<domena-lub-ip>", "type": "domain"|"ip"}` na ten URL (z
`Authorization: Bearer <klucz>`, jeśli go ustawiłeś) i oczekuje w
odpowiedzi `{"verdict": "safe"|"low"|"medium"|"high"|"critical", "score":
0-100, "summary": "..."}` (`score`/`summary` opcjonalne) - wystarczająco
mały kontrakt, by postawić przed nim cokolwiek: skrypt, wewnętrzne
narzędzie, nawet inny, otwartoźródłowy feed, któremu już bardziej ufasz.
Odpowiedź, w której brakuje `verdict` albo jest ono zniekształcone, jest
traktowana jako nieudane wyszukiwanie, a nie zgadywana.

Wynik otwiera się w **nowym oknie przeglądarki**, z kolorem tła ustawionym
wg najgorszego werdyktu spośród wszystkich źródeł, które faktycznie coś
zwróciły - spokojna zieleń dla czystego/bezpiecznego wyniku, eskalująca
przez żółty i pomarańczowy do czerwonego dla czegoś oznaczonego jako
złośliwe - wraz z własnym werdyktem i krótkim podsumowaniem każdego źródła
(silniki oznaczające, wynik pewności nadużycia, liczba pulse'ów,
podsumowanie Twojej własnej usługi itd.). Źródło, które jest
nieskonfigurowane, wyłączone (przełącznik publiczny off) lub nieudane
(zły klucz, limit zapytań, brak danych w rejestrze, niedostępne, źle
sformatowana odpowiedź) pokazuje dlaczego, zamiast wywalić wyskakujące
okno.

Każdy wynik - włącznie z nieskonfigurowanymi/wyłączonymi/nieudanymi - jest
zapisywany lokalnie w `data/enrichment.db`, wyłącznie po to, byś miał
zapis przeszłych wyszukiwań; nic w tej bazie nigdzie nie jest wysyłane.

Wyskakujące okno pokazuje też tabelę **historii wyszukiwań** dla tego
samego celu - każdy poprzedni raz, kiedy kliknąłeś Enrich dla niego, od
najnowszego, z werdyktem i wynikiem, jaki miał *w tamtym momencie* - więc
możesz zobaczyć, czy reputacja wskaźnika zmieniła się od ostatniego
sprawdzenia, bez opuszczania wyskakującego okna. Pokazywane są tylko
poprzednie wyniki dla dokładnie tego celu, który właśnie wyszukałeś
(`GET /api/enrich/history?target=...`), pobierane wprost z
`enrichment.db`; wyszukiwanie po raz pierwszy pokazuje po prostu jeden
wiersz z bieżącym wynikiem.

Dla celu będącego IP, które jest klientem, jaki odpytywał DNS-shield
(kolumna klienta w logu zapytań/Stats i edytor grup klientów zawsze to
oznaczają; wyświetlanie rozwiązanego IP pod domeną w logu zapytań, zobacz
[Przeglądarka logu zapytań](#przeglądarka-logu-zapytań-szybkie-blokowanie-i-szybkie-ukrywanie)
powyżej, to jedyny przypadek, gdy cel będący IP jest zamiast tego
jakimkolwiek adresem, do którego akurat rozwiązała się domena - nie
klientem, więc żadna kontrola blokowania nie ma tu sensu) - wyskakujące
okno ma przycisk **Block this host**/**Unblock this host**, tę samą
funkcję co przycisk "Block host" logu zapytań/Stats, tylko osiągalną bez
opuszczania wyskakującego okna; zobacz
[Całkowite blokowanie klienta](#całkowite-blokowanie-klienta) powyżej,
co faktycznie robi.

Dla celu będącego **domeną**, dla której wrócił ogólny werdykt **safe**,
wyskakujące okno ma też przycisk **Add to allowlist** - skrót do dokładnie
tego samego czyszczenia, co robi przycisk Unblock logu zapytań (zobacz
[Przeglądarka logu zapytań](#przeglądarka-logu-zapytań-szybkie-blokowanie-i-szybkie-ukrywanie)
powyżej): najpierw czyści każdy ręczny wpis listy zablokowanej dla niej, a
potem dodaje ją do globalnej listy dozwolonych, ponieważ wpis listy
zablokowanej zawsze wygrywa z listą dozwolonych i inaczej po cichu
utrzymałby blokadę. Nieoferowane dla celów będących IP - lista
dozwolonych/zablokowanych DNS-shield dopasowuje *nazwy* zapytań, nie
literały IP, więc nie ma równoważnej akcji "dodaj ten IP do listy
dozwolonych" do zaoferowania.

### Lokalne wykrywanie anomalii

Settings -> Anomalies konfiguruje opcjonalne sprawdzanie w tle Twojego
własnego logu zapytań pod kątem garści prostych, statystycznych sygnałów
ostrzegawczych per klient - bez ML, bez wywołań chmurowych, nic poza
arytmetyką na danych już siedzących w `stats.db`. **Domyślnie wyłączone.**
Włącz to, a DNS-shield ponownie sprawdza ostatnią aktywność na czasomierzu
(`anomaly.check_interval_minutes`, domyślnie co 5 minut) w kroczącym oknie
patrzenia wstecz (`anomaly.window_minutes`, domyślnie 15 minut), niezależnie
dla każdego klienta, który go odpytywał w tym oknie:

- **Wysoki stosunek zablokowanych zapytań** - duży udział zapytań klienta w
  oknie był zablokowany. Klasyczny znak zainfekowanej aplikacji/urządzenia
  bombardującego domeny reklamowe/trackerów/malware. Ocenianie tylko po
  tym, jak klient wykona przynajmniej `anomaly.min_queries` (domyślnie 20)
  zapytań w oknie, więc garść zapytań nie może tego wywołać przy małej
  próbce.
- **Wybuch odrębnych domen** - klient rozwiązał niezwykle dużą liczbę
  *odrębnych* domen w oknie (`anomaly.domain_burst_threshold`, domyślnie
  50), **i** znacząca część tych domen wygląda na losowo wygenerowane
  zamiast prawdziwych słów. Typowe dla malware DGA (domain generation
  algorithm) cyklicznie przełączającego się przez kandydackie domeny
  command-and-control. "Wygląda na losowo wygenerowane" to entropia
  Shannona własnej etykiety każdej domeny (np. `kq7xzpqm3f` z
  `kq7xzpqm3f.info`) - oceniana wyłącznie dla etykiet o długości co
  najmniej `anomaly.domain_burst_min_label_length` znaków (domyślnie 10;
  krótsze etykiety są zbyt niepewne do wiarygodnej oceny) względem progu
  losowości (`anomaly.domain_burst_min_entropy`, domyślnie 3,3
  bita/znak); wybuch uruchamia się dopiero, gdy przynajmniej
  `anomaly.domain_burst_entropy_fraction` (domyślnie 50%) odrębnych domen
  przekracza ten próg. Ta druga bramka jest tym, co powstrzymuje zwykły
  wybuch wysokiej kardynalności - strona ładująca trzydzieści różnych
  *prawdziwych* domen dostawców reklam/trackerów, co też jest wybuchem
  odrębnych domen - przed oznaczeniem: prawdziwe słowa konsekwentnie
  oceniają się niżej niż faktycznie losowe ciągi o podobnej długości,
  chociaż sama entropia na poziomie znaków to przybliżenie, nie pewność,
  dla pojedynczej domeny.
- **Wybuch odrębnych zablokowanych domen** - klient trafił w niezwykle dużą
  liczbę odrębnych *zablokowanych* domen w oknie
  (`anomaly.blocked_domain_burst_threshold`, domyślnie 15) - silniejszy
  sygnał niż samo sprawdzanie stosunku, ponieważ nie da się tego wytłumaczyć
  jedną stroną pełną reklam przeładowującą tę samą garść domen reklamowych.
- **Tunelowanie DNS** - klient odpytywał niezwykle dużą liczbę *odrębnych
  subdomen tej samej domeny* w oknie (`anomaly.dns_tunneling_threshold`,
  domyślnie 30), z których większość wygląda długo i losowo, zamiast
  normalnej garści subdomen prawdziwej strony - ta sama ocena entropii co
  przy sprawdzaniu wybuchu domen powyżej, ale zastosowana do pierwszej
  etykiety każdej subdomeny, a nie całej domeny
  (`anomaly.dns_tunneling_min_label_length`, domyślnie 20;
  `anomaly.dns_tunneling_min_entropy`, domyślnie 3,0 bita/znak).
  Tunelowanie DNS nadużywa DNS jako ukrytego kanału danych, kodując
  fragment danych w unikalną subdomenę na zapytanie
  (`k3f9a...92mz.tunnel.example.com`, jedno zapytanie na fragment) - to
  korporacyjna technika wykrywania tego zjawiska w bezpieczeństwie DNS,
  zastosowana do *liczby* domen, a nie surowej objętości ruchu, więc nie
  potrzebuje żadnych nowych danych poza tymi, które już są logowane.
  Różnica względem wybuchu odrębnych domen powyżej: ten uruchamia się na
  wielu różnych *domenach* (malware DGA próbujący kandydackich domen C2),
  ten drugi uruchamia się na wielu różnych *subdomenach jednej domeny*
  (dane wykradane przez jedną domenę kontrolowaną przez atakującego).
- **Skanowanie PTR** - klient wykonał niezwykle dużą liczbę odwrotnych
  wyszukiwań DNS (PTR) względem *prywatnych/lokalnych* adresów IP w oknie
  (`anomaly.ptr_scan_threshold`, domyślnie 15) - jedno urządzenie metodycznie
  pytające "kim jest 192.168.1.1? kim jest 192.168.1.2? ..." wygląda jak
  narzędzie mapujące sieć, wyliczające hosty w LAN, nie normalne
  przeglądanie. Liczą się wyłącznie cele z zakresów prywatnych
  (dekodowane z odwróconej nazwy zapytania `in-addr.arpa`/`ip6.arpa`),
  ponieważ wyszukiwania PTR względem publicznych IP są niczym niezwykłym;
  ważność eskaluje z `medium` do `high` przy podwojeniu progu.

Każda oznaczona anomalia jest zapisywana lokalnie w `data/anomalies.db` i
pokazywana we własnej, głównej zakładce **Anomalies** (między Logs a
Stats, z odznaką liczby nieprzyjętych do wiadomości), z klientem, co
zostało wywołane, czytelnym dla człowieka podsumowaniem oraz (ponownie
używając tych samych przycisków co log zapytań/Stats/wyskakujące okno
Enrich) szybkimi akcjami **Enrich**/**Block host** na IP klienta -
**Acknowledge**, by odrzucić ją z domyślnego widoku bez usuwania, lub
**Remove**, by usunąć ją całkowicie; **Clear all** czyści całą tabelę.
Settings -> Anomalies zawiera konfigurację (progi, obserwowane
domeny/listy) - ten sam podział, co zakładka Logs (dane) vs. Settings ->
Logging (konfiguracja).

Przycisk **Show domains** na dowolnym wierszu otwiera wyskakujące okno
listujące faktyczne nazwy domen stojące za zagregowaną liczbą tej anomalii
(np. które 12 domen złożyło się na trafienie "12 distinct blocked
domains") - odtwarzane na żądanie z logu zapytań dla tego klienta i okna
czasowego, nie przechowywane redundantnie w samej anomalii. Domena z
`logging.ignored_domains`/`ignored_clients` nigdy się tu nie pojawia, z
tego samego powodu, dla którego nigdy nie pojawia się w ogóle w logu
zapytań: nigdy nie jest zapisywana do `stats.db` (Settings -> Logging ->
"Excluded from the log").

Przycisk **Check now** uruchamia sprawdzenie natychmiast, zamiast czekać
na czasomierz, przydatne zaraz po zmianie progów. **Reanalyse** robi coś
innego: wybierz historyczny zakres (12/24/48 godzin, lub 7/14/30 dni), a
narzędzie przechodzi przez cały ten zakres w porcjach wielkości
`anomaly.window_minutes`, ponownie uruchamiając dokładnie te same
heurystyki dla każdej porcji, tak jakby detektor tykał nieprzerwanie przez
cały ten okres - przydatne po zmianie progów, albo do audytu odcinka
historii, dla którego nie miałeś włączonego wykrywania. Nadal obowiązuje
przerwa (cooldown) per klient/typ anomalii, w porządku chronologicznym,
więc wybuch obejmujący kilka kolejnych porcji uruchamia się tylko raz.
Nigdy nie wysyła powiadomienia o tym, co znajdzie (retroaktywny audyt to
nie żywe wydarzenie warte alarmowania kogokolwiek), choć wyniki nadal
lądują na normalnej liście anomalii, ze znacznikiem czasu odpowiadającym
temu, kiedy historyczna aktywność faktycznie się zdarzyła, a nie kiedy
uruchomiono ponowną analizę. Zakres 7 dni lub dłuższy skanuje realną ilość
danych i może chwilę potrwać - panel ostrzega o tym przed uruchomieniem.

Utrzymujący się warunek nie zasypuje świeżym wierszem co każdy cykl: gdy
dana kombinacja klient/typ anomalii się uruchomi, jest wyciszona przez
`anomaly.cooldown_minutes` (domyślnie 60), zanim może uruchomić się
ponownie.

Działa to całkowicie na własnym wątku w tle, odłączonym od rozwiązywania
DNS - wyłącznie czyta `stats.db` na czasomierzu i zapisuje do własnego
`anomalies.db`, nigdy nie dotykając ścieżki odpowiadania na zapytania.
Błąd tutaj może w najgorszym razie przestać produkować nowe alerty; nie
może zepsuć ani spowolnić rozwiązywania DNS.

### Wykrywanie typosquattingu

Settings -> DNS ma osobny przełącznik "Detect typosquatting" (też
domyślnie wyłączony), który sprawdza każde zapytanie względem listy znanych
domen marek pod kątem dwóch rzeczy, których prawdziwa wizyta w tej marce
nigdy by nie wyprodukowała:

- **Bliski wariant literowy** - jeden lub dwa znaki różne od prawdziwej
  domeny (`paypa1.com`, `faceb00k.com`, `gooogle.com`), mierzony jako
  [odległość edycyjna Levenshteina](https://en.wikipedia.org/wiki/Levenshtein_distance)
  między własną etykietą odpytywanej domeny a etykietą chronionej domeny,
  w granicach `dns.typosquat_max_distance` (domyślnie 2).
- **Nazwa marki osadzona w dłuższej domenie** - `paypal-security-check.com`,
  `secure-allegro-login.pl` - klasyczny wzorzec combosquattingu, którego
  sama odległość edycyjna nie wyłapie, ponieważ wstawienie tuzina dodatkowych
  znaków to duża odległość, mimo że nazwa marki siedzi tam niezmieniona.

Dokładne dopasowanie lub prawdziwa subdomena samej chronionej domeny
(`mail.google.com`, `accounts.google.com`) nigdy nie jest jawnie oznaczana -
tylko coś, co jest *blisko, ale nią nie jest*. Dopasowanie zawsze uruchamia
alert przez ten sam pipeline co heurystyki anomalii powyżej (widoczny w
zakładce Anomalies, zdolny do powiadomień, własna przerwa per
klient/domena - `dns.typosquat_cooldown_minutes`, domyślnie 30);
`dns.typosquat_action` (też Settings -> DNS) osobno kontroluje, co dzieje
się z samą *odpowiedzią*:

- `"alert"` (domyślnie) - rozwiąż odpytywaną domenę normalnie. Alert jest
  jedynym efektem; nic w odpowiedzi się nie zmienia.
- `"redirect_real"` - rozwiąż faktyczny adres samej *chronionej* domeny i
  zwróć go pod nazwą, która faktycznie została odpytana, więc klient,
  który wpisał `paypa1.com`, transparentnie ląduje na prawdziwym PayPal
  zamiast tego, na co `paypa1.com` faktycznie wskazuje. Używa tego samego
  mechanizmu rozwiązywania-innej-nazwy-hosta co
  [wymuszone SafeSearch](#kontrola-rodzicielska--safesearch) powyżej,
  włącznie z przechodzeniem przez cache odpowiedzi w ten sam sposób.
- `"redirect_custom"` - zawsze odpowiadaj jednym stałym adresem ustawionym
  w `dns.typosquat_redirect_ip`, np. lokalną stroną wyjaśniającą, co się
  stało (taką stronę uruchamiasz sam - DNS-shield jej nie dostarcza).
  Wraca do normalnego rozwiązywania, jeśli pole jest puste, zamiast
  odpowiadać niczym.

`"redirect_real"` to decyzja warta jawnego wypunktowania: jest wygodna
(pomyłkowo wpisana nazwa marki po cichu nadal działa), ale też oznacza, że
DNS-shield zgaduje, co użytkownik *chciał* wpisać, zamiast po prostu
raportować, co *faktycznie* odpytał - rozsądne dla uczciwej literówki,
mniej rozsądne, jeśli wolałbyś, żeby człowiek spojrzał na każde trafienie,
zanim cokolwiek automatycznie rozwiąże się inaczej. `"alert"` zostawia tę
decyzję Tobie; bliski, ale błędny strzał to realny sygnał, nie pewność, a
fałszywe trafienia tutaj wylądowałyby na legalnym ruchu (domena, która
akurat jest kilka znaków od nazwy marki z zupełnie niepowiązanych powodów),
zamiast zostać po cichu wchłonięte tak, jak mógłby zrobić to zbyt szeroki
wpis listy blokad.

Own lists -> Typosquat protection pokazuje wbudowaną listę ~50 chronionych
domen (główne marki technologiczne/finansowe/kurierskie plus garść często
atakowanych polskich usług - banki, Allegro, InPost, operatorzy komórkowi)
i pozwala dodać własne ponad nią - powiedzmy, domenę własnej firmy. Ta
lista jest z założenia wyłącznie addytywna, to samo rozumowanie co przy
dodatkowych źródłach listy blokad grupy klientów: możesz sprawić, by
sprawdzanie obejmowało więcej, nie po cichu usunąć jeden z wyselekcjonowanych
domyślnych wpisów.

To sprawdzanie per zapytanie, w czasie rzeczywistym (w przeciwieństwie do
heurystyk okienkowych powyżej), ale tanie: odległość jest obliczana tylko
względem ~50 krótkich ciągów, a wyniki są buforowane per odrębna domena,
więc powtórne zapytanie nigdy nie powtarza porównania - cache jest
czyszczony automatycznie, gdy tylko lista chronionych domen lub ustawienie
maksymalnej odległości się zmieni.

### Ochrona przed DNS rebinding

[DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) to atak, w
którym domena, której ufa przeglądarka ofiary (ponieważ właśnie na nią
weszła), zostaje sprawiona, by rozwiązywała się do prywatnego/wewnętrznego
adresu IP, więc JavaScript serwowany z tej domeny może sięgnąć w głąb
własnej sieci LAN ofiary - panel administracyjny routera, NAS, wewnętrzne
API - obchodząc zabezpieczenia same-origin, które normalnie powstrzymałyby
publiczną stronę przed zrobieniem tego. Settings -> DNS ma przełącznik
"DNS rebinding protection" (domyślnie wyłączony), który wyłapuje to w
momencie rozwiązywania: każda odpowiedź A/AAAA wracająca z serwera
nadrzędnego jest sprawdzana względem
[`ipaddress.is_private`](https://docs.python.org/3/library/ipaddress.html)
(obejmuje RFC1918, loopback, link-local i IPv6 ULA jednym wywołaniem), a
jeśli odpytywana domena rozwiązuje się do prywatnego adresu,
`dns.rebinding_action` decyduje, co dzieje się z tą odpowiedzią:

- `"alert"` (domyślnie) - rozwiąż normalnie, po prostu uruchom alert. Nic
  w odpowiedzi się nie zmienia.
- `"block"` - odpowiedz jako zablokowane zamiast tego, w tym samym
  kształcie co trafienie listy blokad, z powodem zapisanym jako `DNS
  rebinding protection (<ip>)`.

Dwie rzeczy są całkowicie zwolnione z tego sprawdzania, ponieważ
*legalnie* rozwiązują się do prywatnych adresów: domeny pod tą samą listą
lokalnych TLD, jakiej używają
[Alerty zapytań o lokalne TLD](#alerty-zapytań-o-lokalne-tld) poniżej
(`.local`, `.lan`, `.home` itd. - router lub NAS odpowiadający własną
nazwą hosta w LAN to nie rebinding), oraz cokolwiek wpisanego przez Ciebie
samego pod `dns.rebinding_exempt_domains` (i jego subdomeny) dla własnych
usług wewnętrznych, które mają się rozwiązywać lokalnie. Trafienie też
ląduje w zakładce Anomalies jako własny wiersz o ważności `high` (ten sam
pipeline przerwy/powiadomień co każda inna anomalia tutaj, przez
`anomaly.cooldown_minutes`), więc tryb `"alert"` nadal Cię alarmuje, mimo
że sama odpowiedź DNS przechodzi nietknięta.

### Alerty zapytań o lokalne TLD

Osobny, niepowiązany przełącznik w Settings -> DNS - "Local TLD query
alerts", też domyślnie wyłączony - po prostu loguje, gdy klient odpytuje
domenę pod jednym z tych samych, wyłącznie lokalnych TLD
(`dns.local_tld_list`, domyślnie `local`, `lan`, `home`, `internal`,
`corp`, `home.arpa`). To nie jest sygnał zagrożenia samo w sobie (ruch
mDNS/homenet jest zupełnie normalny w większości sieci LAN); to wiersz o
niskiej ważności, czysto informacyjny, w zakładce Anomalies
(`dns.local_tld_cooldown_minutes` per kombinacja domena/TLD, domyślnie 30)
dla osób chcących wglądu w to, co jest odpytywane pod tymi sufiksami -
powiedzmy, urządzenia IoT sondujące nazwy `.local` - bez traktowania tego
jako incydentu. Zostaw wyłączone, jeśli to dla Twojej sieci tylko szum.

### Reguły alertów (obserwowane domeny i listy)

Cztery heurystyki powyżej to statystyczne domysły w kroczącym oknie -
użyteczne dla "coś wygląda nie tak", ale nie dla "powiedz mi natychmiast,
gdy ta *konkretna* domena zostanie odpytana". Reguły alertów pokrywają to
zamiast tego: nadal w Settings -> Anomalies, tuż poniżej ustawień
wykrywania anomalii, jest sekcja "Watched domains & lists", gdzie
wypisujesz dokładne domeny (i ich subdomeny) i/lub subskrybujesz listy
obserwowanych (te same formaty hosts/AdBlock/plain, zachowanie
pobierania/parsowania/buforowania co globalna sekcja Blocklists - zobacz
[Formaty list blokad i sugerowane listy](#formaty-list-blokad-i-sugerowane-listy)
powyżej). Lista rozwijana pozwala jednym kliknięciem obserwować listę już
skonfigurowaną w Blocklists (znika z listy rozwijanej po zaobserwowaniu,
tak samo jak katalog Suggested lists); jest też zwykły formularz
nazwa/URL tuż pod nią, do obserwowania listy, której w ogóle nie ma w
Blocklists. Odpytanie czegokolwiek z którejś z tych list uruchamia alert -
**niezależnie od tego, czy zapytanie faktycznie zostało zablokowane** - i
pojawia się jako wiersz o ważności "high" w tej samej, głównej zakładce
Anomalies, przechodząc przez dokładnie te same kontrolki
Acknowledge/Remove/Clear-all i ten sam pipeline powiadomień e-mail/
przeglądarki, opisany powyżej. Brak osobnego przełącznika on/off: pusta
lista domen/źródeł po prostu nigdy niczego nie dopasowuje, tak samo jak
źródła listy blokad/dozwolonych, które odzwierciedla. Pasujące zapytanie
dostaje też mały, czerwony tag "watched" obok siebie w zakładce Logs,
więc możesz je zauważyć bez opuszczania logu zapytań.

Samo dopasowywanie działa dokładnie jak dopasowywanie listy blokad - tanie
sprawdzenie w pamięci względem zbioru odświeżanego wg normalnego cyklu
odświeżania listy blokad (i natychmiast po dodaniu/usunięciu obserwowanej
domeny lub źródła z panelu) - więc nie kosztuje nic dodatkowego na gorącej
ścieżce DNS. To, co jest sprawdzane mniej więcej co
`alert_rules.check_interval_seconds` (domyślnie 15), to osobna, znacznie
lżejsza pętla w tle: odpytuje log zapytań w poszukiwaniu nowo zalogowanych
trafień i zamienia każde w alert, ten sam podział "tani odpyt, cięższa
praca poza ścieżką DNS" co samo wykrywanie anomalii.
`alert_rules.cooldown_minutes` (domyślnie 15) działa tak samo jak przerwa
detektora anomalii: gdy dana kombinacja klient/domena się uruchomi, jest
wyciszona przez tyle czasu, zanim może uruchomić się ponownie, więc
klient wielokrotnie trafiający tę samą obserwowaną domenę nie zalewa
tabeli.

### Powiadomienia

Settings -> Notifications ma trzy niezależne sposoby, by dowiedzieć się o
nowo wykrytej anomalii, bez trzymania otwartego panelu w momencie jej
uruchomienia - wszystkie domyślnie wyłączone, wszystkie całkowicie pod
Twoją kontrolą:

**E-mail**, wysyłany wprost na serwer SMTP skonfigurowany przez *Ciebie* -
Twój własny serwer pocztowy, lub Twoje własne konto u dowolnego dostawcy -
używając wyłącznie standardowej biblioteki Pythona (`smtplib`); to nie
usługa chmurowa firmy trzeciej, to dokładnie to, co robi każdy klient
pocztowy na pulpicie. Wypełnij host, port, tryb bezpieczeństwa
(STARTTLS/SSL/brak), opcjonalną nazwę użytkownika/hasło, adres nadawcy i
przynajmniej jednego odbiorcę, a potem **Save email notification
settings**. Przycisk **Send test email** pozwala zweryfikować konfigurację
natychmiast, zamiast czekać na prawdziwą anomalię.
`notifications.email.min_severity` (domyślnie `medium`) ogranicza, które
anomalie faktycznie wywołują e-mail, więc zalew alertów o niskiej wadze
nie zalewa też Twojej skrzynki - każda anomalia nadal pojawia się w zakładce
Anomalies niezależnie od tego ustawienia, wpływa ono tylko na to, co
wychodzi mailem. Hasło SMTP jest maskowane w ten sam sposób co klucze API
threat-intel (tylko pierwszy/ostatni znak, np. `s******t`) i nigdy nie
wraca w pełni do Twojej przeglądarki po zapisaniu.

**Webhooki**, wprost do Discord, Slack lub bota Telegram - DNS-shield sam
wysyła żądanie HTTP (zwykłe `requests.post`, ta sama biblioteka, której
już używają zapytania threat-intel), nic nie przechodzi przez pośredniczący
serwis firmy trzeciej poza tym, na który z tych trzech usług sam
wskażesz. Dodaj tyle, ile chcesz, z sekcji **Webhook notifications**,
każdy z własną nazwą, celem (URL webhooka przychodzącego Discord/Slack,
lub token bota Telegram + ID czatu) i własnym `min_severity` - więc strumień
niskiego priorytetu może iść na cichy kanał Slack, podczas gdy tylko `high`
alarmuje czat Telegram, powiedzmy. Każdy wpis dostaje własny przycisk
**Test** i możliwość Enable/Disable bez usuwania. URL webhooka Discord/Slack
i token bota Telegram są oba maskowane w ten sam sposób co hasło SMTP
powyżej (to poświadczenia typu bearer - kto je posiada, może przez nie
publikować) i nigdy nie wracają w pełni do Twojej przeglądarki po
zapisaniu; ID czatu Telegram nie jest sekretem i jest pokazywane
jawnym tekstem. Awaria jednego webhooka (zły URL, unieważniony token,
błąd sieci) jest logowana i nigdy nie blokuje pozostałych - każdy jest
wysyłany niezależnie, tak samo jak e-mail jest niezależny od wszystkich
z nich.

**Wyskakujące powiadomienia przeglądarki**, przez własne
[Notification API](https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API)
Twojej przeglądarki - żaden komponent serwerowy w ogóle. Zaznaczenie
"Notify me in this browser when new anomalies are detected" prosi Twoją
przeglądarkę o zezwolenie na wyskakujące okna z panelu; po przyznaniu, ta
karta przeglądarki odpytuje własny licznik nieprzyjętych do wiadomości
anomalii panelu co 30 sekund (dopóki panel jest otwarty w jakiejś karcie)
i wyskakuje z natywnym powiadomieniem, gdy ten licznik rośnie. To wybór
per przeglądarka/per urządzenie, przechowywany we własnym `localStorage`
tej przeglądarki, nie ustawienie po stronie serwera - włączenie tego na
laptopie nie włącza tego na telefonie, a DNS-shield nigdy się nie
dowiaduje, czy to włączyłeś.

Notification API przeglądarki działa wyłącznie w "bezpiecznym kontekście" -
HTTPS, albo panel otwarty przez `localhost`/`127.0.0.1`. Otwarty przez
zwykłe HTTP pod adresem LAN (domyślny sposób, w jaki większość ludzi
dociera do DNS-shield), przeglądarka po cichu odmawia nawet pokazania
promptu z uprawnieniem; checkbox wyjaśnia to i sam się wyłącza, zamiast nic
nie robić bez wyjaśnienia. Postaw reverse proxy z TLS przed tym, jeśli
chcesz wyskakujących powiadomień przeglądarki z adresu LAN.

Oba kanały uruchamiają się wyłącznie z tego samego zdarzenia: nowy wiersz
lądujący w `anomalies.db` z detektora anomalii powyżej. Żaden z nich sam w
sobie nie jest nowym źródłem połączeń wychodzących poza to, co już
udokumentowano - e-mail idzie na serwer pocztowy, który wpisałeś, a
wyskakujące powiadomienie przeglądarki nigdy nie opuszcza Twojej własnej
przeglądarki.

### Konta wieloużytkownikowe, role i widok publiczny

DNS-shield obsługuje więcej niż jedno konto panelu, każde z własnym hasłem
i własnym widokiem danych - Settings -> Users (wyłącznie dla kont
administratora).

**Role.** **Administrator** widzi i robi wszystko: każdą zakładkę, każdego
klienta/grupę, wszystkie Settings, Enrich threat-intel, anomalie oraz pasek
wstrzymania "Blocking active". **User** jest głównie do odczytu i
ograniczony do tego, na co zezwoli administrator:

- **Allowed clients / groups** - wzorce IP/CIDR i/lub nazwy `client_groups`.
  Logi, Stats i Anomalie ograniczonego użytkownika są wszystkie
  transparentnie filtrowane do tylko tych klientów po stronie serwera
  (nie ukrywanie po stronie klienta - samo API nigdy nie zwraca im
  wierszy innego klienta); pozostawienie obu pustych oznacza, że konto
  nie widzi żadnych danych klienta, dopóki administrator czegoś nie
  przyzna.
- **Can see threat-intel results** - bez tego przyciski Enrich są
  wyłączone, a `/api/enrich` jest odrzucane.
- **Can see detected anomalies** - bez tego zakładka Anomalies jest
  ukryta, a jej punkty końcowe są odrzucane.
- **Can block a domain/host** - bez tego "Block host" i dodawanie do
  globalnej listy zablokowanych jest odrzucane (edycja listy zablokowanej
  per grupa i każda inna zmiana w Settings pozostają wyłącznie dla
  administratora niezależnie).
- **Can whitelist a domain** - to samo, dla globalnej listy dozwolonych.

Sama zakładka Settings oraz pasek wstrzymania "Blocking active" są zawsze
wyłącznie dla administratora - konto User nigdy ich nie widzi, a
bazowe punkty końcowe API odmawiają kontu niebędącemu administratorem
niezależnie od tego, co pokazuje panel.

**Logowanie.** `/login` to dedykowana strona (nie wyskakujące okno
przeglądarki Basic-Auth), więc może mieć własny branding i link "back to
the public view". Udane logowanie ustawia ciasteczko sesji `HttpOnly`
(`SameSite=Lax`, bez flagi `Secure` - jest to pomyślane dla wdrożenia w
zwykłym HTTP w sieci LAN, tak jak reszta panelu; postaw reverse proxy z
TLS przed tym, jeśli potrzebujesz ciasteczek `Secure`). Sesje żyją
wyłącznie w pamięci serwera, więc restart kontenera wylogowuje wszystkich;
zmiana hasła użytkownika (własnego, lub kogoś innego zmienianego przez
administratora) też natychmiast wylogowuje każdą sesję tego konta.

**Wylogowany**, `/` pokazuje minimalny widok publiczny: tylko wykres
trendu zapytań i listę najczęściej blokowanych domen (domena + liczba,
nic więcej) - bez IP klientów, bez logu zapytań, bez przycisków Copy czy
Enrich, bez zakładek, bez paska wstrzymania. Jest to pomyślane, by
bezpiecznie zostawić otwarte na współdzielonym ekranie, albo pokazać
domownikowi bez dawania mu logowania. Serwowane przez własny punkt
końcowy, `GET /api/public/summary`, który nie potrzebuje ciasteczka sesji.

**Hasła** są zawsze haszowane bcryptem (`app/auth.py`), nigdy nie
przechowywane ani zwracane jawnym tekstem. Aktualizacja z wersji, która
miała tylko jedną parę `web.username`/`web.password`, automatycznie
migruje to jedno konto do nowej listy `users` przy pierwszym uruchomieniu
nowej wersji, konwertując istniejące hasło na hash bcrypt w miejscu -
niczego nie trzeba powtarzać ręcznie, i ta sama nazwa użytkownika/hasło
nadal działają. Każdy użytkownik może zmienić własne hasło z Settings ->
General -> "Your account"; tylko administrator może tworzyć, edytować lub
usuwać konta (Settings -> Users), a DNS-shield odmawia degradacji lub
usunięcia ostatniego pozostałego administratora, więc nie możesz
całkowicie się zablokować.

Pobrana kopia zapasowa konfiguracji (zobacz **Pobieranie kopii zapasowej**
poniżej) zawiera hash bcrypt każdego konta - nieodwracalny do
oryginalnego hasła, ale nadal wart trzymania w prywatności, tak jak
każde inne poświadczenie w tym pliku.

**Uwierzytelnianie dwuskładnikowe (TOTP)** dodaje drugi krok do logowania -
Settings -> General -> "Two-factor authentication", domyślnie wyłączone,
po jednym koncie na raz (każde konto włącza to dla siebie, administrator
nie może wymusić tego dla kogoś innego). Włączenie pokazuje kod QR dla
dowolnej standardowej aplikacji uwierzytelniającej (Google Authenticator,
Authy, 1Password, Bitwarden itd.) plus bazowy klucz base32 do ręcznego
wpisania, jeśli wolisz go wpisać, niż skanować - oba kodują ten sam
sekret TOTP [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238),
generowany po stronie serwera przez `pyotp` i renderowany do wbudowanego
SVG przez `qrcode` (bez Pillow, bez zewnętrznej usługi obrazów - cała
operacja to jeden przelot HTTP). Potwierdzenie 6-cyfrowym kodem, jaki
produkuje Twoja aplikacja, włącza to i daje Ci 8 jednorazowych kodów
zapasowych, pokazanych dokładnie raz - przechowaj je gdzieś bezpiecznie,
ponieważ każdy jest wart jedno logowanie, jeśli zgubisz urządzenie, na
którym jest Twoja aplikacja uwierzytelniająca. Od tego momentu
`/api/login` zwraca `{"totp_required": true, "totp_token": ...}` zamiast
ustawiać ciasteczko sesji po sprawdzeniu poprawności hasła;
`/api/login/totp` przyjmuje ten token plus 6-cyfrowy kod (lub nieużyty
kod zapasowy) i dopiero wtedy ustawia ciasteczko. Błędny kod liczy się do
tego samego, per-IP limitu blokad co błędne hasło
(`web.login_max_attempts`/`web.login_lockout_minutes`, zobacz **Uwagi o
bezpieczeństwie** poniżej) - zgadywanie kodów nie jest darmowe.
Wyłączenie tego z powrotem prosi najpierw o aktualne hasło, to samo
zabezpieczenie co przy jego zmianie.

**Klucze dostępu (Passkeys, WebAuthn)** to druga opcja drugiego składnika,
obok TOTP, a nie zamiast niego - Settings -> General -> "Passkeys".
Sprzętowy klucz bezpieczeństwa lub wbudowany uwierzytelniacz urządzenia
(Touch ID, Windows Hello, odcisk palca/rozpoznawanie twarzy telefonu)
spełnia to samo "drugi krok" co TOTP, bez wpisywania kodu: samo
zarejestrowanie jednego wystarcza, by wymagać drugiego składnika przy
logowaniu, niezależnie od tego, czy TOTP jest też włączone dla tego konta.
Gdy konto ma oba, strona logowania oferuje jedno lub drugie - wpisz kod,
albo kliknij "Use a passkey instead" - a jeśli ma tylko klucz dostępu (bez
TOTP), prompt klucza dostępu przeglądarki uruchamia się automatycznie w
momencie, gdy krok hasła się powiedzie, bez dodatkowego kliknięcia.
Zbudowane na bibliotece
[`webauthn`](https://github.com/duo-labs/py_webauthn) dla faktycznych
ceremonii rejestracji/uwierzytelniania (`credential.create()`/
`credential.get()` w przeglądarce, weryfikowane po stronie serwera
względem wyzwania, które wygasa po 5 minutach niezależnie od wyniku),
przechowując dla każdego konta klucze publiczne poświadczeń i liczniki
podpisów - nigdy niczego, co dałoby się samodzielnie odtworzyć.

To wiąże się z prawdziwym, nieuniknionym ograniczeniem, o którym warto
wiedzieć, zanim zaczniesz na tym polegać: identyfikator relying-party
WebAuthn musi być prawdziwą domeną, a **przeglądarki odrzucają goły adres
IP LAN wprost** - rejestracja klucza dostępu podczas gdy dostajesz się do
panelu przez `http://192.168.1.50:3000` kończy się natychmiastową porażką
z "This is an invalid domain," potwierdzone na Chromium, nie zgadywane.
`localhost` działa, tak samo jak dowolna prawdziwa nazwa hosta (wpis DNS
w LAN, linia w pliku hosts, domena przez reverse proxy) - jeśli normalnie
dostajesz się do DNS-shield wpisując IP, skieruj najpierw na niego nazwę
(pasek adresu samego panelu powie Ci, pod jaką nazwą hosta jest obecnie
osiągalny).

**Tokeny API** pozwalają skryptowi, zadaniu cron, albo panelowi (Grafana,
automatyzacji Home Assistant, Twoim własnym narzędziom) wywoływać API bez
sesji przeglądarki - Settings -> General -> "API tokens". Każdy token jest
przypisany do konta, które go stworzyło, i działa jako to konto przy
każdym sprawdzeniu uprawnień: token administratora może zrobić przez API
wszystko, co może administrator, token ograniczonego użytkownika jest
ograniczony tak samo, jak już jest to konto. Wyślij go jako
`Authorization: Bearer <token>` w dowolnym żądaniu; `GET /metrics` i
punkt końcowy DoH (`/dns-query`) nigdy go nie potrzebują, ponieważ oba są
z założenia niewymagające uwierzytelnienia (zobacz powyżej) - token ma
znaczenie tylko dla reszty API. Sam token to 256-bitowa losowa wartość
(`secrets.token_urlsafe`, z prefiksem `dnss_`, więc jest rozpoznawalny w
pliku konfiguracyjnym lub `.env`) - przechowywany jest wyłącznie jego
hash SHA-256, a czysty tekst jest pokazywany dokładnie raz, w momencie
tworzenia, bez żadnego miejsca w interfejsie, by odzyskać go później;
zgub go, a stwórz nowy i unieważnij stary. Unieważnienie (lub usunięcie
posiadającego go użytkownika) natychmiast go dezaktywuje - nie ma okresu
przejściowego. Podobnie jak hash hasła bcrypt, hash tokena nie jest
odwracalny do oryginalnej wartości, ale pobrana kopia zapasowa
konfiguracji nadal go zawiera, to samo zastrzeżenie co **Hasła** powyżej.

**Log audytu** (Settings -> Users -> "Audit log") to bieżący, tylko do
odczytu zapis każdej udanej zmiany ustawień/konfiguracji dokonanej przez
API - kto (które konto), co (`METODA /api/ścieżka`) i z jakiego adresu,
od najnowszych - plus logowania i wylogowania. Zbudowany z jednego
elementu middleware, który obserwuje każde `POST`/`PUT`/`PATCH`/`DELETE`
pod `/api/`, więc nowe punkty końcowe są automatycznie objęte, bez
potrzeby dodawania jawnego wywołania logu do każdego z nich; logowanie/
wylogowanie są logowane jawnie zamiast tego, ponieważ ciasteczko sesji
jeszcze nie istnieje w momencie, gdy przychodzi żądanie logowania. Tylko
żądania, które faktycznie się powiodły (status poniżej 400), są
zapisywane - odrzucona lub nieudana próba nie zostawia wpisu - i tylko
żądania mutujące: rutynowe odczyty, jak wczytanie strony czy 10-sekundowe
odpytywanie statystyk panelu, nigdy się nie pojawiają. `GET /dns-query`
(DoH) i `POST /dns-query` są celowo wykluczone też - każde zapytanie DNS
inaczej zalałoby to bezużytecznością, a ma to odpowiadać na "kto co
zmienił", nie być drugim logiem zapytań. Przechowywane we własnym
`audit.db`, przycinane wg tego samego harmonogramu
`logging.retention_days` co log zapytań.

### HTTPS dla panelu

`web.https_enabled` (Settings -> General, domyślnie wyłączone) sprawia, że
własny port webowy panelu serwuje HTTPS zamiast zwykłego HTTP - to
zastępuje port, nie dodaje drugiego, więc po włączeniu tylko `https://`
dociera do panelu na `web.listen_port`. Wymaga restartu kontenera, by
zadziałać, tak samo jak sam adres/port nasłuchu.

Bez skonfigurowanego certyfikatu, DNS-shield generuje własny,
samopodpisany certyfikat przy pierwszym uruchomieniu z włączonym HTTPS, i
używa ponownie tego samego przy każdym późniejszym restarcie
(`<katalog danych>/tls/cert.pem`/`key.pem` - część woluminu danych, więc
przetrwa ponowne utworzenie kontenera, a klucz prywatny jest zapisywany z
uprawnieniami `0600`). Twoja przeglądarka pokaże ostrzeżenie "niezaufany"
przy pierwszym połączeniu, ponieważ samopodpisany certyfikat nie jest
poparty przez urząd certyfikacji, któremu Twoja przeglądarka już ufa -
samo połączenie jest naprawdę zaszyfrowane niezależnie, to ostrzeżenie
dotyczy tylko weryfikacji tożsamości, nie siły szyfrowania. Kliknij
przez to raz, albo - faktycznie poprawna poprawka, jeśli ma to dla Ciebie
znaczenie - ustaw `web.https_cert_path`/`web.https_key_path` na
prawdziwą parę certyfikat/klucz (np. taką, jaką wystawia klient ACME jak
`certbot`/`lego` dla nazwy domeny, która faktycznie rozwiązuje się do
tego hosta, zamontowaną do kontenera obok woluminu danych). DNS-shield
nigdy sam nie łączy się z dostawcą ACME - tylko czyta pliki
certyfikatu/klucza, na które wskażesz, ta sama zasada "brak połączeń
wychodzących, o które nie prosiłeś" co wszystko inne w tym projekcie.

Włączenie HTTPS też automatycznie dodaje flagę `Secure` do ciasteczka
sesji (zobacz **Uwagi o bezpieczeństwie** poniżej), więc warto to zrobić
nawet z samopodpisanym certyfikatem, jeśli panel jest osiągalny poza
localhost - szyfrowanie żądania logowania i ciasteczka sesji w transmisji
nie wymaga certyfikatu zaufanego przez przeglądarkę, by było warte
zachodu.

### DNS-over-HTTPS / DNS-over-TLS dla klientów

Wszystko powyżej tego punktu dotyczyło DNS-shield jako *klienta* DoH/DoT
rozmawiającego z Twoim serwerem nadrzędnym. Ta sekcja to kierunek
odwrotny: sam DNS-shield odpowiadający na zapytania DoH/DoT *od* Twoich
klientów, ponad zwykłym portem 53 UDP/TCP, który zawsze nasłuchuje.

**DoH** nie potrzebuje osobnego przełącznika - `POST /dns-query` i
`GET /dns-query?dns=<base64url>` (RFC 8484, surowy format DNS w
`application/dns-message`) są zawsze obecne na tym samym porcie webowym
co panel, dzieląc jego cache, cache DNSSEC i stan listy blokad, więc
zapytanie DoH jest filtrowane/blokowane/logowane dokładnie jak zwykłe.
Jest jednak faktycznie użyteczne dopiero gdy `web.https_enabled` jest
włączone - DoH to DNS-over-*HTTPS*, a większość klientów, które go
obsługują (wbudowane ustawienia DoH przeglądarek, `curl --doh-url` itd.)
albo wymagają TLS wprost, albo nie wyślą prawdziwego ruchu przez zwykłe
HTTP.

**DoT** jest domyślnie wyłączone - `dns.dot_enabled` (Settings -> DNS,
wymaga restartu kontenera) otwiera drugi nasłuch na `dns.dot_port`
(domyślnie 853), mówiąc DNS-over-TLS (RFC 7858): ten sam format z
prefiksem długości, co zwykły DNS-over-TCP, opakowany w TLS. Używa
ponownie tego samego certyfikatu, który rozwiązuje ustawienie HTTPS
panelu - Twój własny `web.https_cert_path`/`web.https_key_path`, jeśli
ustawiony, w przeciwnym razie ten sam auto-generowany, samopodpisany opisany
powyżej. Ma to tutaj większe znaczenie niż dla panelu: większość klientów
DoT na poziomie systemu operacyjnego (Android "Private DNS",
systemd-resolved itd.) weryfikuje certyfikat względem zaufanego CA i po
prostu odmawia samopodpisanego - nie ma opcji "kliknij przez ostrzeżenie",
jaką daje przeglądarka - więc z samopodpisanym certyfikatem DoT jest w
dużej mierze nie do przetestowania, choć technicznie działa, dopóki nie
wskażesz na prawdziwy certyfikat.

Oba nasłuchy działają wyłącznie w głównym procesie, nie rozproszone po
procesach roboczych `DNSSHIELD_DNS_WORKERS`, w przeciwieństwie do zwykłego
UDP/TCP - sam panel webowy jest już wyłącznie jednoprocesowy, a DoH/DoT
podążają za tą samą granicą, zamiast dodawać ładowanie certyfikatu per
proces roboczy i interakcję z `SO_REUSEPORT` dla ścieżki o stosunkowo
niskiej przepustowości. Żaden nie jest publikowany w dostarczonym
`docker-compose.yml` domyślnie; dodaj mapowanie `- "853:853/tcp"` (lub
jakikolwiek port ustawiłeś), gdy `dns.dot_enabled` jest włączone,
pasujące do wzorca mapowania portów strony blokady powyżej.

### Metryki Prometheus

`GET /metrics` (niewymagające uwierzytelnienia, tak samo jak publiczne
podsumowanie panelu) eksponuje mały zestaw liczników i mierników Prometheus
w standardowym formacie tekstowym: `dnsshield_queries_total` /
`dnsshield_blocked_total` (wyprowadzane na żywo z `stats.db`, więc czytają
się poprawnie w każdym procesie `DNSSHIELD_DNS_WORKERS` dzielącym tę bazę,
a własne `rate()`/`increase()` Prometheusa obsługują reset po wyczyszczeniu
logu lub przycięciu przez 30-dniową retencję w normalny sposób - jako
reset licznika, nie ujemną prędkość), `dnsshield_blocklist_domains` /
`dnsshield_allowlist_domains`, `dnsshield_cache_entries` /
`dnsshield_cache_hits_total` / `dnsshield_cache_misses_total`,
`dnsshield_anomalies_unacknowledged` oraz `dnsshield_uptime_seconds`. Dwa
mierniki `dnsshield_dnssec_*_cached` to jedyny wyjątek od właściwości
"agreguje się we wszystkich procesach roboczych" powyżej - cache DNSSEC
jest per proces, więc przy więcej niż jednym procesie roboczym DNS te
odzwierciedlają wyłącznie ten proces, który akurat jest interfejsem
webowym (ten sam, który posiada `create_app`), nie sumę wszystkich.

### Sprawdzanie kondycji

`GET /healthz` (też niewymagające uwierzytelnienia) to zwykłe sprawdzenie
żywotności - `{"status": "ok", "uptime_seconds": ...}` ze statusem 200,
jeśli proces webowy działa i obsługuje żądania, nic więcej (nie dotyka
`stats.db`, listy blokad ani żadnego innego podsystemu, więc sam nie może
stać się wolny ani zawieść z powodów niezwiązanych z "czy ten proces
żyje"). Wbudowany `HEALTHCHECK` dostarczonego obrazu już kieruje `docker
inspect --format='{{.State.Health.Status}}'`/`docker ps` na niego przez
`app/healthcheck.py`, który próbuje najpierw zwykłego HTTP, a potem
przechodzi na HTTPS (pomijając weryfikację certyfikatu, ponieważ cel
zawsze jest `127.0.0.1` wewnątrz tego samego kontenera), więc nadal działa
niezależnie od tego, jak ustawione jest `web.https_enabled`. Wskaż
zewnętrzne sprawdzanie dostępności lub `livenessProbe` Kubernetes na tę
samą ścieżkę, jeśli uruchamiasz to poza `docker compose`.

### Wstrzymanie blokowania

Pasek na górze panelu może wstrzymać *całe* blokowanie w całej sieci na
wybrany czas (10/30/60/120 sekund, 5/10/30/60 minut, lub do ręcznego
wznowienia) - przydatne do szybkiego sprawdzenia, czy DNS-shield jest
przyczyną czegoś, co się psuje, bez konieczności odnajdywania i tymczasowego
usuwania konkretnego wpisu listy zablokowanej lub listy blokad. Podczas
wstrzymania, każde zapytanie rozwiązuje się tak, jakby nie istniała żadna
lista blokad, lista zablokowanych ani grupa klientów; samo wygasa
dokładnie o wybranym czasie (bez potrzeby odpytywania/czyszczenia -
znacznik czasu jest po prostu porównywany z bieżącym czasem), albo możesz
kliknąć "Resume blocking" wcześniej. Tylko konta administratora mogą
widzieć lub używać tego paska - zobacz **Konta wieloużytkownikowe, role i
widok publiczny** powyżej.

### Wykluczanie domen/klientów z logu

`logging.ignored_domains` / `logging.ignored_clients` (panel: Settings ->
Logging & blocklist refresh) trzymają konkretne domeny lub klientów
całkowicie poza logiem zapytań i statystykami - są nadal normalnie
rozwiązywane i blokowane, to kontroluje tylko to, co jest zapisywane do
`stats.db`. Wpisy domen obejmują też ich subdomeny; klienci przyjmują
dokładny adres IP lub zakres CIDR.

### Motywy kolorystyczne

Settings -> Web UI -> Color theme przełącza między ośmioma paletami,
czterema ciemnymi i czterema jasnymi, sparowanymi wg odcienia: Navy &
Azure / Daylight & Azure, Slate & Cyan / Mist & Cyan, Forest & Emerald /
Meadow & Emerald oraz Plum & Violet / Lilac & Violet. Navy & Azure
(ciemny) jest domyślny. Stosowane natychmiast, przechowywane w `web.theme`.

### Urządzenia mobilne

Panel jest używalny z telefonu - sprawdzenie lub wstrzymanie blokowania,
albo dodanie szybkiej reguły dozwolenia/zablokowania, nie wymaga laptopa.
Poniżej ~640px szerokości: pola formularzy i grupy ustawień zwijają się do
jednej kolumny, szerokie tabele danych (log zapytań, podziały Stats, listy
dozwolonych/zablokowanych/zablokowanych klientów) przewijają się poziomo we
własnym pudełku zamiast zmuszać do przewijania całą stronę, a długie domeny
zawijają się zamiast rozciągać swoją kolumnę. Nie ma osobnej aplikacji
mobilnej ani API - to ta sama strona, to samo `GET /`, po prostu
responsywny CSS.

### Bezpośrednia edycja pliku konfiguracyjnego

Aktywna konfiguracja DNS-shield znajduje się w `./data/config.db`, nie w
pliku YAML - jest edytowana przez panel/REST API, a pełny eksport jest
zapisywany do `./data/config.backup.yaml` co 12 godzin i przy każdym
starcie, jako czytelna dla człowieka kopia zapasowa. Ten plik kopii
zapasowej jest tylko *odczytywany*, by zasiać świeżą bazę danych (pierwsze
uruchomienie na pustym woluminie danych, lub po usunięciu `config.db`, by
zresetować). By ręcznie edytować konfigurację jako YAML: zatrzymaj
kontener, edytuj (lub zamień) `./data/config.backup.yaml`, usuń
`./data/config.db` (i jego pliki `-wal`/`-shm`, jeśli są obecne), i
uruchom ponownie.

### Pobieranie kopii zapasowej

Settings -> General -> **Download backup (.zip)** daje Ci ten sam pełny
zrzut konfiguracji co `data/config.backup.yaml` powyżej, ale jako plik,
który Twoja przeglądarka pobiera na Twoją własną maszynę - zbudowany
całkowicie w pamięci i wysłany od razu z powrotem, nic nie zapisywane na
dysk serwera poza tym, co już jest w `config.db`. Zip zawiera
`config.yaml` (przywróć go w ten sam sposób co `config.backup.yaml`
powyżej, albo zobacz przywracanie z panelu poniżej) plus `README.txt`
wyjaśniający zarówno przypadek świeżej instancji, jak i ręcznego
przywracania istniejącej instancji.

Tak jak `config.backup.yaml`, jest to pełny, niezamaskowany zrzut -
wszystkie klucze API threat-intel wychodzą jawnym tekstem, a hash bcrypt
hasła każdego konta użytkownika też wychodzi (nieodwracalny do
oryginalnego hasła, ale nadal wart trzymania w prywatności). Traktuj
pobrany plik tak, jak traktowałbyś hasło: przechowuj go tam, gdzie
przechowywałbyś hasło, nie w miejscu publicznym.

**Settings -> Import -> Restore from backup** stosuje jeden z tych zipów
bez opuszczania panelu czy dotykania kontenera - prześlij go, a cała Twoja
aktualna konfiguracja jest całkowicie zastępowana tym, co było w kopii
zapasowej (bez scalania, ponieważ to własny, natywny format DNS-shield,
nie ma nic do konwertowania). Nieodwracalne, chyba że też zrobiłeś kopię
zapasową konfiguracji, którą właśnie zamierzasz nadpisać - panel najpierw
prosi o potwierdzenie.

## Import z AdGuard Home lub Pi-hole

Oba importery znajdują się w zakładce panelu **Settings -> Import** (albo
jako jednorazowy skrypt z linii poleceń), i oba działają tak samo: czytają
jeden plik z Twojej istniejącej konfiguracji, scalają to, co jest
obsługiwane, do konfiguracji DNS-shield i drukują podsumowanie tego,
dokładnie co zostało, a co nie zostało przeniesione.

### AdGuard Home

Konwertuje `AdGuardHome.yaml`: subskrypcje filtrów i filtrów-listy
dozwolonych, `user_rules` (zarówno reguły blokujące, jak i wyjątki `@@`),
resolwery nadrzędne (`tls://`/`https://` konwertowane na
`dot://`/`doh://`), adres/port nasłuchu, tryb blokowania oraz każdy wpis
`clients.persistent[].ids` (adresy IP, CIDR i adresy MAC, konwertowane na
wzorzec `mac:` - własne ciągi identyfikatorów klientów AdGuard to
koncepcja, której DNS-shield nie ma, te są pomijane z ostrzeżeniem) jako
wpis `client_groups`.

**Z panelu**: prześlij plik, jest scalany bezpośrednio z działającą
konfiguracją i wchodzi w życie natychmiast - listy blokad odświeżają się od
razu. To **zastępuje** Twoje aktualne listy blokad i grupy klientów tymi
z AdGuard, ale zachowuje wszystko inne, włącznie z Twoim logowaniem
webowym.

**Z linii poleceń**, dla świeżej instalacji lub by wyprodukować plik do
przejrzenia przed zastosowaniem:

```bash
docker compose exec dns-shield python -m app.import_adguard /ścieżka/do/AdGuardHome.yaml
```

Nieimportowane: kontrola rodzicielska/bezpieczne przeglądanie, DHCP,
terminowanie TLS oraz hasło do panelu webowego - AdGuard przechowuje hash
bcrypt, którego nie da się zamienić z powrotem na czysty tekst, więc
ustaw to sam z panelu.

### Pi-hole

Konwertuje `gravity.db` - własną bazę SQLite Pi-hole, dołączoną do kopii
zapasowej "Teleporter" lub kopiowalną bezpośrednio z
`/etc/pihole/gravity.db` na hoście Pi-hole: `adlist` (lista blokad, a na
nowszych schematach lista dozwolonych, adresy URL subskrypcji, zachowany
stan włączenia), włączone dokładne wpisy dozwolone/zablokowane
`domainlist`, włączone wpisy regex-zablokowane `domainlist` (mapowane na
[eksperymentalną listę zablokowaną regex](#lista-zablokowana-regex-eksperymentalna)
DNS-shield, która jest dla Ciebie włączana), oraz adresy IP `client` jako
`client_groups`.

**Z panelu**: prześlij `gravity.db` - to samo zachowanie: scalenie i
natychmiastowe zastosowanie, tak jak przy imporcie AdGuard Home powyżej.

**Z linii poleceń**:

```bash
docker compose exec dns-shield python -m app.import_pihole /ścieżka/do/gravity.db
```

Nieimportowane: serwery DNS nadrzędne, adres/port nasłuchu i tryb
blokowania (znajdują się w `setupVars.conf`/`pihole.toml`/konfiguracji
dnsmasq Pi-hole, innym pliku, którego ten importer nigdy nie czyta), wpisy
regex ALLOW (DNS-shield nie ma listy dozwolonej regex, tylko listę
zablokowaną regex), przypisania list per klient/per grupa (tabele
przynależności do grup w gravity.db różnią się między wersjami Pi-hole,
więc zaimportowany klient dostaje domyślną, globalną politykę
DNS-shield, nie tę grupę Pi-hole, do której należał) oraz hasło do panelu
webowego.

## Architektura

```
app/
  config.py          przechowywanie konfiguracji: SQLite (data/config.db) jako aktywne
                      źródło prawdy, eksportowane do data/config.backup.yaml co 12h
  netmatch.py         wspólne dopasowywanie IP/CIDR dla grup klientów i reguł log-ignore
  blocklist.py        pobiera + parsuje listy hosts/AdBlock/plain-domain (automatycznie
                       wykrywając format każdego źródła) dla list blokad, dozwolonych i
                       obserwowanych reguł alertów, odświeża na czasomierzu, buforuje
                       listy na dysku dla offline'owych restartów, i (eksperymentalnie)
                       dopasowuje z cache w pamięci skompilowane wzorce listy zablokowanej regex
  blocklist_catalog.py  ustalona lista znanych, publicznych list blokad oferowanych jako
                       "Suggested lists" jednym kliknięciem w panelu, w sekcji Blocklists
  dns_server.py        serwer DNS UDP/TCP oparty na dnslib (plus opcjonalny nasłuch DoT);
                        blokuje lokalnie, odpowiada rekordem niestandardowym, serwuje
                        zbuforowaną odpowiedź, lub przekazuje do Twoich serwerów nadrzędnych
  metrics.py            renderuje format tekstowy Prometheus dla GET /metrics (zobacz
                        powyżej) z tego samego stanu stats.db/listy blokad/cache/anomalii,
                        który już czyta wszystko inne
  healthcheck.py         samodzielny skrypt zasilający HEALTHCHECK obrazu Docker - trafia w
                        GET /healthz przez HTTP, potem HTTPS, cokolwiek używa aktywna
                        konfiguracja
  audit.py               log kto-co-zmienił: przechowywanie SQLite (data/audit.db), zasilany
                        przez jeden element middleware w web/server.py, który automatycznie
                        obejmuje każdy mutujący punkt końcowy /api/ (zobacz powyżej)
  two_factor.py           generowanie/weryfikacja sekretu/QR TOTP (pyotp + qrcode), plus
                        krótkotrwały magazyn tokenów oczekującego logowania, którego
                        używa dwuetapowy przepływ logowania (zobacz Uwierzytelnianie
                        dwuskładnikowe powyżej)
  passkeys.py             ceremonie rejestracji/uwierzytelniania WebAuthn (zobacz Passkeys
                        powyżej), cienki wrapper na bibliotece webauthn
  dns_rewrites.py       dopasowywanie niestandardowych, lokalnych rekordów A/AAAA (zobacz
                       Niestandardowe rekordy DNS powyżej)
  dns_cache.py         cache odpowiedzi z serwerów nadrzędnych w pamięci, respektujący TTL
                       (ograniczony LRU, nic trwale zapisywane na dysk)
  block_page.py         opcjonalny lokalny serwer HTTP dla strony "zablokowano" (zobacz
                        powyżej) - odpowiada wyłącznie na żądania, które już do niego dotarły
  upstream.py          transporty do serwerów nadrzędnych: zwykły UDP/TCP, DNS-over-TLS, DNS-over-HTTPS
  upstream_stats.py    kroczące śledzenie opóźnienia/sukcesu + sondowanie kondycji w tle,
                       zasilające strategie wyboru serwera nadrzędnego fastest/most_stable
  client_names.py      resolwer odwrotnego DNS (PTR) w tle, wyłącznie do wyświetlania w panelu
  stats.py             przechowywanie logu zapytań: baza SQLite (data/stats.db), zapisy
                       asynchroniczne, przycinanie co godzinę, przeszukiwalne dla przeglądarki logu zapytań
  import_adguard.py    jednorazowy konwerter AdGuard Home -> konfiguracja DNS-shield (zobacz powyżej)
  import_pihole.py      jednorazowy konwerter Pi-hole gravity.db -> konfiguracja DNS-shield (zobacz powyżej)
  enrichment.py         zapytania o reputację VirusTotal/AbuseIPDB/OTX/GreyNoise/Shodan/URLhaus/RDAP/crt.sh -
                        wywoływane wyłącznie z punktu końcowego przycisku "Enrich", nigdy
                        samodzielnie (zobacz powyżej)
  enrichment_store.py   lokalne przechowywanie wyników wzbogacania: SQLite (data/enrichment.db)
  anomaly.py             lokalne, heurystyczne wykrywanie anomalii nad logiem zapytań, plus
                        pętla w tle obserwowanych domen/reguł alertów - przechowywanie SQLite
                        (data/anomalies.db) (zobacz powyżej)
  notifications.py       opcjonalny e-mail dla nowych anomalii, wprost na skonfigurowany przez
                        Ciebie serwer SMTP (tylko stdlib smtplib) - nigdy niewywoływane samodzielnie (zobacz powyżej)
  auth.py               haszowanie haseł bcrypt (cienki wrapper, izoluje zależność bcrypt
                        do jednego modułu)
  users.py              konta wieloużytkownikowe + role/uprawnienia: przechowywane w SQLite
                        (przez listę `users` w config.py), migruje konto webowe
                        sprzed wprowadzenia wielu kont (web.username/web.password) do konta admina z hashem bcrypt
  sessions.py           sesje logowania w pamięci (token -> nazwa użytkownika) zasilające
                        ciasteczko sesji - nigdy niezapisywane na dysk, restart
                        wylogowuje wszystkich
  web/server.py        REST API FastAPI + uwierzytelnianie/RBAC oparte na ciasteczku sesji, zasilające panel
  web/static/          samodzielna, pojedyncza strona panelu, plus osobna strona
                       logowania (bez zewnętrznych zasobów/CDN - nawet favicon/logo to
                       wbudowany SVG, nie pobierany plik)
  main.py              spina powyższe razem i uruchamia całość
```

Przepływ żądania: klient -> DNS-shield (UDP/TCP :53) -> dopasowanie listy
blokad? -> lokalnie NXDOMAIN/null-IP; w przeciwnym razie dopasowanie
niestandardowego rekordu DNS? -> odpowiedz lokalnie; w przeciwnym razie
trafienie w cache? -> odpowiedz z lokalnego cache; w przeciwnym razie
przekaż surowy pakiet do serwera nadrzędnego, przekaż surową odpowiedź z
powrotem i zbuforuj ją na pozostały czas TTL. Każde zapytanie jest
zapisywane do lokalnego logu statystyk niezależnie od tego, jak zostało
odpowiedziane.

### Współbieżność

Domyślnie DNS-shield działa jako pojedynczy proces. W ramach tego procesu,
serwer DNS obsługuje każde przychodzące zapytanie na własnym wątku
(serwery UDP/TCP dnslib z `ThreadingMixIn`) - nie ma stałego limitu
połączeń, a ponieważ rozwiązywanie jest ograniczone przez I/O (czekanie na
gniazdo serwera nadrzędnego, albo na wyszukiwanie w cache/liście blokad w
pamięci), wygodnie obsługuje to skoki zapytań domowej lub małej biurowej
sieci. Wątki nie dają prawdziwej równoległości między rdzeniami CPU dla
samego kodu Pythona (GIL), ale ponieważ praca tutaj jest ograniczona przez
I/O, a nie przez CPU, rzadko ma to znaczenie w praktyce. Panel webowy
działa w ten sam sposób - FastAPI/Starlette rozsyła każde żądanie do puli
wątków, wszystko w tym jednym procesie.

Dla wyższej przepustowości zapytań, niż wygodnie obsłuży jeden proces,
ustaw `DNSSHIELD_DNS_WORKERS` (zmienna środowiskowa, jak
`DNSSHIELD_DATA_DIR` - nie ustawienie panelu) na liczbę większą niż 1.
DNS-shield forkuje tyle dodatkowych, w pełni niezależnych procesów
serwujących DNS - każdy z własnym stanem listy blokad/cache/kondycji
serwera nadrzędnego - i wiąże wszystkie z tym samym portem DNS przez
`SO_REUSEPORT`, więc jądro równoważy przychodzące zapytania między każdym
procesem/rdzeniem. Tylko oryginalny proces uruchamia panel webowy,
wykrywanie anomalii i powiadomienia - te pozostają wyłącznie
jednoprocesowe niezależnie od tego ustawienia, więc sesje logowania i
alerty anomalii nigdy nie są duplikowane. Dodatkowe procesy wyłącznie-DNS
przeładowują swoją konfigurację z `config.db` co kilka sekund (więc zmiana
z panelu dociera do nich szybko bez restartu) i niezależnie pobierają
własną kopię każdej skonfigurowanej listy blokad/obserwowanej listy/listy
złośliwych IP wg normalnego harmonogramu odświeżania - poprawne i proste,
kosztem tego, że każdy proces roboczy robi to pobieranie osobno, zamiast
dzielić jeden wynik. Log zapytań (`stats.db`) jest bezpieczny do
jednoczesnego zapisu z wielu procesów (tryb WAL SQLite, już domyślny
tutaj). `SO_REUSEPORT` jest wyłącznie dla Linux/BSD; na platformie bez
tego, DNS-shield loguje ostrzeżenie i wraca do pojedynczego procesu
roboczego. To wszystko nadal nie jest dostrojone do bardzo wysokiej,
utrzymanej przepustowości niezależnie od liczby procesów roboczych: każde
przekazane zapytanie otwiera świeże gniazdo UDP do serwera nadrzędnego
(bez ponownego użycia/puli połączeń). Cache powyżej wchłania większość
powtarzalnego ruchu, który inaczej trafiłby do serwera nadrzędnego.

**Pamięć**: każda lista blokad (globalna, per grupa, lista dozwolonych,
reguła alertu, złośliwe adresy IP odpowiedzi) jest trzymana w całości w
pamięci jako `frozenset[str]` po odświeżeniu, co czyni dopasowywanie
wyszukiwaniem w zbiorze O(1), zamiast odczytem sieciowym lub dyskowym per
zapytanie. Zmierzone bezpośrednio na prawdziwych feedach: połączenie
StevenBlack's Unified Hosts plus trzy duże listy HaGeZi (~867 tys.
unikalnych domen łącznie) kosztuje około **196 MB**; lista
[Newly Registered Domains](#nowo-zarejestrowane-domeny-nrd) sama w sobie
to ~2,8 mln domen i kosztuje około **650 MB** - z grubsza 200-230 bajtów
na domenę w obu przypadkach, spójnie w obu pomiarach. Wiele procesów
roboczych DNS (powyżej) każdy trzyma niezależną kopię, więc ten sam zestaw
subskrybowanych list kosztuje proporcjonalnie więcej RAM na proces
roboczy, nie raz, dzielone między nimi.

## Uwagi o bezpieczeństwie

- Zmień domyślne hasło `admin` przed wystawieniem panelu poza localhost
  (Settings -> General -> "Your account", albo Settings -> Users). Hasła
  są zawsze haszowane bcryptem - zobacz **Konta wieloużytkownikowe, role i
  widok publiczny** powyżej.
- Punkt końcowy logowania ma limit prób per adres IP źródłowy
  (`web.login_max_attempts`, domyślnie 5 błędów przed blokadą trwającą
  `web.login_lockout_minutes`, domyślnie 15 - poprawne hasło nie omija
  aktywnej blokady). Nic innego w API nie ma jednak limitu prób; postaw
  panel za własnym reverse proxy / VPN, jeśli wystawiasz na zewnątrz Twojej
  sieci LAN więcej niż formularz logowania. Ciasteczko sesji dostaje flagę
  `Secure` automatycznie, gdy tylko `web.https_enabled` jest włączone
  (zobacz [HTTPS dla panelu](#https-dla-panelu) poniżej) - jest domyślnie
  wyłączona, ponieważ wdrożenie w zwykłym HTTP w LAN nigdy nie mogłoby
  jej odesłać z powrotem.
- Tokeny API (`Authorization: Bearer <token>`, zobacz **Tokeny API**
  powyżej) celowo nie mają limitu prób w sposób, w jaki ma go punkt
  końcowy logowania - 256-bitowa losowa wartość czyni zgadywanie
  niewykonalnym niezależnie, w przeciwieństwie do hasła wybranego przez
  człowieka. Token to poświadczenie typu bearer: kto go posiada, może go
  użyć, nieodróżnialnie od konta, które go stworzyło, dopóki pozostaje
  ważny - traktuj go jak hasło i unieważnij w momencie, gdy podejrzewasz,
  że wyciekł.
- Publiczny, wylogowany widok (`/` i `GET /api/public/summary`) jest
  celowo osiągalny bez logowania - zwraca wyłącznie trend zapytań i
  najczęściej blokowane domeny, nic więcej specyficznego dla klienta czy
  domeny poza tym.
- Port 53 wymaga roota lub `CAP_NET_BIND_SERVICE` w kontenerze -
  dostarczony obraz działa jako root z tego powodu (to samo podejście co
  oficjalne obrazy AdGuard Home / Pi-hole). Uruchom bez roota przez
  nadpisanie compose z `cap_add: [NET_BIND_SERVICE]` i `user:` innym niż
  root, jeśli tego potrzebujesz.
- Klucze API threat-intel (VirusTotal/AbuseIPDB/OTX/GreyNoise/Shodan/URLhaus/
  Twoja własna, lokalna usługa) są przechowywane w `config.db`/
  `config.backup.yaml`, tak jak każde inne ustawienie - kto ma dostęp do
  panelu webowego lub woluminu `./data`, może je odczytać lub użyć. Strona
  Settings i `GET /api/settings` nigdy nie zwracają klucza z powrotem,
  tylko to, czy jest ustawiony. `local_url` jest przechowywany i pokazywany
  jawnym tekstem (to URL, nie sekret) - nie umieszczaj w nim poświadczeń,
  użyj do tego osobnego pola lokalnego klucza API.
- `enrichment.public_enabled` (Settings -> Threat intelligence -> "Enable
  public lookups") jest domyślnie wyłączone i jest faktyczną bramką, czy
  VirusTotal/AbuseIPDB/OTX są kiedykolwiek kontaktowane - zapisanie klucza
  dla jednego z nich samo w sobie tego nie włącza. Każdy z dostępem do
  panelu może to przełączyć, tak jak każde inne ustawienie.

## Ograniczenia / plany na przyszłość

- Brak serwera DHCP, brak DoQ (DoH/DoT są obsługiwane zarówno jako
  transport do serwera nadrzędnego, jak i jako nasłuch dla klientów -
  zobacz powyżej).
  [Kontrola rodzicielska](#kontrola-rodzicielska--safesearch) jest
  ograniczona do tego, co faktycznie potrafi zrobić rozwiązywanie DNS -
  wymuszone SafeSearch, listy blokad kategorii per grupa oraz harmonogramy
  godziny snu per grupa - nie limity per aplikacja ani inspekcja treści.
- Grupy klientów i `blocked_clients` dopasowują też wg adresu MAC lub
  rozwiązanej nazwy hosta (wzorce `mac:`/`host:`, zobacz powyżej), ale
  dopasowywanie MAC zależy od tego, czy tabela ARP hosta jest widoczna dla
  kontenera (sieć hosta), a dopasowywanie nazwy hosta zależy od włączonego
  rozwiązywania nazw klientów - żadne z nich nie jest dostępne od razu przy
  domyślnym, sieciowanym przez bridge `docker-compose.yml`.
- HTTPS dla panelu (zobacz powyżej) jest domyślnie samopodpisany -
  certyfikat zaufany przez przeglądarkę nadal oznacza albo dostarczenie
  własnego, albo postawienie przed nim reverse proxy z własnym klientem
  ACME.
- Dopasowywanie listy blokad jest oparte na domenie/subdomenie. Reguły
  blokujące `||domain^` i reguły wyjątków `@@||domain^` (zarówno z
  subskrybowanych list, jak i własnych, dodatkowych źródeł grupy) są
  rozumiane; domena objęta wyjątkiem nigdy nie jest blokowana przez to
  samo źródło, nawet jeśli szersza reguła w nim inaczej by pasowała.
  Wszystko inne w gramatyce AdBlock/uBlock jest architektonicznie poza
  zasięgiem blokera na poziomie DNS i jest po cichu pomijane, zamiast
  błędnie interpretowane: ukrywanie elementów (`##`/`#@#`) wymaga
  przeglądarki, by wstrzyknąć CSS do strony, której DNS-shield nigdy nie
  widzi, a modyfikatory per żądanie jak `$third-party`, `$domain=` czy
  `$script` wymagają strony odsyłającej i typu zasobu, których żadnego nie
  niesie zapytanie DNS - reguła domeny z jednym z tych modyfikatorów jest
  nadal egzekwowana jako bezwarunkowa blokada, ten sam kompromis, jaki
  robią Pi-hole i AdGuard Home. Istnieje osobna, eksperymentalna lista
  zablokowana regex do blokowania opartego na wzorcach (zobacz powyżej),
  ale to płaska lista Twoich własnych wzorców, nie interpreter reguł
  AdBlock.
