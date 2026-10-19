# using QrEd25519Lab;


Testowa aplikacja konsolowa .NET 10 do porównania gęstości QR z podpisem Ed25519 i bez, oraz wariantu awizacji okresowej z obciętym HMAC-SHA256 w trybie QR alphanumeric.

## Uruchomienie

```powershell
dotnet restore
dotnet run -c Release
```

W `LabConfig.cs` można zmienić payload, ECC (L/M/Q/H), wielkość modułu, generowane warianty, 32-bajtowy seed Ed25519 (`PrivateSeedHex`), `kid`, typ JWS, nagłówek ramki binarnej oraz dane awizacji okresowej (`SupplierMasterKeyHex`, `AwizoId`, `AwizoPlate`, `DocNumber`, `ProductCode`, `ProductCodeUtf8`, `DeclaredWeightKg`, `HmacTagBytes`).

W katalogu `output` otrzymasz 10 wariantów SVG (`01_` ... `09_`, `09a_`), odpowiadające im pliki `.bin` z **dokładną zawartością QR**, pliki `.txt` z zawartością (tekst lub zrzut hex) i kodem QR w ASCII (wypisywane też na konsolę), `report.txt` i `public_key.hex`.

Warianty:
1. Plain text
2. Binary byte mode bez podpisu
3. Base64url bez podpisu
4. Binary payload+64B podpis (bez ramki)
5. Base64url wariantu 4
6. Binary PDM1 frame+signature
7. Base64url wariantu 6
8. JWS Compact EdDSA
9. Awizacja okresowa: HMAC-SHA256 (6 B) + Base32, tryb QR alphanumeric (opis niżej)
   - **9a:** jak 9, ale pola tekstowe w UTF-8 (np. polskie znaki) — QR byte mode

W wariantach 4 i 5 podpis weryfikowany jest nad payload. W 6 i 7 nad ramką (`PDM1`+len+payload). W 8 nad ASCII `base64url(header).base64url(payload)`.

**Uwaga:** Warianty 4/5 nie mają wbudowanej informacji o ID klucza ani granicy bajtów bez założenia długości podpisu (64B). 
Dla integracji lepsza jest ramka PDM1 lub JWS. 
QR binarny może być obsługiwany nieprawidłowo przez skanery z interfejsem klawiaturowym, które dekodują jako tekst. 
Testuj czytniki zachowujące oryginalne bajty (np. API skanera).

`JwsType = "JWT"` jest domyślny wyłącznie do testów formatu: dla prostego tekstu niebędącego JWT zmień go na `PDM-QR`.

**Bezpieczeństwo:** Seed prywatny oraz `supplierMasterKey` wypisywane są w `report.txt` dla łatwego powtarzania testów. 
Nie wykorzystuj tego mechanizmu do produkcyjnego zarządzania kluczami. Nie publikuj raportu z rzeczywistym seedem.

## Awizacja okresowa (wariant 9)

- Opis procesu krok po kroku (najprostszy do czytania): [docs/proces-krok-po-kroku.md](docs/proces-krok-po-kroku.md)
- Diagramy przepływu, pseudokod i przykładowe przebiegi HMAC: [docs/awizacja-okresowa.md](docs/awizacja-okresowa.md)

### Problem

Zwykła awizacja zawiera komplet danych: tablica, firma, deklarowana waga, produkt, numer dokumentu.
Awizacja okresowa (np. na miesiąc, nieznana liczba dostaw) zawiera tylko **firmę, tablicę i zakres dat**.
Gdy LPR rozpozna pojazd z taką awizacją, systemowi brakuje danych konkretnej dostawy (produkt, waga, numer dokumentu).
Kierowca skanuje wtedy bilet QR wygenerowany przez dostawcę. Bilet musi być trudny do podrobienia,
ale nie wymaga kryptografii klasy „podpis prawny” — wystarcza obcięty HMAC.

Jednostką jest **awizo** (`AwizoId`, liczba całkowita), nie umowa: umowa nie istnieje w systemie (co najwyżej jako tekst w polu opisowym),
a jednej umowie może odpowiadać wiele awiz. Każde awizo ma własny klucz.

### Klucze: co jest gdzie

| Klucz | Gdzie jest | Kto go zna | Do czego |
|---|---|---|---|
| `supplierMasterKey` (32 B), **jeden na dostawcę** | wyłącznie system wagowy (zaszyfrowany magazyn kluczy, nie zwykła tabela awiz) | tylko GSW | wyprowadzanie kluczy awiz tego dostawcy i weryfikacja biletów |
| `awizoKey` (32 B) = `HMAC-SHA256(supplierMasterKey, "awizo:" + AwizoId)` | **nie jest zapisywany po stronie GSW** (odtwarzany z `supplierMasterKey`); u dostawcy: w aplikacji/pliku generatora | GSW (wylicza) i ten jeden dostawca | tworzenie biletów dla jednego awiza |

Konsekwencje:
- Wyciek `awizoKey` pozwala podrabiać bilety **tylko** dla tego awiza (ta firma, ta tablica, ten zakres dat). Nie daje dostępu do innych awiz.
- Nie trzeba prowadzić bazy kluczy awiz: system wagowy przelicza `awizoKey` z `supplierMasterKey` i `AwizoId`.
- Unieważnienie = zakończenie lub zablokowanie awiza w systemie.
- Rotacja `supplierMasterKey` unieważnia wszystkie awiza **tylko tego dostawcy**; inni dostawcy nie są dotknięci.

### Proces

**1. Dodanie awiza okresowego (GSW, system wagowy)**
1. Tworzymy awizo okresowe: `AwizoId` (liczba całkowita, np. `1045`), firma/dostawca, tablica, zakres dat.
2. System wylicza `awizoKey` z `supplierMasterKey` tego dostawcy i `AwizoId`.
3. Przekazujemy dostawcy (kanałem innym niż publiczny, np. osobiście, zaszyfrowany mail):
   - `AwizoId`,
   - tablicę rejestracyjną z awiza (dostawca musi ją wpisać do generatora — wchodzi do MAC),
   - `awizoKey` (hex) **albo** gotowy generator z wbudowanym kluczem (np. pojedynczy plik HTML działający offline),
   - specyfikację formatu (poniżej) i wektor testowy — dla dostawców z własnym systemem.

   Dostawca **nie dostaje** `supplierMasterKey` ani kluczy innych awiz.

**2. Dostawa (u dostawcy, offline)**
1. Dostawca wpisuje numer dokumentu, kod produktu i deklarowaną wagę.
2. Generator buduje bilet i drukuje/wyświetla QR. Kierowca zabiera go ze sobą.

**3. Przyjazd (GSW)**
1. LPR rozpoznaje tablicę; system znajduje aktywne awizo okresowe i prosi o skan biletu.
2. System dzieli bilet po `*`, sprawdza `V1`, czy `AwizoId` to awizo znalezione dla pojazdu i czy data mieści się w zakresie.
3. Odtwarza `awizoKey` z `supplierMasterKey`, odcina tag, wstawia **tablicę z awiza** po `AwizoId` (nie z odczytu LPR — błąd LPR nie może psuć weryfikacji; zgodność LPR z awizem sprawdzana osobno, z tolerancją), liczy HMAC i porównuje tag.
4. Odrzuca bilet, jeśli `DocNumber` był już użyty w tym awizie (ochrona przed kopiowaniem QR).
5. Po ważeniu porównuje wagę rzeczywistą z deklarowaną.

### Format biletu `V1`

```
QR (tekst):   V1*<AwizoId>*<DocNumber>*<ProductCode>*<DeclaredWeightKg>*<Tag>
Wejście MAC:  V1*<AwizoId>*<TABLICA>*<DocNumber>*<ProductCode>*<DeclaredWeightKg>    (UTF-8)
Tag:          Base32( HMAC-SHA256(awizoKey, wejście MAC)[0..6] )                     (RFC 4648, bez '=')
```

Wejście MAC = tekst biletu bez ostatniego pola (tagu), z tablicą wstawioną po `AwizoId`. Separator w obu miejscach to `*`.

Reguły:
- `AwizoId`, `DeclaredWeightKg`: liczby całkowite dodatnie, zapis dziesiętny, bez zer wiodących, spacji i separatorów tysięcy.
- Pola tekstowe: tylko znaki trybu QR alphanumeric `0-9 A-Z spacja $ % + - . / :` (małe litery zamieniane na wielkie), bez `*` (separator).
  Dzięki temu cały bilet koduje się w trybie alphanumeric (~45% gęściej niż byte).
- `TABLICA`: wielkie litery i cyfry, bez spacji i myślników (`BS 12345` → `BS12345`). Nie ma jej w QR.
- Tag 6 B = 10 znaków Base32; szansa trafienia losowym tagiem 1 : 2⁴⁸ na próbę, a próby wymagają fizycznego skanu przy wadze.

### Wektor testowy (dla implementacji u dostawców)

```
supplierMasterKey = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
AwizoId           = 1045
awizoKey          = D8FDBDF396C750C8FDC4DDFD03F148AEE50501018F4B862793BEE5D80FB49A5A
Tablica           = BS 12345 → BS12345
Wejście MAC       = V1*1045*BS12345*WZ1542/10/2026*TOW123*24500
Bilet             = V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM
```

Wynik: 46 znaków, QR wersja 3 (29×29 modułów) przy ECC M — najmniejszy z wariantów w laboratorium.

### Wariant 9a — pola tekstowe UTF-8

Format, klucze i weryfikacja jak w wariancie 9. Różni się tylko zestaw znaków w polach tekstowych (`DocNumber`, `ProductCode`):

- dozwolony **dowolny znak UTF-8** poza separatorem `*` i znakami sterującymi (CR, LF, TAB…),
- tekst normalizowany do **Unicode NFC** (`Ż` jako jeden znak, nie `Z` + kropka łącząca) i zamieniany na wielkie litery — po obu stronach,
- HMAC liczony z bajtów UTF-8 (`Ż` = `C5 BB`, `Ó` = `C3 93`, `Ł` = `C5 81`).

Koszt: bilet nie mieści się w trybie alphanumeric, więc QR przechodzi na tryb byte i jest większy.

```
ProductCode = GŻEGŻÓŁKA-245+18
Wejście MAC = V1*1045*BS12345*WZ1542/10/2026*GŻEGŻÓŁKA-245+18*24500        (57 B)
HMAC (32 B) = 365E5CD09C9C57D932B8935947046E7386E1B4AA65BBEC86D978FF70F316DC54
Tag Base32  = GZPFZUE4TQ
Bilet       = V1*1045*WZ1542/10/2026*GŻEGŻÓŁKA-245+18*24500*GZPFZUE4TQ   (56 znaków, 60 B UTF-8)
```

Wynik: QR wersja 4 (33×33). Ten sam towar po transliteracji (`GZEGZOLKA-245+18`) mieści się w wariancie 9: 56 znaków alphanumeric → nadal wersja 3 (29×29).

**Ryzyko:** skanery działające jak klawiatura często psują polskie znaki (układ klawiatury, AltGr, strona kodowa).
Przed wyborem 9a trzeba sprawdzić wszystkie skanery na wadze, czy przekazują `GŻEGŻÓŁKA` bez zmian — inaczej tag się nie zgodzi.

## Zależności

- QRCoder 
- BouncyCastle.Cryptography  
 
