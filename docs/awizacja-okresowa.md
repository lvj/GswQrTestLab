# Awizacja okresowa — przepływ (wariant 9)

Bilet QR `V1` uwierzytelniony obciętym HMAC-SHA256, kodowany w trybie QR alphanumeric.
Format i zasady: [README](../README.md#awizacja-okresowa-wariant-9). Opis tekstowy krok po kroku: [proces-krok-po-kroku.md](proces-krok-po-kroku.md).
Implementacja referencyjna: [AwizoTicket.cs](../AwizoTicket.cs).

Jednostką jest **awizo** (`AwizoId`, liczba całkowita), nie umowa — umowa nie istnieje w systemie, a jednej umowie może odpowiadać wiele awiz.
Każdy dostawca ma własny `supplierMasterKey`, każde awizo okresowe ma własny klucz `awizoKey`.

## 1. Klucze — co jest gdzie

```mermaid
flowchart LR
    subgraph WAGA["System wagowy GSW"]
        MK[("supplierMasterKey<br/>32 B, jeden na dostawcę,<br/>zaszyfrowany magazyn kluczy")]
        DB[("Awiza okresowe<br/>AwizoId, dostawca, tablica, zakres dat,<br/>użyte DocNumber")]
    end

    subgraph DOST["Dostawca (offline)"]
        GEN["Generator biletów<br/>(plik HTML / aplikacja / własny system)"]
        AK[("awizoKey<br/>tylko dla 1 awiza")]
    end

    MK -- "HMAC(supplierMasterKey, 'awizo:' + AwizoId)" --> DERIV["awizoKey"]
    DB -- AwizoId --> DERIV
    DERIV -. "przekazany raz, bezpiecznym kanałem,<br/>razem z AwizoId i tablicą" .-> AK
    AK --> GEN
    GEN -- "bilet QR (wydruk / telefon)" --> KIER(["Kierowca"])
```

- `supplierMasterKey` nigdy nie opuszcza systemu wagowego.
- `awizoKey` nie jest zapisywany po stronie GSW — zawsze można go przeliczyć.
- Wyciek `awizoKey` = możliwość podrobienia biletów tylko dla tego jednego awiza.

## 2. Przebieg end-to-end

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator GSW
    participant W as System wagowy
    actor D as Dostawca
    participant G as Generator (offline)
    actor K as Kierowca
    participant L as LPR + skaner QR

    rect rgb(235, 245, 255)
    Note over Op,G: Etap 1 — dodanie awiza okresowego (raz)
    Op->>W: utwórz awizo okresowe (dostawca, tablica, od–do)
    W->>W: AwizoId = 1045<br/>awizoKey = HMAC(supplierMasterKey, "awizo:1045")
    W-->>Op: AwizoId, tablica, awizoKey / gotowy generator
    Op-->>D: przekazanie (osobiście / szyfrowany mail)
    D->>G: instalacja generatora z awizoKey
    end

    rect rgb(240, 255, 240)
    Note over D,K: Etap 2 — każda dostawa (offline)
    D->>G: DocNumber, ProductCode, DeclaredWeightKg
    G->>G: tag = HMAC(awizoKey, wejście MAC)[0..6]<br/>bilet = V1*...*Base32(tag)
    G-->>K: wydruk QR
    end

    rect rgb(255, 245, 235)
    Note over K,W: Etap 3 — przyjazd na wagę
    K->>L: wjazd
    L->>W: odczyt tablicy (LPR)
    W->>W: aktywne awizo okresowe dla tablicy?<br/>brakuje produktu/wagi/dokumentu
    W-->>K: „zeskanuj bilet”
    K->>L: skan QR
    L->>W: V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM
    W->>W: weryfikacja (sekcja 5)
    alt bilet poprawny
        W-->>K: wjazd, ważenie
        W->>W: zapis DocNumber jako użytego<br/>porównanie wagi rzeczywistej z deklarowaną
    else bilet odrzucony
        W-->>Op: alarm / obsługa ręczna
    end
    end
```

## 3. Etap 1 — dodanie awiza okresowego (system wagowy)

```text
function AddPeriodicAwizo(supplierId, plate, validFrom, validTo, freeText):
    awizoId  = NextAwizoId()                               // liczba całkowita, np. 1045
    awizo    = { awizoId, supplierId,
                 plate: NormalizePlate(plate),             // "BS 12345" -> "BS12345"
                 validFrom, validTo,
                 note: freeText,                           // np. numer umowy, jeśli ktoś wpisze — nie bierze udziału w kryptografii
                 status: ACTIVE, usedDocNumbers: {} }
    db.Save(awizo)

    supplierMasterKey = keyStore.GetSupplierMasterKey(supplierId)
    awizoKey = HMAC_SHA256(supplierMasterKey, UTF8("awizo:" + ToString(awizoId)))
    // awizoKey NIE jest zapisywany w bazie

    return SupplierPackage {
        awizoId,
        plate:    awizo.plate,
        awizoKey: Hex(awizoKey),                           // albo generator HTML z wbudowanym kluczem
        spec:     "README: Format biletu V1 + wektor testowy"
    }
```

## 4. Etap 2 — generowanie biletu (dostawca, offline)

```text
// Konfiguracja generatora (otrzymana raz):  awizoId, plate, awizoKey
function CreateTicket(docNumber, productCode, weightKg):
    fields = [ "V1",
               ToString(awizoId),                          // "1045" — bez zer wiodących
               Upper(docNumber),                           // np. "WZ1542/10/2026"
               Upper(productCode),                         // np. "TOW123"
               ToString(weightKg) ]                        // liczba całkowita, np. "24500"
    Require(text fields use only "0-9 A-Z space $ % + - . / :")

    macInput = Join("*", [ fields[0], fields[1], NormalizePlate(plate), fields[2], fields[3], fields[4] ])
             // "V1*1045*BS12345*WZ1542/10/2026*TOW123*24500"

    tag      = HMAC_SHA256(awizoKey, UTF8(macInput))[0..6]
    ticket   = Join("*", fields + [ Base32_NoPadding(tag) ])
             // "V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM"

    return QrCode(ticket, ecc: M)                          // biblioteka wybierze tryb alphanumeric
```

Przeglądarkowy generator offline (szkic):

```js
const key = await crypto.subtle.importKey("raw", hexToBytes(AWIZO_KEY),
                                          { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
const macInput = [fields[0], fields[1], PLATE, ...fields.slice(2)].join("*");
const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(macInput)));
const ticket = fields.join("*") + "*" + base32(mac.slice(0, 6));
```

## 5. Etap 3 — weryfikacja na wadze

```mermaid
flowchart TD
    A([LPR: odczyt tablicy]) --> B{Aktywne awizo okresowe<br/>dla tablicy?}
    B -- nie --> X1[Zwykła ścieżka / obsługa ręczna]
    B -- tak --> C[Prośba o skan biletu]
    C --> D{Format: 6 pól, 'V1'?}
    D -- nie --> R[Odrzuć: zły format]
    D -- tak --> E{AwizoId z biletu<br/>= awizo znalezione dla pojazdu?}
    E -- nie --> R2[Odrzuć: bilet innego awiza]
    E -- tak --> F{Dziś w zakresie dat<br/>i awizo aktywne?}
    F -- nie --> R3[Odrzuć: awizo nieaktywne]
    F -- tak --> G["awizoKey = HMAC(supplierMasterKey, 'awizo:' + AwizoId)<br/>MAC z tablicą Z AWIZA"]
    G --> H{Tag zgodny?<br/>porównanie stałoczasowe}
    H -- nie --> R4[Odrzuć: podrobiony / błędne dane]
    H -- tak --> I{DocNumber już użyty<br/>w tym awizie?}
    I -- tak --> R5[Odrzuć: kopia biletu]
    I -- nie --> J[Akceptuj, zapisz DocNumber]
    J --> K[Ważenie: porównaj wagę rzeczywistą z deklarowaną]

    R & R2 & R3 & R4 & R5 --> Z[Alarm / obsługa ręczna]
```

```text
function OnTicketScanned(lprPlate, ticket):
    awizo = db.FindActivePeriodicAwizoByPlate(lprPlate, tolerance: FUZZY)   // błąd LPR obsługiwany tutaj
    if awizo == null:                                   return Reject("brak awiza okresowego")

    parts = Split(Trim(ticket), "*")
    if parts.Length != 6 or parts[0] != "V1":           return Reject("zły format")
    [ver, awizoId, docNumber, productCode, weightKg, tag] = parts

    if awizoId != ToString(awizo.awizoId):              return Reject("bilet innego awiza")
    if not (awizo.validFrom <= Today <= awizo.validTo)
       or awizo.status != ACTIVE:                       return Reject("awizo nieaktywne")

    supplierMasterKey = keyStore.GetSupplierMasterKey(awizo.supplierId)
    awizoKey = HMAC_SHA256(supplierMasterKey, UTF8("awizo:" + awizoId))
    macInput = Join("*", [ver, awizoId, awizo.plate, docNumber, productCode, weightKg])
             // pola biletu bez tagu + tablica z AWIZA (nie z odczytu LPR) wstawiona po awizoId
    expected = Base32_NoPadding(HMAC_SHA256(awizoKey, UTF8(macInput))[0..6])
    if not FixedTimeEquals(expected, tag):              return Reject("niepoprawny tag")

    if docNumber in awizo.usedDocNumbers:               return Reject("bilet już użyty")
    awizo.usedDocNumbers.Add(docNumber)                 // atomowo, razem z otwarciem ważenia

    return Accept(delivery: { awizo, docNumber, productCode, declaredWeightKg: weightKg })
```

## 6. HMAC_SHA256 krok po kroku — przykładowe przebiegi

Wartości z wektora testowego (`supplierMasterKey = 00 01 02 … 1F`). Można je odtworzyć laboratorium (`SupplierMasterKeyHex` w `LabConfig.cs`)
lub dowolną biblioteką HMAC-SHA256 — dostawcy mogą tym sprawdzić własną implementację krok po kroku.

```mermaid
flowchart TD
    subgraph S1["Przebieg 1 — wyprowadzenie klucza awiza (system wagowy, przy tworzeniu awiza i przy każdej weryfikacji)"]
        MK["supplierMasterKey (32 B)<br/>000102030405060708090A0B0C0D0E0F<br/>101112131415161718191A1B1C1D1E1F"]
        DIN["dane: UTF8('awizo:1045') (10 B)<br/>6177697A6F3A31303435"]
        H1(["HMAC_SHA256"])
        AK["awizoKey (32 B)<br/>D8FDBDF396C750C8FDC4DDFD03F148AE<br/>E50501018F4B862793BEE5D80FB49A5A"]
        MK -- klucz --> H1
        DIN -- dane --> H1
        H1 --> AK
    end

    subgraph S2["Przebieg 2 — tag biletu (dostawca tworzy; waga przelicza i porównuje)"]
        F["pola od dostawcy:<br/>1045 · WZ1542/10/2026 · TOW123 · 24500"]
        P["tablica z awiza:<br/>BS 12345 → BS12345"]
        MI["wejście MAC (43 B):<br/>V1*1045*BS12345*WZ1542/10/2026*TOW123*24500"]
        H2(["HMAC_SHA256"])
        FULL["wynik (32 B)<br/>4C6D6F69846BC617A38280727A781065<br/>92E86A539EFDEF962D41F7D25F64C496"]
        TR["obcięcie do 6 B<br/>4C 6D 6F 69 84 6B"]
        B32["Base32 (48 bitów → 10 znaków)<br/>JRWW62MENM"]
        T["bilet (46 znaków, QR v3):<br/>V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM"]
        F --> MI
        P --> MI
        MI -- dane --> H2
        H2 --> FULL --> TR --> B32 --> T
    end

    AK -- klucz --> H2
```

### Przebieg 1 — wyprowadzenie `awizoKey`

```text
> awizoKey = HMAC_SHA256(key = supplierMasterKey, data = UTF8("awizo:1045"))

  key   = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F   (32 B)
  data  = 61 77 69 7A 6F 3A 31 30 34 35                                      (10 B, "awizo:1045")
  ----
  awizoKey = D8FDBDF396C750C8FDC4DDFD03F148AEE50501018F4B862793BEE5D80FB49A5A
```

### Przebieg 2 — tag biletu, z wnętrzem HMAC

HMAC to dwa wywołania SHA-256: `HMAC(K, m) = SHA256( (K ⊕ opad) ‖ SHA256( (K ⊕ ipad) ‖ m ) )`,
gdzie `K` to klucz dopełniony zerami do 64 B, `ipad = 0x36…`, `opad = 0x5C…`.

```text
> tag = HMAC_SHA256(key = awizoKey, data = UTF8("V1*1045*BS12345*WZ1542/10/2026*TOW123*24500"))

  K         = D8FDBDF3…0FB49A5A ‖ 00 × 32                                      (64 B)
  K ⊕ ipad  = EECB8BC5A0F166FECBF2EBCB35C77E98…                                (64 B)
  K ⊕ opad  = 84A1E1AFCA9B0C94A19881A15FAD14F2…                                (64 B)

  inner = SHA256( K⊕ipad ‖ data )
        = 79E2947AADC34E458E85CE415DA975A6E31FB52A283F724682E061717A5CB461
  outer = SHA256( K⊕opad ‖ inner )
        = 4C6D6F69846BC617A38280727A78106592E86A539EFDEF962D41F7D25F64C496   ← wynik HMAC

  [0..6]   = 4C 6D 6F 69 84 6B
  bity     = 01001 10001 10110 10110 11110 11010 01100 00100 01101 011(00)
  indeksy  =   9    17    22    22    30    26    12     4    13    12
  Base32   =   J     R     W     W     6     2     M     E     N     M      → "JRWW62MENM"
```

### Przebieg 3 — odczyt i weryfikacja biletu na wadze, krok po kroku

Waga **nie odszyfrowuje** tagu — HMAC jest jednokierunkowy. Waga liczy tag jeszcze raz z tych samych danych
(pola z biletu + tablica z awiza + `awizoKey` odtworzony z `supplierMasterKey`) i sprawdza, czy wyszedł identyczny.

```mermaid
flowchart TD
    S0["Krok 0: Skaner (klawiatura) przesyła tekst + Enter<br/>V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM⏎"]
    S1["Krok 1: Oczyszczenie: Trim (usuń CR/LF, spacje na końcach)"]
    S2["Krok 2: Podział po '*' → 6 części<br/>V1 · 1045 · WZ1542/10/2026 · TOW123 · 24500 · JRWW62MENM"]
    S3{"Krok 3: parts[0] = 'V1'<br/>i 6 części?"}
    S4["Krok 4: Awizo z bazy (znalezione po LPR):<br/>AwizoId = 1045, plate = BS12345,<br/>01.10–31.10, ACTIVE"]
    S5{"Krok 5: AwizoId z biletu = 1045<br/>i dziś w zakresie dat?"}
    S6["Krok 6: awizoKey = HMAC_SHA256(supplierMasterKey, 'awizo:1045')<br/>= D8FDBDF3…0FB49A5A  (Przebieg 1)"]
    S7["Krok 7: Odcięcie tagu, wstawienie tablicy Z AWIZA po AwizoId:<br/>V1*1045*BS12345*WZ1542/10/2026*TOW123*24500"]
    S8["Krok 8: HMAC_SHA256(awizoKey, wejście MAC)<br/>= 4C6D6F69846BC617…5F64C496  (Przebieg 2)"]
    S9["Krok 9: Obcięcie do 6 B → Base32<br/>expected = JRWW62MENM"]
    S10{"Krok 10: FixedTimeEquals(expected, 'JRWW62MENM')"}
    S11{"Krok 11: DocNumber WZ1542/10/2026<br/>już użyty w awizie 1045?"}
    OK["✔ Akceptuj: zapisz DocNumber,<br/>uzupełnij dostawę: TOW123, 24500 kg, WZ1542/10/2026"]
    NO["✘ Odrzuć → alarm / obsługa ręczna"]

    S0 --> S1 --> S2 --> S3
    S3 -- tak --> S4 --> S5
    S3 -- nie --> NO
    S5 -- tak --> S6 --> S7 --> S8 --> S9 --> S10
    S5 -- nie --> NO
    S10 -- zgodny --> S11
    S10 -- niezgodny --> NO
    S11 -- nie --> OK
    S11 -- tak --> NO
```

```text
> raw = ScannerRead()
  raw = "V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM\r\n"

> ticket = Trim(raw)
  ticket = "V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM"            (46 znaków)

> parts = Split(ticket, "*")
  parts[0] ver          = "V1"                ✔ znana wersja
  parts[1] awizoId      = "1045"              ✔ liczba całkowita
  parts[2] docNumber    = "WZ1542/10/2026"
  parts[3] productCode  = "TOW123"
  parts[4] weightKg     = "24500"             ✔ liczba całkowita
  parts[5] tag          = "JRWW62MENM"        ✔ 10 znaków A-Z2-7
  parts.Length          = 6                   ✔

> awizo = db.FindActivePeriodicAwizoByPlate(lprPlate = "BS12346")   // LPR pomylił ostatnią cyfrę
  awizo = { awizoId: 1045, supplierId: 77, plate: "BS12345", validFrom: 2026-10-01, validTo: 2026-10-31, status: ACTIVE }
          // dopasowanie z tolerancją; do MAC idzie awizo.plate, więc błąd LPR nie psuje weryfikacji

> awizoId == ToString(awizo.awizoId)          "1045" == "1045"                   ✔
> validFrom <= Today <= validTo               2026-10-01 <= 2026-10-19 <= 2026-10-31   ✔

> supplierMasterKey = keyStore.GetSupplierMasterKey(77)
> awizoKey = HMAC_SHA256(supplierMasterKey, UTF8("awizo:1045"))
  awizoKey = D8FDBDF396C750C8FDC4DDFD03F148AEE50501018F4B862793BEE5D80FB49A5A

> macInput = Join("*", [ver, awizoId, awizo.plate, docNumber, productCode, weightKg])
  macInput = "V1*1045*BS12345*WZ1542/10/2026*TOW123*24500"

> mac      = HMAC_SHA256(awizoKey, UTF8(macInput))
  mac      = 4C6D6F69846BC617A38280727A78106592E86A539EFDEF962D41F7D25F64C496
> expected = Base32_NoPadding(mac[0..6]) = Base32(4C 6D 6F 69 84 6B) = "JRWW62MENM"

> FixedTimeEquals(expected, tag)
  expected  J R W W 6 2 M E N M
  tag       J R W W 6 2 M E N M
            ✔ wszystkie 10 znaków zgodne     (porównywane są zawsze wszystkie znaki, bez wczesnego wyjścia)

> "WZ1542/10/2026" in awizo.usedDocNumbers    → nie                              ✔
> awizo.usedDocNumbers.Add("WZ1542/10/2026")  // atomowo z otwarciem ważenia

> Accept → dostawa: awizo 1045, BS12345, TOW123, deklarowane 24500 kg, dokument WZ1542/10/2026
```

Równoważnie zamiast kodować `expected` do Base32 można zdekodować tag z biletu do bajtów
(`Base32Decode("JRWW62MENM") = 4C 6D 6F 69 84 6B`) i porównać 6 bajtów z `mac[0..6]` — wynik ten sam.

Dlaczego porównanie stałoczasowe: zwykłe `==` kończy na pierwszej różnicy, więc czas odpowiedzi zdradzałby,
ile początkowych znaków tagu jest poprawnych. Przy wadze (fizyczny skan) to ryzyko teoretyczne, ale koszt jest zerowy.

### Przebieg 4 — weryfikacja na wadze: trzy skany

Waga zawsze liczy tag od nowa z danych z biletu i **tablicy z awiza**, potem porównuje z tagiem z biletu.

```mermaid
flowchart LR
    subgraph OK["Skan A — oryginał"]
        A1["waga 24500<br/>tablica awiza BS12345"] --> A2(["HMAC → JRWW62MENM"]) --> A3{"= JRWW62MENM?"} --> A4["✔ akceptuj"]
    end
    subgraph BAD1["Skan B — ktoś zmienił wagę w bilecie"]
        B1["waga 25500<br/>tablica awiza BS12345"] --> B2(["HMAC → ZKAG6R4G4Q"]) --> B3{"= JRWW62MENM?"} --> B4["✘ odrzuć"]
    end
    subgraph BAD2["Skan C — bilet przywieziony innym pojazdem (awizo z BS99999)"]
        C1["waga 24500<br/>tablica awiza BS99999"] --> C2(["HMAC → IL7UNPAE3U"]) --> C3{"= JRWW62MENM?"} --> C4["✘ odrzuć"]
    end
```

```text
> A: bilet  V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM,  awizo.plate = BS12345
     macInput = V1*1045*BS12345*WZ1542/10/2026*TOW123*24500
     expected = JRWW62MENM   tag z biletu = JRWW62MENM   → ZGODNY

> B: bilet  V1*1045*WZ1542/10/2026*TOW123*25500*JRWW62MENM,  awizo.plate = BS12345
     macInput = V1*1045*BS12345*WZ1542/10/2026*TOW123*25500
     expected = ZKAG6R4G4Q   tag z biletu = JRWW62MENM   → NIEZGODNY (zmiana 1 znaku zmienia cały tag)

> C: ten sam bilet co A, ale awizo.plate = BS99999
     macInput = V1*1045*BS99999*WZ1542/10/2026*TOW123*24500
     expected = IL7UNPAE3U   tag z biletu = JRWW62MENM   → NIEZGODNY
     (w praktyce odrzucony już wcześniej: AwizoId z biletu ≠ awizo znalezione dla tego pojazdu)
```

## 7. Co chroni przed czym

| Zagrożenie | Ochrona |
|---|---|
| Ręcznie wymyślony / zmieniony bilet | tag HMAC (1 : 2⁴⁸ na próbę, próby tylko fizycznie przy wadze) |
| Przesunięcie znaków między polami (np. z numeru dokumentu do kodu produktu) | separator `*` w wejściu MAC; `*` niedozwolony w polach |
| Bilet z awiza A użyty dla pojazdu z awiza B | `AwizoId` musi zgadzać się z awizem pojazdu; tablica z awiza w MAC |
| Skopiowany QR (druga dostawa na ten sam bilet) | unikalność `DocNumber` w awizie |
| Bilet po końcu okresu awiza | zakres dat / status awiza w systemie |
| Wyciek `awizoKey` od dostawcy | szkoda ograniczona do 1 awiza; zablokuj je i wystaw nowe awizo (nowy `AwizoId`) |
| Zawyżona / zaniżona deklarowana waga | ważenie rzeczywiste |
| Wyciek `supplierMasterKey` | poważne, ale tylko dla jednego dostawcy — nowy klucz główny dostawcy, nowe awiza i klucze dla jego aktywnych awiz |
