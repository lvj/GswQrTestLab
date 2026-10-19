# Awizacja okresowa z biletem QR — proces krok po kroku

Prosty opis tekstowy. Diagramy i szczegółowe przebiegi HMAC: [awizacja-okresowa.md](awizacja-okresowa.md).
Implementacja referencyjna: [AwizoTicket.cs](../AwizoTicket.cs).

Przykładowe wartości w całym dokumencie pochodzą z wektora testowego (na końcu).

## A. Przygotowanie dostawcy (GSW, raz na dostawcę)

1. GSW generuje **jeden klucz główny na dostawcę**: `supplierMasterKey` — 32 losowe bajty.
2. Klucz główny dostawcy jest przechowywany **wyłącznie w systemie wagowym GSW**, w zaszyfrowanym magazynie kluczy
   (nie w zwykłej tabeli awiz). **Nigdy nie jest przekazywany dostawcy.**

## B. Utworzenie awiza okresowego (GSW, raz na awizo)

3. GSW tworzy awizo okresowe: `AwizoId` (liczba całkowita, np. `1045`), dostawca, tablica rejestracyjna, zakres dat.
4. System wylicza klucz tego awiza:

   ```
   awizoKey = HMAC_SHA256(supplierMasterKey, "awizo:" + AwizoId)
   ```

   - tekst `"awizo:1045"` kodowany jako UTF-8; prefiks `awizo:` dokładnie tak, **małymi literami**, z dwukropkiem, bez spacji,
   - `AwizoId` zapisany dziesiętnie, bez zer wiodących (`1045`, nie `01045`).
5. `awizoKey` **nie jest zapisywany** po stronie GSW — w razie potrzeby zawsze można go wyliczyć ponownie z kroku 4.
6. GSW przekazuje dostawcy bezpiecznym kanałem (osobiście, zaszyfrowany mail):
   - `AwizoId`,
   - tablicę rejestracyjną z awiza,
   - `awizoKey` (64 znaki hex) **albo** gotowy generator z wbudowanym kluczem (np. plik HTML działający offline),
   - dla dostawców z własnym systemem: tę specyfikację i wektor testowy.

   Dostawca **nie dostaje** `supplierMasterKey` ani kluczy innych awiz.

## C. Wystawienie biletu (dostawca, przy każdej dostawie, offline)

7. Dostawca wpisuje dane dostawy: numer dokumentu, kod produktu, deklarowaną wagę w kg.
8. Generator **normalizuje pola**:
   - pola tekstowe (numer dokumentu, kod produktu): usunięcie spacji z początku i końca, **zamiana na wielkie litery**,
   - dozwolone znaki w polach tekstowych: `0-9 A-Z spacja $ % + - . / :` — inne (w tym `*` i polskie znaki) są odrzucane,
   - liczby (`AwizoId`, waga): zapis dziesiętny, bez zer wiodących, spacji, separatorów tysięcy i części ułamkowej,
   - tablica: wielkie litery i cyfry, **bez spacji i myślników** (`BS 12345` → `BS12345`).
9. Generator buduje **wejście MAC** — pola połączone znakiem `*`, w tej kolejności:

   ```
   V1*<AwizoId>*<TABLICA>*<DocNumber>*<ProductCode>*<DeclaredWeightKg>
   V1*1045*BS12345*WZ1542/10/2026*TOW123*24500
   ```

10. Generator liczy HMAC i bierze **pierwsze 6 bajtów** wyniku:

    ```
    mac = HMAC_SHA256(awizoKey, UTF8(wejście MAC))   → 4C6D6F69846BC617…  (32 B)
    tag = mac[0..6]                                  → 4C 6D 6F 69 84 6B
    ```

11. Tag jest kodowany w **Base32** (RFC 4648, alfabet `A-Z 2-7`, wielkie litery, **bez znaków `=`**): 6 bajtów → 10 znaków.

    ```
    Base32(4C 6D 6F 69 84 6B) = JRWW62MENM
    ```

12. Generator składa **tekst biletu** — to samo co wejście MAC, ale **bez tablicy**, z tagiem na końcu:

    ```
    V1*<AwizoId>*<DocNumber>*<ProductCode>*<DeclaredWeightKg>*<Tag>
    V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM
    ```

13. Generator drukuje/wyświetla kod QR z tym tekstem (ECC M). Wszystkie znaki należą do trybu QR alphanumeric,
    więc kod jest mały (46 znaków → QR wersja 3, 29×29 modułów). Kierowca zabiera bilet.

## D. Weryfikacja na wadze (GSW, przy każdym przyjeździe)

14. LPR odczytuje tablicę; system szuka **aktywnego awiza okresowego** dla tej tablicy
    (z tolerancją na błędy odczytu LPR). Brak awiza → zwykła ścieżka / obsługa ręczna.
15. System prosi kierowcę o zeskanowanie biletu. Skaner przesyła tekst biletu; system usuwa znaki końca linii i spacje z końców.
16. System dzieli tekst po `*`. Muszą być **dokładnie 6 części** i pierwsza musi być `V1` — inaczej odrzuca.

    ```
    V1 | 1045 | WZ1542/10/2026 | TOW123 | 24500 | JRWW62MENM
    ```

17. System sprawdza, że `AwizoId` z biletu (`1045`) to **awizo znalezione dla pojazdu** w kroku 14,
    że awizo jest aktywne i dzisiejsza data mieści się w jego zakresie — inaczej odrzuca.
18. System pobiera `supplierMasterKey` dostawcy przypisanego do awiza i **odtwarza** `awizoKey` tak jak w kroku 4.
19. System **odcina ostatnią część (tag)** i odkłada ją do porównania.
20. System **wstawia tablicę po `AwizoId`** — tablicę **z awiza w bazie**, znormalizowaną jak w kroku 8,
    **nie** z odczytu LPR (pomyłka LPR nie może psuć weryfikacji). Wynik to wejście MAC, identyczne jak u dostawcy w kroku 9:

    ```
    V1*1045*BS12345*WZ1542/10/2026*TOW123*24500
    ```

21. System liczy `HMAC_SHA256(awizoKey, wejście MAC)`, bierze pierwsze 6 bajtów i koduje w Base32 → `JRWW62MENM`.
22. System porównuje wynik z tagiem z biletu **porównaniem stałoczasowym** (zawsze wszystkie znaki).
    Różnica → bilet podrobiony lub zmieniony → odrzucenie.
23. System sprawdza, czy `DocNumber` nie był już użyty w tym awizie. Był → kopia biletu → odrzucenie.
24. Bilet przyjęty: system zapisuje `DocNumber` jako użyty (razem z otwarciem ważenia) i uzupełnia dostawę
    o produkt, deklarowaną wagę i numer dokumentu.
25. Po ważeniu system porównuje wagę rzeczywistą z deklarowaną.

## Uwagi

- **HMAC nie jest szyfrowaniem.** Z tagu nie da się odczytać danych ani klucza. Obie strony liczą tę samą wartość
  z tych samych danych i sprawdzają, czy wynik jest identyczny.
- **Ten sam klucz dla wszystkich dostaw w awizie** jest zamierzony i bezpieczny — tagi różnią się, bo różnią się dane.
  Zebranie wielu biletów nie pozwala odtworzyć klucza.
- **Wielkie litery:** cały bilet i wejście MAC są wielkimi literami — z jednym wyjątkiem: prefiks `awizo:` w kroku 4
  (to stała, nie trafia do QR).
- **Separator `*`:** zabroniony w polach, dzięki czemu nie da się przesunąć znaków między polami bez zmiany tagu.
- **Polskie znaki:** w wariancie 9 niedozwolone. Generator może je odrzucić albo zamienić stałą tabelą
  (`Ą→A Ć→C Ę→E Ł→L Ń→N Ó→O Ś→S Ź→Z Ż→Z`) **przed** liczeniem HMAC — wtedy bilet i weryfikacja działają bez zmian.
  Alternatywa: wariant **9a** (pola UTF-8, np. `GŻEGŻÓŁKA-245+18`) — patrz [README](../README.md#wariant-9a--pola-tekstowe-utf-8):
  większy QR (tryb byte), normalizacja NFC po obu stronach i konieczność sprawdzenia, czy skanery nie psują polskich znaków.
- **Tablicy nie ma w QR**, ale jest w HMAC — bilet wystawiony na inną tablicę nie przejdzie weryfikacji.
- **Wyciek `awizoKey`** (np. z komputera dostawcy): ktoś może wystawiać bilety tylko dla tego jednego awiza
  (ta tablica, ten okres). Reakcja: zablokować awizo i wystawić nowe (nowy `AwizoId` = nowy klucz).
- **Wyciek `supplierMasterKey`**: poważny, ale dotyczy tylko jednego dostawcy. Reakcja: nowy klucz główny dla tego dostawcy
  i nowe klucze dla jego aktywnych awiz.
- **Zmiana formatu** w przyszłości (np. inne pola) — nowa wersja `V2`; system może przez jakiś czas akceptować obie.

## Wektor testowy

Do sprawdzenia własnej implementacji (np. u dostawcy z własnym systemem):

```
supplierMasterKey = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
AwizoId           = 1045
dane klucza       = "awizo:1045"   (hex: 6177697A6F3A31303435)
awizoKey          = D8FDBDF396C750C8FDC4DDFD03F148AEE50501018F4B862793BEE5D80FB49A5A

Tablica           = BS 12345 → BS12345
DocNumber         = WZ1542/10/2026
ProductCode       = TOW123
DeclaredWeightKg  = 24500

Wejście MAC       = V1*1045*BS12345*WZ1542/10/2026*TOW123*24500
HMAC (32 B)       = 4C6D6F69846BC617A38280727A78106592E86A539EFDEF962D41F7D25F64C496
Tag (6 B)         = 4C6D6F69846B
Tag Base32        = JRWW62MENM

Bilet (QR)        = V1*1045*WZ1542/10/2026*TOW123*24500*JRWW62MENM
```
