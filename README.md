# using QrEd25519Lab;


Testowa aplikacja konsolowa .NET 10 do porównania gęstości QR z podpisem Ed25519 i bez.

## Uruchomienie

```powershell
dotnet restore
dotnet run -c Release
```

W `LabConfig.cs` można zmienić payload, ECC (L/M/Q/H), wielkość modułu, generowane warianty, 32-bajtowy seed Ed25519 (`PrivateSeedHex`), `kid`, typ JWS, nagłówek ramki binarnej.

W katalogu `output` otrzymasz 8 wariantów SVG (`01_` ... `08_`), odpowiadające im pliki `.bin` z **dokładną zawartością QR**, `report.txt` i `public_key.hex`.

Warianty:
1. Plain text
2. Binary byte mode bez podpisu
3. Base64url bez podpisu
4. Binary payload+64B podpis (bez ramki)
5. Base64url wariantu 4
6. Binary PDM1 frame+signature
7. Base64url wariantu 6
8. JWS Compact EdDSA

W wariantach 4 i 5 podpis weryfikowany jest nad payload. W 6 i 7 nad ramką (`PDM1`+len+payload). W 8 nad ASCII `base64url(header).base64url(payload)`.

**Uwaga:** Warianty 4/5 nie mają wbudowanej informacji o ID klucza ani granicy bajtów bez założenia długości podpisu (64B). Dla integracji lepsza jest ramka PDM1 lub JWS. QR binarny może być obsługiwany nieprawidłowo przez skanery z interfejsem klawiaturowym, które dekodują jako tekst. Testuj czytniki zachowujące oryginalne bajty (np. API skanera).

`JwsType = "JWT"` jest domyślny wyłącznie do testów formatu: dla prostego tekstu niebędącego JWT zmień go na `PDM-QR`.

**Bezpieczeństwo:** Seed prywatny wypisywany w `report.txt` dla łatwego powtarzania testów. Nie wykorzystuj tego mechanizmu do produkcyjnego zarządzania kluczami. Nie publikuj raportu z rzeczywistym seedem.

## Zależności

- QRCoder 1.8.0
- BouncyCastle.Cryptography 2.5.1

Pliki przygotowane jako kod źródłowy, bez lokalnego builda (brak SDK w środowisku tworzenia).
