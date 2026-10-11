# Dodanie TZNSECVIRUS do winget

Winget pobiera paczki z **trwałego adresu HTTPS**. Twoja binarka musi więc najpierw
trafić na GitHub Releases. Poniżej pełna procedura.

---

## Krok 1 — wypchnij źródła na GitHub

```bash
cd "C:\Users\wojte\Documents\moje projekty\tznsecvirus"
git init
git add .
git commit -m "TZNSECVIRUS 2.0.0"
git branch -M main
git remote add origin https://github.com/TWOJ-USER/tznsecvirus.git
git push -u origin main
```

> **Ważne:** `tznsecvirus.exe`, `target/` i `.gitignore` — sprawdź `.gitignore`,
> żeby binarka nie poszła do repo (i tak wrzucisz ją jako *asset* release).

---

## Krok 2 — zrób Release z binarką

Na GitHubie: **Releases → Draft a new release**

- Tag: `v2.0.0`
- Tytuł: `TZNSECVIRUS 2.0.0`
- **Attach files**: przeciągnij `tznsecvirus.exe`

Po publikacji adres będzie:

```
https://github.com/TWOJ-USER/tznsecvirus/releases/download/v2.0.0/tznsecvirus.exe
```

---

## Krok 3 — policz SHA256 nowej binarki

Kiedy zrobisz nowy build, **hash się zmienia** — musisz go zaktualizować:

```powershell
(Get-FileHash .\tznsecvirus.exe -Algorithm SHA256).Hash
```

Wklej do `winget\TZNSECVIRUS.installer.yaml` w obu miejscach
(`InstallerSha256` i `FileSha256`).

---

## Krok 4A — szybka ścieżka: `winget create new`

Winget sam pobierze binarkę i wygeneruje manifesty:

```powershell
winget create new --url "https://github.com/TWOJ-USER/tznsecvirus/releases/download/v2.0.0/tznsecvirus.exe" `
  --version 2.0.0 --name tznsec.TZNSECVIRUS --publisher tznsec `
  --installer-type portable --architecture x64 `
  --output-directory .\winget\auto
```

---

## Krok 4B — ręcznie (pliki już masz)

Edytuj w `winget\`:
1. `TZNSECVIRUS.yaml` — zamień `TWOJ-USER` na swój nick
2. `TZNSECVIRUS.installer.yaml` — popraw URL i SHA256
3. `TZNSECVIRUS.locale.pl-PL.yaml` — jw.

Potem zwaliduj:

```powershell
winget validate --manifest .\winget\TZNSECVIRUS.yaml --manifest-version 1.6.0
```

---

## Krok 5 — wyślij do winget-pkgs

1. Zrób **fork**: https://github.com/microsoft/winget-pkgs
2. W swoim forku utwórz katalog:
   `manifests/t/tznsec/TZNSECVIRUS/2.0.0/`
3. Skopiuj tam 3 pliki `.yaml`
4. Wyślij **Pull Request** do `microsoft/winget-pkgs`
5. Bot automatycznie zwaliduje; po review pakiet pojawi się w winget.

Alternatywa bez GitHuba: formularz na https://winget.pkgmgr.dev/packages/submit

---

## Sprawdzenie po publikacji

```powershell
winget search tznsecvirus
winget show tznsec.TZNSECVIRUS
winget install tznsec.TZNSECVIRUS
```

Po instalacji polecenie `tznsecvirus` jest dostępne w PATH.

---

## Wskazówki

- **Nazwa pakietu** to `Publisher.PackageName`, np. `tznsec.TZNSECVIRUS`.
  Ta sama nazwa już istnieje? Wymyśl inną.
- **Kolejne wersje**: nowy tag `v2.0.1`, nowy katalog `2.0.1/`, zaktualizowany SHA256.
- **Autor praw** w metadanych jest obowiązkowy — wpisz np. `tznsec`.
- Bez licencji w `License:` PR nie przejdzie walidacji.
- Manifest weryfikują boty winget pobierający binarkę z twojego URL — **plik musi być dostępny publicznie**, najlepiej przez cały czas.