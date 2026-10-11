# Dodanie TZNSECVIRUS do winget

Pakiet jest gotowy do publikacji pod komendą:

```powershell
winget install tznsecvirus
```

Identyfikator pakietu to `tznsecvirus.TZNSECVIRUS` — publisher musi być prefiksem,
żeby skrócona nazwa działała.

---

## Krok 1 — wypchnij źródła na GitHub

```bash
cd "C:\Users\wojte\Documents\moje projekty\tnssecvirus"
git add .
git commit -m "v2.0.0"
git push
```

> `tznsecvirus.exe` i `target/` są w `.gitignore` — binarka idzie jako *asset* release,
> nie do repo.

---

## Krok 2 — utwórz Release z binarką (OBOWIĄZKOWE)

Bez tego kroku walidacja winget-pkgs nie przejdzie — bot musi pobrać `InstallerUrl`.

### Sposób A — GUI (30 sekund, bez tokenu)

GitHub → **Releases → Draft a new release**

- Tag: `v2.0.0`
- Tytuł: `TZNSECVIRUS 2.0.0`
- **Attach files**: przeciągnij `tznsecvirus.exe` (przemianuj przy wgrywaniu na
  `TZNSECVIRUS.exe` — takiego pliku oczekuje manifest)
- **Publish release**

### Sposób B — skryptem (wymaga tokenu)

```powershell
$env:GITHUB_TOKEN = "ghp_..."   # scopes: contents:write
.\tools\make_release.ps1
```

Skrypt utworzy release, wrzuci asset **i sam zaktualizuje SHA256** w manifeście.

---

## Krok 3 — wypchnij zmiany manifestu

```bash
git add winget tools
git commit -m "winget: manifest v2.0.0 + skrypt release"
git push
```

---

## Krok 4 — wyślij do winget-pkgs

1. **Fork**: https://github.com/microsoft/winget-pkgs
2. W swoim forku utwórz katalog:
   `manifests/t/tznsecvirus/TZNSECVIRUS/2.0.0/`
3. Skopiuj tam 3 pliki z katalogu `winget/`:
   - `TZNSECVIRUS.yaml`
   - `TZNSECVIRUS.installer.yaml`
   - `TZNSECVIRUS.locale.pl-PL.yaml`
4. **Pull Request** do `microsoft/winget-pkgs`

Alternatywa bez forka: formularz na https://winget.pkgmgr.dev/packages/submit

---

## Krok 5 — instalacja

Po merge (zwykle 1–7 dni):

```powershell
winget install tznsecvirus
```

Alias `tznsecvirus` trafia do PATH, więc potem:

```powershell
tznsecvirus run
```

Odinstaluowanie: `winget uninstall tznsecvirus`

---

## Uwagi

- **Kolejne wersje**: nowy tag `v2.0.1`, katalog `2.0.1/`, zaktualizowany SHA256.
- **Bez nowego buildu nie ruszaj hasha.** Każdy nowy `tznsecvirus.exe` ma inne SHA256 —
  błędny hash = instalacja się nie uda.
- `winget validate` w CLI nie obsługuje manifestów multi-file (błąd „does not support
  multi file manifest format”) — to ograniczenie narzędzia. Walidację robi CI winget-pkgs.
- Autor praw w metadanych jest obowiązkowy, `License: MIT` też.
- Release musi być **publiczny** — boty nie mają dostępu do prywatnych repo.