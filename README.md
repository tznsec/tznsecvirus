# TZNSECVIRUS

Aplikacja desktopowa w **Rust + WebView** do pełnego skanowania bezpieczeństwa komputera z analizą AI.

## Uruchomienie

```bash
tznsecvirus            # GUI
tznsecvirus run        # to samo (alias po instalacji przez winget)
```

Po instalacji z winget polecenie `tznsecvirus` jest dostępne globalnie
(`PortableCommandAlias`), a `tznsecvirus run` uruchamia interfejs graficzny.

### Tryby tekstowe

```bash
tznsecvirus --selftest              # pełny pipeline w konsoli
tznsecvirus --selftest --no-ai      # bez zapytań do AI
tznsecvirus --models                 # lista dostawców AI
tznsecvirus --help
```

## Co robi

Jeden przycisk **SKANUJ** uruchamia kompletny pipeline:

1. **Kontrole systemu** — Defender, firewall, UAC, Secure Boot, BitLocker, RDP, SMBv1,
   otwarte porty, autostart, zadania, plik hosts
2. **VPN** — adaptery, profile (WireGuard/OpenVPN/Tailscale), stan tunelu, publiczne IP
3. **Skan katalogów** — najczęściej infekowane miejsca + heurystyka
4. **Panel AI** — kilka modeli równolegle, wspólny werdykt i lista „co należy sprawdzić"

Dodatkowo:

- **Skaner dowolnej ścieżki** (z `%TEMP%`, `~`, zmiennymi środowiskowymi) + przycisk
  **SKANUJ + AI**, gdzie modele oceniają czy plik jest wirusem
- **Chat z AI** znający stan Twojego komputera
- **Prywatność** — przy każdym uruchomieniu usuwane są poprzednie raporty

## Dostawcy AI

Wybierasz w **USTAWIENIA**:

| Dostawca | Klucz | Uwagi |
|---|---|---|
| **Darmowe API** | opcjonalny | `openai`, `openai-fast`, `llama`, `qwen-coder` — działa **bez klucza** |
| **xkiro.com** | wbudowany | 13 modeli `:free` |
| **Lokalne (Ollama)** | nie | wykrywane automatycznie, działa offline |

- **Wiele kluczy na dostawcę** — klikasz zapisany klucz, żeby go użyć
- **Automatyczny fallback** — gdy model odmówi (limit, pusta odpowiedź, błąd sieci),
  aplikacja próbuje kolejnych kluczy i modeli, i informuje który ostatecznie odpowiedział

## Heurystyka skanera

- podwójne rozszerzenia (`faktura.pdf.exe`)
- podejrzane nazwy dla plików wykonywalnych/skryptów
- pliki wykonywalne w katalogu tymczasowym
- skrypty w Autostarcie
- sygnatury w skryptach (`Invoke-WebRequest`, `-EncodedCommand`, `certutil`, `vssadmin delete shadows`…)
- wysoka entropia (packing/szyfrowanie)
- ukryte pliki wykonywalne

## Struktura

| Plik | Rola |
|---|---|
| `src/main.rs` | okno (tao + wry), IPC, pipeline, komendy, prywatność |
| `src/security.rs` | 14 kontroli Windows przez PowerShell z wagami ryzyka |
| `src/vpn.rs` | detekcja adapterów/profili, start/stop tuneli, weryfikacja IP |
| `src/scanner.rs` | chodzenie po katalogach, entropia, sygnatury, ocena |
| `src/ai.rs` | dostawcy, modele, fallback kluczy/modeli, konsensus, czat |
| `src/util.rs` | uruchamianie procesów z limitem czasu |
| `ui/index.html` | splash, menu, widoki, animacje |
| `assets/tznsecvirus.ico` | ikona aplikacji (osadzana w exe) |
| `tools/make_icon.ps1` | generator ikony |
| `winget/` | manifesty do publikacji w winget |

## Budowanie

```bash
cargo build --release
```

Rust 1.85+ (edition 2021). Zależności: `tao`, `wry`, `ureq`, `serde`, `serde_json`,
`walkdir`, `dirs`, `winres`. WebView2 (Edge) jest wbudowany w Windows 10/11.

## Wgryzanie do winget

Instrukcja w [`winget/README.md`](winget/README.md).