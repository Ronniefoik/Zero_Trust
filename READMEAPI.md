# Lokalny API dla Zero Trust

Mały, działający komponent po stronie sieci lokalnej. API uruchamia się tylko na `127.0.0.1`, wymaga HTTPS, sprawdza krótką sesję i uprawnienia do każdej operacji oraz zapisuje zdarzenia audytowe w formacie JSON Lines.

## Co demonstruje

- **Dwie role:** `audytor` odczytuje telemetrię i alerty; `operator` może dodatkowo potwierdzać alerty.
- **Least privilege:** uprawnienia wynikają z mapy ról w API. Poprawnie zalogowany audytor otrzyma `403` przy próbie potwierdzenia alertu.
- **Segmentację:** domyślny nasłuch to loopback, a lista CIDR dopuszcza wyłącznie `127.0.0.1` i `::1`. API nie otwiera portu na interfejsie publicznym.
- **Szyfrowany kanał:** TLS 1.2 lub nowszy. Tryb integracyjny z bramą wymaga dodatkowo mTLS.
- **Obsługę sekretów:** klucz sesji powstaje losowo przy starcie skryptu demonstracyjnego; hasła są pytane interaktywnie i zapisywane wyłącznie jako skróty scrypt. Klucz i dane lokalne są wykluczone z repozytorium.
- **Kontrolę sesji:** token HMAC ma 10 minut ważności, a wylogowanie unieważnia go natychmiast w działającym procesie.
- **Logi i alert:** zdarzenia trafiają jako JSON do `logs/audit.jsonl` i na standardowe wyjście. Trzy błędne logowania z jednego adresu w ciągu minuty tworzą zdarzenie `login_anomaly`; pięć prób blokuje kolejne logowania na czas okna.

## Uruchomienie demonstracji w Windows

Wymagane: Python 3.10+. Projekt nie wymaga dodatkowych pakietów Pythona. Do automatycznego utworzenia certyfikatu potrzebny jest PowerShell 7+; alternatywnie można przygotować certyfikat przez OpenSSL.

1. Otwórz PowerShell w tym katalogu.
2. Uruchom `.\start_demo.ps1`. Przy pierwszym uruchomieniu skrypt tworzy lokalny certyfikat i poprosi o ustawienie dwóch haseł.
3. Pozostaw to okno z API uruchomionym. W drugim oknie PowerShell, w tym samym katalogu, wykonaj scenariusze z poniższej tabeli.

| Polecenie | Konto | Oczekiwany wynik |
| --- | --- | --- |
| `python demo_client.py read` | audytor lub operator | `200`, telemetria lokalna |
| `python demo_client.py deny-ack` | audytor | `403`, `insufficient_scope` |
| `python demo_client.py ack` | operator | `200`, alert `ALT-001` potwierdzony |
| `python demo_client.py logout` | dowolne | `200`, sesja zamknięta |

Jeśli masz OpenSSL zamiast PowerShell 7, przygotuj certyfikat przed uruchomieniem skryptu:

```powershell
New-Item -ItemType Directory -Force tls | Out-Null
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout tls/dev-key.pem -out tls/dev-cert.pem -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Klient ufa wyłącznie certyfikatowi utworzonemu dla lokalnego demo i nie wyświetla tokenu. Nie wpisuj prawdziwych haseł firmowych.

## Sprawdzenia automatyczne

Uruchom w katalogu projektu:

```powershell
python -m unittest -v
```

Zestaw sprawdza skróty haseł, podpis/wygaśnięcie/unieważnianie sesji, różnicę uprawnień ról, listę sieci oraz alert po serii błędnych logowań.

## Integracja z bramą OIDC i tunelem

Samodzielne logowanie lokalne służy do demonstracji. W wariancie hybrydowym brama OIDC powinna usuwać nagłówki tożsamości dostarczone przez klienta, po uwierzytelnieniu ustawiać `X-Authenticated-User` i `X-Authenticated-Role` oraz łączyć się z API przez prywatny segment/tunel. Uruchomienie API w tym trybie:

```powershell
$env:AUTH_MODE = 'trusted_gateway'
$env:API_BIND_HOST = '10.42.0.2'                 # adres interfejsu prywatnego/tunelu
$env:API_ALLOWED_NETWORKS = '10.42.0.1/32'       # adres bramy, bez sieci użytkowników
$env:TRUSTED_GATEWAY_NETWORKS = '10.42.0.1/32'
$env:TLS_CLIENT_CA = 'C:\certyfikaty\gateway-ca.pem'
$env:TLS_CERT_FILE = 'C:\certyfikaty\api-cert.pem'
$env:TLS_KEY_FILE = 'C:\sekrety\api-key.pem'
python local_api.py serve
```

W tym trybie Python wymaga certyfikatu klienta bramy (mTLS); endpoint lokalnego logowania jest wyłączony. Certyfikat serwera musi mieć adres IP z `API_BIND_HOST` w SAN. Brama powinna ograniczyć ruch wychodzący do `10.42.0.2:8443`, nie publikować lokalnego API do Internetu i kierować zdarzenia z `logs/audit.jsonl`/stdout do centralnego kolektora. W środowisku produkcyjnym klucze, CA, konta oraz konfigurację sieci należy dostarczyć przez firmowy menedżer sekretów i PKI.

Alert `login_anomaly` jest sygnałem z korelacji zdarzeń regułą progową; kolektor może łączyć go z logami bramy/OIDC i zasilać projektowy detektor ML. Certyfikat samopodpisany z `generate_dev_certificate.ps1` jest przeznaczony tylko do loopback demo.
