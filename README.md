# Zero Trust dla hybrydowej aplikacji biznesowej

Materiały na przegląd architektury i ryzyka: [M2 — architektura, przepływ danych, zagrożenia i backlog](M2-architektura-i-ryzyka.md).

## Cel i zakres

Celem projektu jest zapewnienie bezpiecznego dostępu użytkowników do usługi rozproszonej między siecią lokalną a chmurą.

Architektura referencyjna: **klient → brama tożsamości OIDC → reverse proxy → aplikacja → API lokalne → telemetria**. Zdarzenia z komponentów trafiają do centralnego systemu logowania i analizy.

Minimalny działający prototyp (MVP) obejmuje dwie role użytkowników, uwierzytelnienie, autoryzację API, bezpieczne kanały, centralne logowanie oraz demonstrację odmowy dostępu. Wymagania bezpieczeństwa obejmują zasadę najmniejszych uprawnień, segmentację, obsługę sekretów, kontrolę sesji i logów oraz MFA, jeśli pozwala na to środowisko. Analiza ML ma wykrywać nietypowe próby logowania lub korelować sekwencje zdarzeń.

Kryteria odbioru: działający system, scenariusze pozytywne i negatywne dostępu, alert logowania oraz dowody testów.

## Podział odpowiedzialności

| Osoba | Rola | Element architektury | Główne kryterium odbioru |
| --- | --- | --- | --- |
| 1 | Tożsamość i brama dostępu (IAM / proxy) | Brama OIDC → reverse proxy | Działające logowanie OIDC dla dwóch ról, wariant MFA jeśli możliwy, blokada nieautoryzowanego ruchu |
| 2 | Klient i aplikacja biznesowa | Klient → aplikacja chmurowa | Interfejs z logowaniem, przekazywanie kontekstu i ekran odmowy dostępu |
| 3 | API lokalne i sieć hybrydowa | Bezpieczny kanał → API lokalne | Autoryzacja najmniejszych uprawnień, segmentacja i szyfrowany kanał |
| 4 | Telemetria, logowanie i AI / ML | Centralne logowanie → moduł ML | Zbiorczy strumień logów oraz działający alert wykrytej anomalii |
| 5 | Integracja, DevSecOps i testy | Środowisko całościowe i walidacja | Powtarzalne uruchomienie, testy dostępu i dowody odbioru |

## Osoba 1: tożsamość, MFA i reverse proxy

- Skonfigurować dostawcę OIDC, np. Keycloak, Authentik lub Entra ID; utworzyć dwie role i przypisać konta testowe.
- Ustawić krótki czas życia tokenów JWT oraz politykę wygasania i unieważniania sesji. Jeśli środowisko pozwala, włączyć MFA, np. TOTP.
- Skonfigurować reverse proxy, np. Nginx, Traefik lub Envoy z OAuth2-Proxy, wymuszające HTTPS/TLS i odrzucające nieautoryzowany ruch przed aplikacją.
- Bezpiecznie przechowywać sekrety klienta OIDC i certyfikaty TLS, np. w Vault, Docker Secrets lub zarządzanych sekretach chmurowych; nie umieszczać ich w repozytorium.

## Osoba 2: klient i aplikacja biznesowa

- Utworzyć lekki interfejs webowy realizujący logowanie OIDC przez Authorization Code Flow z PKCE i wyświetlający zasoby zależnie od roli.
- Przekazywać kontekst tożsamości i odpowiedni token JWT do API lokalnego oraz dodawać identyfikator korelacji `request_id` do każdego żądania.
- Obsłużyć odpowiedzi HTTP 401 i 403 oraz wyraźnie komunikować odmowę wykonania akcji zastrzeżonej dla wyższej roli.
- Zapewnić higienę sesji, stosując bezpieczne ciasteczka `HttpOnly`, `Secure` i `SameSite` lub wzorzec BFF; nie przechowywać wrażliwych tokenów w `localStorage`.

## Osoba 3: API lokalne, segmentacja i kanał hybrydowy

- Zaimplementować endpoint odczytu dla roli podstawowej oraz operację administracyjną dla roli uprzywilejowanej. API niezależnie weryfikuje podpis JWT, ważność, wymagane pola tokena i uprawnienia; nie ufa ślepo proxy.
- Zestawić szyfrowane połączenie między aplikacją a siecią lokalną, np. WireGuard, Tailscale, Cloudflare Tunnel lub mTLS z rotowanymi certyfikatami.
- Odizolować API w wydzielonej sieci, np. VLAN lub odseparowanej sieci kontenerowej z regułami firewalla, dopuszczając ruch wyłącznie od wskazanej aplikacji lub proxy na wskazanym porcie.
- Bezpiecznie obsługiwać sekrety lokalne i emitować ustrukturyzowane logi JSON dla każdego zezwolenia i odmowy dostępu.

## Osoba 4: telemetria, logowanie i AI / ML

- Wdrożyć agregator, np. Grafana Loki z Promtail, ELK/OpenSearch lub lekki kolektor z bazą, zbierający ujednolicone zdarzenia z IdP, proxy, aplikacji i API.
- Zapewnić integralność i higienę logów: spójne znaczniki czasu i pola użytkownika, maskowanie danych wrażliwych oraz brak haseł i pełnych tokenów JWT.
- Zbudować skrypt lub usługę ML, np. Python i scikit-learn z Isolation Forest albo detektorem sekwencji. Analizować przykładowo nietypowe godziny logowania, serie odpowiedzi 401/403, zmianę IP lub User-Agent i nietypową kolejność wywołań API.
- Generować czytelny alert po przekroczeniu progu anomalii, np. jako wpis w dashboardzie, webhook lub e-mail.

## Osoba 5: integracja, DevSecOps i dowody odbioru

- Przygotować wspólne repozytorium, powtarzalne uruchomienie, np. Docker Compose lub skrypty IaC, konfigurację zmiennych środowiskowych oraz dokumentację architektury.
- Przygotować powtarzalne testy, np. pytest, Postman/Newman lub skrypty curl, obejmujące:
  - poprawne logowanie i dostęp dla obu ról;
  - odmowę dostępu roli podstawowej do zasobu uprzywilejowanego (403);
  - odrzucenie żądania bez tokena oraz z tokenem wygasłym lub zmodyfikowanym (401);
  - próbę bezpośredniego połączenia z API lokalnym z pominięciem proxy lub tunelu jako dowód segmentacji.
- Przygotować skrypt generujący nietypowe logowania i wywołujący alert modułu osoby 4. Zebrać zrzuty ekranu, logi testów i raport odbiorowy do prezentacji końcowej.

## Ustalenia zespołu przed rozpoczęciem prac

W pierwszej godzinie zespół powinien wspólnie uzgodnić i zapisać trzy kontrakty, aby umożliwić równoległą pracę:

1. **Token JWT i role:** dokładne nazwy dwóch ról, np. `user` i `admin`, oraz pole (claim), w którym IdP je przekazuje. Kontrakt jest potrzebny osobom 1, 2 i 3.
2. **API lokalne:** lista dwóch lub trzech endpointów, np. `GET /api/data` dla obu ról i `POST /api/admin/action` tylko dla roli uprzywilejowanej. Kontrakt jest potrzebny osobom 2, 3 i 5.
3. **Schemat logów JSON:** wspólny format zdarzeń, np. `timestamp`, `service`, `user_id`, `role`, `source_ip`, `endpoint`, `status_code` i `request_id`. Dzięki temu osoba 4 może budować analizę na danych testowych przed pełną integracją.

Podane nazwy ról, endpointy i technologie są przykładami do wspólnego uzgodnienia, a nie gotowymi decyzjami implementacyjnymi.
