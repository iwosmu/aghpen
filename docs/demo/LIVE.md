# Pokaz na żywo: ściąga

Jedna maszyna jury (docker-in-docker) z Czujką i szablonem organizatorów w środku. Na zewnątrz wychodzi tylko UI: http://127.0.0.1:18730.
Czujka skanuje tylko wnętrze maszyny (blokada operatora: 2 sieci), tylko GET/HEAD.

| Kiedy | Polecenie | Czas |
| --- | --- | --- |
| dzień wcześniej, z internetem | `docs/demo/live/live.sh prewarm` | kilka minut |
| na sali | `docs/demo/live/live.sh start` | ok. 4 min; hasło admina pojawia się raz |
| hasło jeszcze raz | `docs/demo/live/live.sh pass` | |
| po pokazie | `docs/demo/live/live.sh stop` | |

Każde `live.sh N` samo czyści Czujkę i przygotowuje przypadek N. `live.sh reset` czyści bez przygotowania.
Login: `admin@czujka.local`. Czasy zmierzono na MacBooku pod obciążeniem. Dowody: `docs/demo/live/proof/`.

## 1. Usługa znika i wraca (skrypt organizatorów, profil domyślny)

- Przygotuj: `live.sh 1`, gotowe po ok. 2 min 10 s.
- Na żywo: `live.sh 1 change`.
- Klik: Przebiegi skanów → Uruchom skan → „Ten komputer: Domyślny…” → Uruchom → po ok. 100 s Zmiany.
- UI: „Usługa 172.18.0.1:8787 zniknęła (nginx 1.31.9)”.
- Dalej: `live.sh 1 up`, ten sam skan (ok. 110 s). UI: „Usługa 172.18.0.1:8787 wróciła po 1 min (nie było jej w 1 skanie)”.
- Powiedz: „Czujka porównuje każdy skan z poprzednim i sama mówi, co zniknęło, a co wróciło.”
- Uwaga: pełny zakres portów to ok. 100 s na skan. Uruchom skan i mów w trakcie.

## 2. Host przestaje odpowiadać

- Przygotuj: `live.sh 2`, gotowe po 40 s.
- Na żywo: `live.sh 2 stop`.
- Klik: Przebiegi skanów → Uruchom skan → „Serwer w pracowni: port 80” → Uruchom → po 7 s Zmiany.
- UI od razu: „Host 172.31.250.10 nie odpowiada (niepotwierdzone)”.
- UI ok. 1,5 min później, bez kliknięcia: „Host 172.31.250.10 zgłoszony jako nieaktywny”, „Usługa 172.31.250.10:80 zniknęła (nginx 1.31.9): host zgłoszony jako nieaktywny”.
- Powiedz: „Jeden brak odpowiedzi to jeszcze nie awaria. Czujka sama sprawdza ponownie i dopiero wtedy potwierdza.”
- Powrót hosta: `live.sh 2 start`.

## 3. Usługa odpowiada wolniej

- Przygotuj: `live.sh 3`, gotowe po 75 s.
- Na żywo: `live.sh 3 slow` (Toxiproxy +500 ms).
- Klik: Przebiegi skanów → Uruchom skan → „WordPress za proxy” → Uruchom → po ok. 20 s Zmiany.
- UI: „Usługa 172.18.0.1:8085 odpowiada wolniej: 585 ms (zwykle 39 ms)”.
- Dalej, jeśli jest czas: `live.sh 3 fast`, ten sam skan. UI: „znów odpowiada w zwykłym czasie: 44 ms (zwykle 39 ms)”.
- Powiedz: „Czujka zna zwykły czas odpowiedzi każdej usługi, więc widzi spowolnienie, zanim usługa padnie.”

## 4. Nowa ekspozycja, reguły i DefectDojo

- Przygotuj: `live.sh 4`, gotowe po 60 s.
- Na żywo: `live.sh 4 expose` (stos podatny obok czystego).
- Klik: Przebiegi skanów → Uruchom skan → „Porty szablonu” → Uruchom → po ok. 90 s Zmiany → Reguły ekspozycji.
- UI: 19 × „Nowa usługa…”, np. „Nowa usługa 172.18.0.1:8088 (Apache httpd 2.4.10)”. Reguły: „Niedokończona instalacja aplikacji” 3, „API sterujące bez uwierzytelniania” 3.
- DefectDojo: w drugim terminalu, w trakcie skanu: `live.sh 4 dojo` (ok. 65 s).
- Klik: Znaleziska → Wszystkie do DefectDojo → Eksportuj.
- UI: „Eksport zakończony.” Nowe w DefectDojo: 75, nieudane: 0.
- Powiedz: „Nowa usługa od razu przechodzi przez reguły. To, czego nie powinno być w sieci, staje się znaleziskiem i jednym kliknięciem trafia do DefectDojo.”
- Uwaga: link „Otwórz test” działa tylko w maszynie. Port 2375 (Docker Engine API) to demon samej maszyny jury.

## 5. Role

- Przygotuj: `live.sh 5`, gotowe po 45 s. Terminal pokazuje raz 4 konta z hasłami: viewer@, analyst@, editor@czujka.local, admin2@czujka.local.
- Klik: Wyloguj → viewer@ → Przebiegi skanów. UI: „Tylko odczyt. Twoja rola nie pozwala na zmiany na tej stronie.”
- Klik: analyst@ → jest „Uruchom skan” i „Stop awaryjny” → Import / eksport. UI: „Twoja rola nie może importować wyników”.
- Klik: editor@ → Import / eksport działa, sygnatury też → admin2@ → Administracja → Użytkownicy.
- Powiedz: „Cztery role z zadania. Przycisku, którego rola nie może użyć, nie widać albo jest wyłączony.”

## 6. Sygnatura z prawdziwej usługi

- Przygotuj: `live.sh 6`, gotowe po ok. 2 min 10 s.
- Klik: Usługi → 172.18.0.1:8888 (httpbin) → Zaproponuj sygnaturę → Otwórz w edytorze → Uruchom test → Zapisz sygnaturę.
- UI: „Sygnatura „gunicorn” pasuje do przykładu i do żadnej innej z 6 zapisanych usług.” → „Sygnatura jest poprawna i bezpieczna” → „Dopasowano 1 zapisaną usługę, wysłano 0 pakietów.”
- Przed zapisem możesz zmienić `name:` w edytorze, np. na „httpbin w pracowni”.
- Powiedz: „Sygnaturę robimy z prawdziwej usługi w minutę. Test na zapisanych wynikach nie wysyła ani jednego pakietu.”

## 7. Import i edycja, która przeżywa skan

- Przygotuj: `live.sh 7`, gotowe po 90 s. Pliki: `docs/demo/live/samples/`.
- Klik: Import / eksport → Importuj wyniki: `wyniki-nmap.xml` (4 hosty, 12 usług) → Importuj znaleziska: `znaleziska-dojo-generic.json` (2 nowe).
- Klik: Znaleziska → „Test ręczny: brak nagłówka Content-Security-Policy…” → waga niska, notatka, przypisanie → Przebiegi skanów → Uruchom skan „Quickstart”.
- UI po skanie: znalezisko nadal ma wagę niską i notatkę „Obniżone: serwer tylko w sieci laboratorium.”
- Powiedz: „Wyniki z nmapa i znaleziska z pentestu trafiają do tej samej bazy, a decyzja analityka przeżywa kolejny skan.”
