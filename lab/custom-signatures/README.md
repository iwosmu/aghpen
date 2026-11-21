# Własne sygnatury laboratorium

`infokiosk.yaml` to przypadek testowy wymagania „możliwość tworzenia własnych sygnatur detekcyjnych”.

- Cel: hosty `kiosk-1` (`10.66.60.12`) i `kiosk-2` (`10.66.200.200`). Oba udają wymyślony produkt „InfoKiosk”.
- Wbudowana biblioteka sygnatur nie zna tego produktu. Po dodaniu sygnatury oba hosty muszą dostać dopasowanie `lab-infokiosk` z wersją ze stopki.
- Sygnatura używa sześciu rodzajów reguł z treści zadania: nagłówek `X-InfoKiosk-Node`, ciasteczko `infokiosk_sid`, fragment HTML `<!-- InfoKiosk build`, hash favicony, ścieżka `/kiosk/status`, wersja w stopce `InfoKiosk v4.2.1`.
- W stanie `t1` `kiosk-1` ma wersję `4.3.0`. Skan po zmianie stanu musi pokazać zmianę wersji.
- Hash favicony pochodzi z generatora ikon laboratorium (`lab/labcfg/favicon.go`); ta sama wartość jest w `lab/ground-truth/t0.json`.

Sprawdzenie ręczne ze skrzynki skanera:

```sh
lab/lab.sh sh curl -si http://10.66.60.12/ | head -20
lab/lab.sh sh curl -s http://10.66.60.12/kiosk/status
```

Ocena: `e2e/score` liczy wiersz „custom signatures” z pola `signatures` w ground truth.
