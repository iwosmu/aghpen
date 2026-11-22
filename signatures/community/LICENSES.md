# Licencje zaimportowanych sygnatur

Pliki `nuclei-*.yaml` w tym katalogu (i w `opt-in/`) powstały z szablonów projektu
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates),
wersja z commita `1ad258956016afba455d4284539812eb24be690a` (21.11.2026), na licencji MIT.
Licencję sprawdzono w pliku `LICENSE.md` tego commita. Każda sygnatura ma pole `source`:
repozytorium, commit, plik źródłowy, id szablonu i licencję.

Pliki odtwarza polecenie (bez dostępu do sieci w czasie budowania; wynik jest w repozytorium):

```
git clone https://github.com/projectdiscovery/nuclei-templates /tmp/nt
git -C /tmp/nt checkout 1ad258956016afba455d4284539812eb24be690a
make sigimport NUCLEI_TEMPLATES=/tmp/nt
```

Nie importujemy innych korpusów. rapid7/recog (BSD-2) nie jest jeszcze podłączony. Korpusów
Wappalyzera na licencji GPL nie używamy. `http/technologies/tech-detect.yaml` to część
nuclei-templates i ma licencję MIT całego repozytorium.

## Tekst licencji MIT (nuclei-templates)

```
MIT License

Copyright (c) 2025 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
