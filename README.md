# ⚡ EnergyGame

Budovatelská strategie o stavbě energetické sítě. Běží čistě v prohlížeči,
2D izometrie vykreslovaná přes **WebGL2** s instancovaným renderováním
(terén, budovy i animovaná vedení se kreslí na GPU).

**[▶ Hrát](https://mirapavlicek.github.io/energyGame/)** (po zapnutí GitHub Pages)

## Princip hry

- Mapa je **náhodně generovaná** (fraktální šum): jezera, louky, lesy, kopce,
  hory a **řeky** s reálným průtokem, které pramení v horách a stékají po spádu.
- **Vodní elektrárnu** postavíš **jen na řece** – výkon roste s průtokem.
- **Přehrada** (také jen na řece) zaplaví údolí proti proudu, dá velký stabilní
  výkon a **posílí průtok** po proudu – vodní elektrárny níže pak vyrábí víc.
- Dále: uhelná elektrárna (stabilní, drahý provoz), solární park (jen ve dne),
  větrné turbíny (kolísají s větrem, na kopcích víc).
- Města napájíš přes **rozvodny** (dosah 6 dlaždic) a vše spojuješ **vedením**.
- **Toky v síti** se počítají zjednodušeným DC power-flow modelem – energie si
  sama najde cesty, delší vedení „klade větší odpor". Každé vedení má kapacitu
  120 MW; přetížené trasy červeně blikají a chtějí paralelní posilu.
- Napájená města rostou a platí za energii; při výpadcích se lidé stěhují pryč.
- Den/noc cyklus ovlivňuje poptávku i výrobu (slunce, vítr).

## Ovládání

| Vstup | Akce |
| --- | --- |
| tažení myší | posun kamery |
| kolečko | zoom ke kurzoru |
| `1`–`6` | stavby (vodní, přehrada, uhelná, solár, vítr, rozvodna) |
| `7` | vedení – klikej z budovy na budovu (řetězí se) |
| `Q` / `Esc` | režim prohlížení |
| `X` | bourání (budovy i vedení) |
| mezerník | pauza |
| `+` / `−` | rychlost hry |
| klik na minimapu | přesun kamery |

## Spuštění lokálně

Žádný build, žádné závislosti:

```bash
python3 -m http.server 8000
# → http://localhost:8000
```

Konkrétní mapu lze sdílet přes URL: `index.html?seed=123456`.

## Technika

- **WebGL2** – celá scéna instancovaně: statický buffer terénu (25 600 dlaždic
  nahraných jednou), dynamický buffer budov/kurzorů, vedení jako instancované
  segmenty s animovanými „pakety" energie ve fragment shaderu.
- **Sprite atlas** se generuje procedurálně do canvasu při startu – repozitář
  neobsahuje žádné binární assety.
- Deterministický RNG (mulberry32) + hodnotový fBm šum pro terén.
- Čistý vanilla JS (ES2020), bez frameworků a bez build kroku.

## Struktura

```
index.html      – vstupní stránka + UI
style.css       – vzhled HUD
js/rng.js       – seedovaný RNG a šum
js/map.js       – generátor mapy (terén, řeky, města)
js/atlas.js     – procedurální sprite atlas
js/renderer.js  – WebGL2 izometrický renderer
js/sim.js       – simulace sítě (DC power flow, ekonomika, města)
js/game.js      – herní smyčka, vstup, HUD, minimapa
```
