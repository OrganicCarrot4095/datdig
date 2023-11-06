#  Kompendium TDT4160 - Datamaskinar og digitalteknikk
#### Dette er eit sjølvskriven kompendium basert på "Structured Computer Organization" 6th edt. av Tanenbaum og Austin.

<a name="del1"></a>
## 1. Innleiing til Datamaskinar og Digital Teknologi
### Historia om datamaskinar
### Grunnleggjande datamaskinterminologi
### Oversikt over struktur
1. [*Innleiing til Datamaskinar og Digital Teknologi*](#del1)
2. [*Grunnleggjande om digital logikk*](#del2)
3. [*Arkitekur og organisasjon i ei datamaskin*](#del3)
4. [*Mikroarkitektur*](#del4)
5. [*Minnehandtering og lager*](#del5)
6. [*Inndata/Utgongssystem*](#del6)
7. [*Parallelle datamaskinar*](#del7)
8. [*Operativsystem og maskinvaregrensesnitt*](#del8)
9. [*Datamaskinnettverk*](#del9)
10. [*Fremtidige trender*](#del10)

Datamaskinar har gjennomgått stor utvikling gjennom tidene. Frå dei første mekaniske reknemaskinane, til dei avanserte mikroprosessorane som ligg i kjernen til dei fleste teknologiane vi har i dag. Innovasjonar i mikroarkitekturen - den fysiske implementasjonen av settet med instruksjonar maskina kan utføre, ofte referert til som maskinas "instruksjonssettakritektur", har vore ein stor pådrivar for denne utviklinga. Her er mikroarkitekturen tilpassa for å effektivt utføre instruksjonssettakritekturen, og omvendt. Saman dannar dei fundamentet for den digitale logikken som er essensiell for funksjonaliteta til ei datamaskin.

<a name="del2"></a>
## 2. Grunnleggjande om digital logikk
### Digital logikk og viktigheten av denne
Digital logikk er studiet av elektroniske system som nyttar binære tal for å representere og manipulere informasjon. Dette konseptet er grunnmuren for alle datamaskinar og mange andre typar elektroniske einingar. Ved å bruke binærsystemet, klarar digital logikk å utføre komplekse berekningar og datahandtering gjennom relativt enkle operasjonar. Desse operasjonane blir utført ved hjelp av logiske portar, slik som AND, OR og NOT. Dei ulike portane har ulike eigenskapar som vi skal sjå på seinare. Ved å kombinere desse grunnleggjande operasjonane i meir kompliserte kretsar, kan digital logikk utføre alle typar datamaskininstruksjonar. Dette gjer det mogleg for elektroniske einingar å køyre program, prosessere data og simulere menneskeleg tenkning i form av kunstik intelligens.

### Binære system og datarepresentasjon

Det binære tallsystemet dannar grunnlaget for all digital logikk og databehandling. Der det desimale systemet brukar ti siffer (0-9), opererer det binære systemet kun med to, 0 og 1. Desse siffera svarar til dei to moglege tilstandane i digitale kretsar, herfrå referert til som av(0) og på(1). Dette samsvarar godt med den binære naturen til elektroniske komponentar som kan vere i nettopp to tilstandar - at elektrisk strøm flyt gjennom (på/1), eller ikkje (av/0).

Innan datamaskingar og elektroniske einingar blir all informasjon koda binært. Til dømes bruker ASCII sekvensar beståande av 0 og 1 for å representere bokstavar og teikn. "A" kan altså skrivast 01000001. På same måte kan bilete og lyd også omformast til binært form ved hjelp av ulike kodingssystem. Bilete blir koda som ei samling med pikslar der kvar piksel har ein binær verdi som representerer farge og intensitet. Lydfiler blir tilsvarande representert med binær data som skildrar amplituden til bølgja over tid. Desse binære representasjonane tillet lagring, manipulering og overføriong av komplekse data i elektroniske system, og det gjer det mogleg for datamaskinar å prosessere og "forstå" eit mangfold av informasjonstypar gjennom deira grunnleggjande digitale logikk.


### Grunnleggjande digitale komponentar
Grunnleggjande digitale komponentar er dei byggjesteinane som digitale kretsar er konstruert frå. Kvar og ein utfører fundamentale funksjonar som tillet konstruksjonen av meir komplekse digitale system.

Logiske portar er dei mest grunnleggjande komponentane i digital logikk. For å produsere ein binær utgong, utfører dei enkle operasjonar på dei binære inngongane. Nedanfor kan ein sjå korleis dei ulike portane fungerer.

| A | B | A _AND_ B |A _OR_ B |A _NAND_ B|A _NOR_ B |A _XOR_ B |A _XNOR_ B |_NOT_ A  |
|---|---|--------|--------|--------|--------|--------|--------|--------|
| 0 | 0 |   0    |   0    |   1    |   1    |   0    |   1    |   1    |
| 0 | 1 |   0    |   1    |   1    |   0    |   1    |   0    |   -    |
| 1 | 0 |   0    |   1    |   1    |   0    |   1    |   0    |   0    |
| 1 | 1 |   1    |   1    |   0    |   0    |   0    |   1    |   -    |

Flip-flops er bi-stabile einingar som kan lagre ein tilstand (0/1). Dei er kritiske for minnefunksjonar i digitale kretsar sidan dei kan "flippe" mellom to tilstandar, og "floppe" tilbake. Denne eigenskapen gjer at desse komponentane dannar grunnlaget for lagereningar som register og minneceller.

Multiplexere

<a name="del3"></a>
## 3. Arkitetkur og organisasjon i ei datamaskin
### Von Neumann-arkitekturen
### Kjernekomponentar i ei datamaskin (CPU, minne, I/O)
### Instruksjonssettarkitektur

<a name="del4"></a>
## 4. Mikroarkitektur
### Design og implementasjon av ein CPU
### Pipeline-prosessering og optimalisering av yting
### Kontrolleining og aritmetisk/logisk eining


<a name="del5"></a>
## 5. Minnehandtering og lager
### Typar minne (RAM, ROM, cache)
### Minnehierarki og lagringsteknologi
### Virtualisering og verning av minne


<a name="del6"></a>
## 6. Inndata/Utgongssystem
### I/O arkitektur
### Bussystem og kommunikasjon
### Eksempel på I/O-einingar


<a name="del7"></a>
## 7. Parallelle datamaskinar
### Typar av paralelle arkitekturar
### Multithreading og multiprocessing
### Skalering og parallell yting

<a name="del8"></a>
## 8. Operativsystem og maskinvaregrensesnitt
### Rolla til OS
### Styring av ressursar og maskingvareabstraksjon
### Drivarar og interruptshandtering

<a name="del9"></a>
## 9. Datamaskinnettverk
### Grunnleggjande nettverkskomponentar
### Datakommunikasjon og protokollar
### Nettverksarkitektur og infrastruktur

<a name="del10"></a>
## 10. Framtidige trender
### Nye teknologiar på horisonten (kvantedatamaskinar, AI-chips)
### Påverknaden av datatryggleik og kryptografi
### Etiske og samfunnsmessige utfordringare med teknologisk utvikling


