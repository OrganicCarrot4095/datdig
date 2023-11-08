#  Kompendium TDT4160 - Datamaskinar og digitalteknikk
#### Dette er eit sjølvskriven kompendium basert på "Structured Computer Organization" 6th edt. av Tanenbaum og Austin.

<a name="del1"></a>
## 1. Innleiing til Datamaskinar og digitalteknikk
### Historia om datamaskinar
### Grunnleggjande datamaskinterminologi
### Oversikt over struktur
1. [*Innleiing til Datamaskinar og digitalteknikkk*](#del1)
2. [*Grunnleggjande om digital logikk*](#del2)
3. [*Arkitektur og organisasjon i ei datamaskin*](#del3)
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

Flip-flops er bi-stabile einingar som kan lagre ein tilstand (0/1). Dei er kritiske for minnefunksjonar i digitale kretsar sidan dei kan "flippe" mellom to tilstandar, og "floppe" tilbake. Denne eigenskapen gjer at desse komponentane dannar grunnlaget for lagringseningar som register og minneceller.

Multiplexere (MUX) og Demultiplexere (DEMUX) er komponentar som hhv handterer signalvegar. Ein MUX vel ein av fleire inngongssignal og sender den til ein enkelt utgong, basert på ein kontrollinngong. Ein DEMUX tek eit enkelt inngongssignal og distribuerer det til ein av fleire utgongar, også styrt av ein kontrollinngong. 

Kodere og dekodere er komponentar som omformar informasjon frå ei form til ei anna. Ein koder tek fleire inngongssignal og omformar dei til ein enklare, binær representasjon. Til dømes kan ein 4-til-2-linjers koder ta fire inngongar og redusere dei til to utgongssignal. Ein dekoder gjer det motsatte; dei tek ein binær kode og ekspanderer den til fleire utgongar. Ein 2-til-4-linjers dekoder vil ta to binære inngongar og tilby fire relaterte utgongar. 

Desse kompnentane kan kombinerast for å lage meir komplekse kretsar som tellarar, minnebankar, aritmetiske logikkeiningar (ALU), og heile mikroprosessorar. Til dømes kan ein enkel datalagringseining kan byggjast ved å koble saman fleire flip-flops, medan ein MUX kan brukast i ein ALU for å velje mellom forskjellige aritmetiske og logiske operasjonar basert på ein kode som indikerer ønska operasjon. 

<a name="del3"></a>
## 3. Arkitektur og organisasjon i ei datamaskin
### Von Neumann-arkitekturen

Den grunnleggjande strukturen til Von Neumann er basert på fire hovudkomponentar:
1. Kontrolleining (CU): Tolkar og utfører instruksjoner frå minnet.
2. Aritmetisk/logisk eining (ALU): Utfører matematiske og logiske operasjonar.
3. Minne: Lagrar både instruksjonar og data.
4. Input/Output (I/O): Handterer kommunikasjon mellom datamaskina og omverdenen.

Von Neumann-arkitekturen representerer eit fundamentalt skifte i designet av datamaskinar, ved å innføre eit konsept der både instruksjonar og data er lagra i det same minneområdet. Dette var ei revolusjonerande utvikling samanligna med dei tidlige maskinane som var hardkoda for å utføre spesifikke oppgåver, då det vart modleg for datamaskinar å bli omprogrammerte kun ved å endre innhaldet i minnet - utan behov for nokre fysiske endringar i maskinvara. Bakgrunnen for denne arkitekturen er ideen om ein "stored-program computer". Dette tillet maskina å utføre eit bredt spekter av oppgåver ved å hente og utføre instruksjonane sekvensielt, ein prosess som er kjenta i lineære sekvensiell prosessering. Denne prosesseringa blir styrt av programteljaren (PC), som innehar ei kritisk rolle i å halde styr på adressa til neste instruksjon som skal utførast. Etter at instruksjonen er henta, aukar PC verdien sin for å peike på den påfølgjande instruksjon i minnet, med mindre sjølve instruksjonen angir eit hopp i sekvensen. 

Når ein instruksjon er henta frå minnet, går CPU'en gjennom ein instruksjonssyklus som byrjar med å dekode instruksjonen for å forstå kva for ein operasjon som skal utførast. Etterpå blir operasjonen utført, dette kan innebære alt frå aritimetiske berekningaar til datamanipulasjon eller interaksjon med andre systemkomponentar. Resultatet av operasjonen blir anten midlertidig lagra i registeret til CPU'en for rask tilgong, eller skriven tilbake til minnet for seinare bruk. Viktigheita av denne arkitekturen ligg i enkelheita og effektiviteten den gir. Dette har gjort det mogleg å designe og konstrurere datamaskinar som kan utføre eit bredt utval av oppgåver ved å køyre forskjellige program utan å måtte endre maskinvara. Dette er grunnlager for moderne PU og har leia til ei eksplosiv vekst i dataprogram og applikasjonar. 

<a name=buss></a>
Denne sekvensielle tilnærminga til databehandling blir transportert gjennom eit system av databussar, med kontrollsignal som dirigerer aktivitetane i CPU'en basert på den dekoda instruksjonen. Harvard-arktitekturen, til dømes, nyttar seg av separate lagrings- og bussystem for instruksjonar og data, noko som potensielt aukar hastigheita på dataflyten og reduserer ventetida for operasjonane. 

Gjennom kontinuerlige forbetringar og innovasjonar i mikroarkitekturen - den fysiske implementeringa av settet med instruksjonar som CPU'en kan utføre - har moderne prosessorar blitt betydeleg mykje raskare og meir effektive.

Von Neumann-arkitekturen har ikkje berre fordelar. På grunn at delinga av minne for både instruksjonane og data, oppstår det som blir kalla Von Neumann-flaskehalsen; eit problem der hastigheita på dataflyten mellom prosessoren og minnet begrensar ytinga til systemet. Sidan begge operasjonane, henting av instruksjonar og lesing/skriving av data, må dele den same kommuniksjonskanalen, kan maskina oppleve ein flaskehals der hastigheita til prosessoren overgår minnebåndbreidda. Dette har leia til forskning og utvikling av andre arkitekturar, som Hardvard-arkitekturen der instruksjonar og data er lagra i separate minneblokker, samt forskjellege cache-strategiar for å minimere ventetida forbunde med minneaksess.


### Kjernekomponentar i ei datamaskin
#### CPU - Central Processing Unit
CPU, eller prosessoren, er hjernen til datamaskina og ansvaleg for å tolke og utføre dei fleste av instruksjonane frå dei andre komponentane og programvara til datamaskina. Den består av fleire nøkkelkomponentar:
- Register: Små lagringsområde som blir brukt for å utføre operasjonar og midlertidig halde på data.
- Kontrolleining (CU): Dirigerer operasjonane til CPU'en ved å hente, tolke og utføre instruksjonar.
- Aritmetisk/logisk eining (ALU): Utfører matematiske, logiske og avgjersleoperasjonar.


#### Minne
Det finst ulike typar minne i ei datamaskin: 
- RAM (Random Access Memory): Voltatilt* minne som blir brukt for å lagre data og instruksjonar som ei datamaksin treng medan den er i bruk.
- ROM (Read-Only Memory): Ikkje-voltatilt minne som inneheld essensiell data som ikkje blir endra, ofte rukt for oppstartsprosessar.
- Cache: Hurtigminne som lagrar kopiar av data frå ofte brukte hovudminneområde.
- Virtuelt minne: Ein metode for å utvide det fysiske minnet ved å bruke ein del av harddisken so om det var RAM.

Minnehierarkiet, frå hurtig og dyr cache til treigare og billigare RAM og lagring, er essensielt for å balansere kostnad og yting i maskina. "Random Access" refererer til evna til å få tilgong til dataelement direkte og i vilkårleg rekkefølgje, noko som er kritisk for effektiviteten til mange operasjonar.

<a name="voltatilt"></a>
> *Voltatil: I datamaskinkontekst refererer det til ein type minne som krever straum for å behalde lagra informasjon. Ettersom RAM er voltatilt, tyder det at alt som er lagra der, går tapt dersom/når datamaskina blir skrudd av.


#### I/O - Input/Output
I/O-einingar tillet ein datamaskin å kommunisere med omverda og brukeren. Dei inkluderer alt frå tastatur og mus, til skjermar, printarar og nettverkskort.

Desse einingane kommuniserer med CPU og minne gjennom I/O-bussar, som er dataspor som fraktar informasjonen fram og tilbake. Desse bussane er avgjerande for datamaskina si evne til å overføre data til og fra I/O-einingar, og effektiviteta av desse bussane påverkar direkte ytinga til systemet. 


### Instruksjonssettarkitektur

Eit instruksjonssett er ei samling av kommandoar som CPU'en kan gjenkjenne og utføre. Det definerer dei lavnivå operasjonane som prosessoren kan utføre og spelar ei kritisk rolle i CPU-funksjonalitet. Desse kommandoane er grunnlaget for all programvare, sidan høgare-nivå språk til slutt må oversettjar til desse instruksjonane for at CPU'en skal kunne utføre dei. 

RISC (Reduced Instruction Set Computer) og CISC (Complex Instruction Set Computer) er to forskjellege typar arkitekturar basert på instruksjonssett. RISC-arkitektur fokuserer på å ha eit mindre og meir optimisert sett av instruksjonar som ofte kan utførast i éin klokkesyklus. CISC derimot, inkluderer eit breiare og meir komplekst sett av instruksjonar som kan utføre meir kompliserte oppgåver pr instruksjon, men kan kreve fleire klokkesyklusar for å utføre. 

Ein typisk instruksjonssettarkitektur inneheld fleire typar instruksjonar:
- Aritmetiske instruksjonar: Utfører matematiske operasjonar som addisjon og subtraksjon.
- Kontrollinstruksjonar: Endrar sekvensen av utførte instruksjonar, f.eks. ved løkker og betinga sprang.
- Dataoverføringsinstruksjonar: Flyttar data mellom register, mellom minne og register, eller mellom I/O-einingar og register.

CPU'en utfører instruksjonar gjennom ein syklus som inkluderer henting av instruksjonen frå minnet, dekoding for å forstå instruksjonen, gjennomføring av dei naudsynte operasjonane, og til slutt lagring av resultatet. Pipelining er ein teknikk der CPU'en byrjar utføringa av ein ny instruksjon før den forrige er fullført, noko som lignar på eit samleband, slik at fleire instruksjonar kan vere under behandling samstundes. Dette aukar ytinga ved å redusere ventetida mellom instruksjonar

Mikroarkitekturen refererer til den spesifikke måten ein CPU er designa på for å implementere eit instruksjonssett. Det er mikroarkitekturen som avgjer korleis instruksjonane faktisk blir utført - timing, pipelining, typar og antal register, og andre lavnivå operasjonsdetaljar.

Medan instruksjonssettarkitekturen forblir konstant, kan mikroarkitekturen endrast for å forbetre ytinga. Til dømes, kan vi ved å forbetre pipelining, auke storleiken på cache, eller leggje til funksjonar som out-of-order execution, kan ein prosessor gjere meir arbeid pr klokkesyklus utan å endre det grunnleggjande settet med instruksjonar det støttar. 

<a name="del4"></a>
## 4. Mikroarkitektur
### Design og implementasjon av ein CPU
Mikroarkitekturen i ein CPU refererer til den fysiske realiseringen og organisasjonen av prosessorens funksjoner, som må være i stand til å utføre instruksjonssettarkitketuren. Den styrer korleis instruksjonane blir handtert, behandla og utført på maskinvarenivå, og er essensiell for å bestemme ytinga og effektiviteten til prosessoren. 

Hjartet av CPU'en består av fleire kritiske komponentar:
- Rekneregister: Små hurtige lagringsområde som blir brukt for å midlertidig halde på data og instruksjoner som er under behandling.
- Kontrolleiing (CU): Dirigerer operasjonen av CPU'en ved å hente instruksjonar frå minnet, dekode dei og sende naudsame signal til ALU og andre komponentar for å utføre desse instruksjonane.
- Aritmetisk logisk eining (ALU): Utfører aritmetiske og logiske operasjonar.
- Hurtigbufferminne (Cache): Raskt minne som lagrar kopiar av ofte brukt data frå hovudminne for å redusere tida det tek for å hente den.

Desse komponentane er organiser på ein slik måte at dei jobbar saman i ein koordinert sekvens for å utføre komplekse instruksjonar raskt og effektivt. 

CPU-design inkluderer utvikling av ein instruksjonssyklus og datapath som saman legg føresentader for korleis instruksjonar skal bli henta, dekoda, utført og korleis resultat blir lagra. Datapathen er den faktiske "stien" dataen flyt gjennom. Dekodinga av instruksjonar er ein kritisk del, ettersom den overset instruksjonar til signal som fortel dei ulike delane i CPU'en kva dei skal gjere. 

Implementasjon av mikroarkitekturen på silisium inneber bruk av halvleiarteknologi for å lage integrerte kretsar. Dei grunnleggjande byggjesteinane er transistorar, som fungerer som elektroniske brytarar. Desse transistorane blir kombinert for å lage logiske portar som AND, OR og NOT, som igjen byggjer opp meir komplekse funksjonar som ALU, register og kontrolleiningar. 

Desse komponentane blir nøye organiser på ein silisium-chip gjennom ein prosess som blir kalla VLSI-design (Very Large Scale Integration). Denne prosessen inneber skapinga av mikroskopiske strukturar som formar dei individuelle funksjonelle einingane i CPU'en, som deretter blir test og optimaliser for yting og energieffektivitet.


### Pipeline-prosessering og optimalisering av yting
Pipelining er ein teknikk der fleire instruksjonar overlapper i utføringa ved å dele instruksjonshandlinga i fleire steg eller "stages". Ein CPU-pipeline liknar eit samleband i ein fabrikk, der kvar del av ein instruksjon  blir behandla i eit separat trinn av pipeline. Dei vanlegaste trinna er henting, dekoding, utføring, minnetilgong og skriv tilbake (fetch, decode, execute, memory access og write back). Medan ein instruksjon blir utført, kan neste instruksjon bli dekoda, og neste etter der bli henta, etc. Dette aukar effektiviteten. 

Fordelar: 
- Auke i throughput: Ved at fleire instruksjonar blir behandla samstundes, aukar antalet fullførte instruksjonar pr tidseining.
- Betre nytta ressursar: Sidan kvart trinn i pipeline er aktivt og produktivt, tyder det at ressursane til CPU'en (td. ALU eller minnetilgongseiningar) konstant er i bruk.

Ulemper:
- Hazards: Dette er problem som oppstår når fleire instruksjonar som er i pipeline påverkar kvarandre. Det finst tre hovudtypar av hazards: data hazards, control hazards og structural hazards.
- Minimering av hazards: For å handtere desse problema, blir det implementert teknikkar som pipeline scheduling som omorganiserer rekkefølgja av instruksjonar og out-of-order execution, noko som tillet instruksjonar etter ein hazard å fullføre før instruksjonen som forårsaka hazard.

For å optimialisere ytinga, kan ein bruke følgjande teknikkar:
- Prediksjon av forgreiningar: Dette hjelp med å reduserer ventetida ved å gjette vegen ei forgreining vil ta, og lastar inn instruksjonar på forhand basert på denne gjetninga.
- Superskalær arkitektur: Tillet at fleire instruksjonar blir henta, dekoda og utfør samstundes, noko som ytterlegare aukar gjennomstrømmningsraten.
- Parallellitet på fleire nivå: Inkluderer teknikkar som multithreading, kor ein enkelt CPU kan utføre fleire threads parallelt, og multicore-prosessering, der fleire CPU-kjerner i ein enkelt chip jobbar parallelt for å behandle fleire oppgåver samstundes.

Samla sett forbetrar desse teknikkane ytinga ved å maksimere utnyttinga av ressursar og redusere ventetida, noko som er avgjerande for å møte dagens krav til datamaksinkraft og effektivitet. 

### Kontrolleining og aritmetisk/logisk eining
Kontrolleininga (CU) er ein kritisk komponent i CPU-en som styrer og koordinerer aktiviteten til dei andre komponentane i prosessoren. Hovudfunksjonen til CU'en er å tolke instruksjonane som blir henta frå minnet og deretter generere dei naudsynte signala for å utføre desse instruksjonane. Den styrer dataflyten inn og ut av prosessoren og sørger for å at dei riktige operasjonane blir utført på dei riktige tidspunkta. 

For å utføre instruksjonar, bryt CU'en dei ned i mindre trinn som vert kalla mikrooperasjonar. Desse inkluderer operasjonar som er å flytte data mellom register, utføre aritmetiske og logiske operasjonar, og kommunisere med minnet. Mikrooperasjonar er grunnleggjande handlingar som er lette å handtere for hardwaren som høyrer til CPU'en. CU'en sikrar at desse operasjonane blir utført i korrekt sekvens for å fullføre den opprinnelege instrukasjonen. 

ALU'en er den delen av CPU'en som utfører alle dei matematiske berekningane of logiske operasjonane. Når det er naudsynt med bereknigar, sender CU'en data og operasjonstype til ALU'en, som deretter utfører operasjonen og sender resultatet tilbake, anten for vidare behandling eller for lagring i minnet.

Samspelet mellom CU og ALU er avgjerande for operasjonane CPU'en skal utføre. CU gir instruksjonar og kontrollerer handlingane til ALU'en ved å fortelje kva for nokre operasjonar som skal utførast og når. ALU'en mottek og utfører desse operasjonane, og returnerer resultat til CU for vidare handling. Denne tilbakekoplingsløkkja er grunnleggjande for alle funksjonane til prosessoren og evna til å utføre komplekse instruksjonar. 

Moderne CPU-design står ovanfor fleire utfordringar, spesielt med tanke på straumforbruk og varmeproduksjon. For å takle desse utfordringane bruker både CU og ALU avanserte teknikkar for straumforsyning, som å reduserer klokkehastigheita eller spenningsnivåa når maksimal yting ikkje er naudsynt. Dei kan også bruke meir sofistikert kjøleteknologi og termisk design for å handtere varme. I tillegg bidreg finare produksjonsteknologiar til å redusere straumforbruket ved å tillate lågare spenningsnivå og redusere lekkasjestraumar i transistorar.


<a name="del5"></a>
## 5. Minnehandtering og lager
### Typar minne
### RAM - Random Access Memory
RAM er hovudminnet til ei datamaskin og fungerer som ein midlertidig lagringsplass for data og program som er aktive eller i bruk. Det er "tilfeldig tilgang" fordi CPU'en har evna til å få tilgong til data lagra i kva som helst del av minnet direkte og i kva som helst rekkefølgje, samanlikna med sekvensiell tilgong som i magnetband.

Det finst to hovudtypar RAM: 
- Statisk RAM (SRAM): Dette er raskare og meir påliteleg enn DRAM, men er også dyrare. SRAM brukar fleire transistorar pr minnecelle og held på dataen så lenge det er tilførsel av straum. Det blir ofte brukt i cache pga den høge hastigheita.
- Dynamisk RAM (DRAM): Dette er den vanlegaste typen RAM og blir brukt for hovudminnet i dei fleste datamaskinar. DRAM lagrar kva bit av data i ein separat kondensator innanfor ein integrert krets, som må friskast opp periodisk for å behalde dataen. DRAM er treigare enn SRAM, men det er billegare og kan lagre meir data pr minnechip.

#### ROM - Read Only Memory
ROM er ein type ikkje-flyktig minne som beheld informasjonen sin sjølv når straumen er av. Det er ofte brukt til å lage firmware eller oppstartsprogramvare (BIOS/UEFI) som maskina treng for å starte opp. ROM-innhald er vanlegvis programmert av produsenten og det er ikkje meint at brukaren skal endre dette. 

#### Cache
Cache er ein liten mengde hurtig, men dyr, SRAM som blir brukt av CPU'en til å redusere gjennomsnittleg tilgongstid til data frå hovudminnet. Cacheminne fungerer som ei mellommlagringseining for ofte brukt data, slik at CPU'en kan unngå den tidskrevande prosessen me då hente data frå det treigare hovudminnet. 

Cacheminne er organisert i ulike nivå:
- L1-cache: Dette er første og raskaste cache, ofte bygd direkte inn i prosessorkjerna. Den har svært låg latens og er designa for å gi rask tilgong til den mest kritiske dataen.
- L2-cache: Ligg ofte på same chip som CPU'en, men kan vere ein separat cache for kvar prosessorkjerne. Den er større enn L1-cache, men har også litt høgare latens.
- L3-cache: Denne cachen er vanlegvis delt mellom kjernene på ein CPU og er større enn både L1 og L2, men har større latens. L3-cache hjelp til med å redusere belastninga på hovudminnet ved å lagre data som er rimeleg ofte brukt.

Desse ulike nivåa av cache arbeider saman for å forbetre den genrelle ytinga til datamaskina ved å redusere den tida det tek for prosessoren å få tilgong til data og instruksjonar den treng for å utføre oppgåver.

### Minnehierarki og lagringsteknologi
Minnehierarkiet i ei datamaskin er eit strukturert oppsett av minne og lagringseiningar som varierer i hastigheit, storleik og avstand til CPU'en. Øvst i hierarkiet finn ein CPU-registera som er den raskaste formen for minne lagring, men også den med minst kapasitet og direkte tilkopla til CPU'en. Deretter føl cache-minnet (L1, L2 og L3) som fungerer som midlertidlig lagringsplass for å minimere antal langsame minneaksessar som CPU'en må utføre. 

Under cache ligg hovudminnet, eller RAM, som har større kapasitet enn registera og cache, men er treigare og framleis [voltatilt](#voltatilt). Lagringseiningar som SSD (Solid State Drives) og HDD (Hard Disk Drives) utgjer neste nivå i hierarkiet. Desse er betydeleg treigare enn RAM, men tilbyr mykje større lagringskapasitet og er ikkje-flyktige, noko som tyder at dei held på dataen sjølv om systemet er skrudd av.
- Solid State Drives (SSD): SSD brukar flash-basert minne, noko som er raskare, meir påliteleg og meir energi effektivt enn tradisjonelle harddiskar. Dei har ingen bevegelige delar, noko som reduserer risikoen for mekaniske feil og gjer dei meir holdbare. SSD er derimot dyrare pg GB enn HDD.
- Harddiskar (HDD): Disse einingane lagrar data magnetisk på roterande plater. Sjølv om dei er treigare enn SSD, spesielt når det gjeld tilgongstid og dataoverføringshastigheit, tilbyr HDD meir lagringskapasitet for mengane og er derfor eit meir kostnadseffektivt alternativ for mykje lagring.
- Optisk lagring: Dette inkluderer medier som CD, DVD og Blu-ray-plater. Sjølv om dei er relevante for distribusjon av media og arkivering, har optisk lagrning blitt mindre populær som primær lagringsløysing på grunn av avgrensingar i kapasitet og hastighet samanlikna med SSD og HDD.

Minnehierarkiet påverkar systemet si generelle yting på grunn av dei hastigheitsskilnadane mellom dei ulike lagringseiningane. Ein CPU kan utføre operasjonar mykje raskare enn det er mogleg å lese og skrive til RAM, som igjen er mykje raskare enn sekundære lagringseiningar som SSD og HDD. Derfor brukar ein hurtige, men dyre og små minneeiningar (som cache) til å lagre data og instruksjoner som CPU'en treng umiddelbart, medan større og treigare einingar blir brukt til å lagre større mengder data som ikkje krever rask tilgong.

Balansen mellom hastigheit og kapasitet er avgjerande for optimal yting. For mykje fokus på kapasitet kan føre til ein flaksehals dersom data ikkje blir flytta raskt nok til og fra lagringseiningane. På andre sida, hvis systemet har for mye rask, underutnytta minne, kan det vere eit spørsmål om ineffektiv ressursbruk. Moderne system brukar ein kombinasjon av RAM, SSD og nokre gonger HDD for å skape ei balansert og kostnadseffektiv løysing.

### Virtualisering og verning av minne
Virtuelt minne er ein teknikk som blir brukt av OS for å gi applikasjonar inntrykk av at det er meir minne tilgjengeleg enn det som faktisk eksisterer. Dette kan ein oppnå ved å  bruke ein del av lagringsplassen på harddisken som om det var ekstra RAM. Dette tillet OS handtere større program eller fleire program samstundes enn det ville vært mogleg med berre den fysiske RAM. 

- Sideveksling (Paging): OS deler minnet inn blokker av ein viss storleik, kald sider. Når eit program treng data som ikkje er i RAM, flyttar OS ei side av data fra disk til RAM og erstattar eksisterande side ved behov.
- Segmentering: Dette er ei anna form for virtuell minnehandtering der minnet er delt inn i segmenter av varierande storleikar som representerer logiske einingar som program eller datastrukturar.

Minnevern er avgjerande for å oppretthalde stabilitet og sikkerhet innad i systemet. Det sikrar at ein prosess ikkje kan tilgå eller endre minneområde som er tildelt til ein anna prosess. Dette er viktig for å forhindre at ein prosess forårsakar feil i ein annan prosess, anten ved uhell eller gjennom ondsinna kode. 

OS handterer minnevern ved hjelp av mekanismar som:
- Minnetillatelsar: Sider eller segment kan få ulike løyve (lese, skrive og køyre), og OS syt for at desse løyvene blir handheldt.
- Sidevern: Kvar side i minnet kan vernast slik at forsøk på uautorisert tilgong blir blokkert og eventuelt rapportert til OS.

OS bruker ulike strategiar for å handtere minnet effektivt:
- Garbage Collection: Dette er ein prosess for automatisk minnerydding som identifiserer og frigjer minne som ikkje lenger er i bruk av eit program.
- Minnetildeling og frigjering: OS tildel minne til program ved behov og frigjer det når programma er ferdige, ofe ved hjelp av algoritmar som "first fit", "best fit" eller "worst fit" for å administere minneblokker

Sikkerheit knytta til minne er eit kritisk aspekt av programvaredesign og system adminstrasjon. Sårbarheiter som buffer overflows, der data blir skriven utanfor grensene til ein allokert buffer, kan føre til sikkerheitsbrukk ved å tillate ondsinna kode å køyre. For å forhindre slike problem har ein:

- Bounds Checking: Sørg for at program utfører grensesjekking på buffer og input.
- Address Space Layout Randomization (ASLR): Dette er ein sikkerheitsteknikk som tilfeldig plasserer data i minnet for å gjere det vanskelegare for angriparar å føreseie kvar spesifikke delar av eit program vil vere i minnet.
- Non-executable Memory: Mange moderne OS forhindrar køyring av kode frå område av minnet som er allokert for data, noko som hjelp til å forhindre utnytting av buffer overflows.



<a name="del6"></a>
## 6. Inndata/Utgongssystem
### I/O arkitektur
Inngong/utgongsarkitekturen (I/O-arkitekturen) er eit kritisk subsystem i ei datamaskin som handlar om korleis data flyttar seg mellom CPU'en og dei eksterne einingane som skjermar, tastatur, nettverkskort og lagringseiningar. Denne arkitekturen fungerer som ei bru som koblar den raske og komplekse verda til CPU'en med den treigare og mer varierte verda til periferiutstyr. I/O-arkitekturen må handtere ein stor variasjon i einingshastigheiter og kommunikasjonsprotokollar.

Det finst fleire metodar for å kontrollere I/O-operasjonar:
- Programstyrt I/O: Dette er den enklaste metoden der CPU'en aktivt ventar på og sjekkar statusen til ei I/O-eining. Dette er ikkje effektivt sidan det bind CPU'en til I/O-prosessen og kan føre til mykje unødvendig venting.
- Avbruddsstyrt I/O: Her blir CPU'en frigjort til å utføre andre oppgåver medan I/O-operasjonen pågår. Når I/O-operasjonen er ferdig, sender eininga eit avbrudd til CPU'en, som da kan handtere overføringa av data.
- Direkte minnetilgong (DMA): DMA tillet I/O-einingar å sende og motta data direkte til og frå hovudminnet, utan konstant overvåkning frå CPU'en. Dette frigjer CPU'en frå å måtte kopiere data frå ein buffer til ein annan og forbetrar ytinga til systemet betydeleg.

Datamaskinar opererer i to modusar: brukermodus og kernelmodus (også kalla supervisormodus). Brukermodus er der vanlege appliksajonar køyrer; desse applikasjonane har begrensa tilgong til systemressursar og kan ikkje direkte utføre I/O-operasjonar. Kernelmodus er der kjerna til OS køyrer og har full tilgong til maskinvara og kan utføre I/O-operasjonar.

Når ein applikasjon i brukermodus treng å utføre ein I/O-operasjon, må den gjere eit systemkall til OS, som då kan bytte til kernelmodus for å utføre I/O-operasjonen på ein sikker og kontrollert måte. Dette skjer for å beskytte systemet mot skadeleg eller feilaktig kode og for å sikre at I/O-operasjonane ikkje forstyrrar kvarandre, noko som er essensielt for stabilitet og sikkerhet i systemet.


### Bussystem og kommunikasjon
Kommunikasjon over bussystemet involverer overføring av data, adresser og kontrollsignal:
- Når CPU'en treng å lese data frå minnet, sender den ei adresse over adresse[buss](#buss)en til minnet.
- M


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


