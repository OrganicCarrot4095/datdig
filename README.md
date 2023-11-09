
#  Kompendium TDT4160 - Datamaskinar og digitalteknikk
#### Dette er eit sjølvskriven kompendium, med god hjelp av Google og Geir. Forfattaren innehar infinitesimale mengder kunnskap og tek ikkje ansvar for evt. feil.

<a name="del1"></a>
## 1. Innleiing til Datamaskinar og digitalteknikk
Datamaskinar og digitalteknologi er overalt i dagens samfunn, frå handholdte einingar til komplekse datasenter som driv store delar av den digitale verda vår. For å forstå desse systemas kompleksitet og kraft, er det viktig å starte med grunnleggjande begrep og terminologi. Denne kunnskapen vil danne grunnlaget for vidare utforskning av verda til datamaskinar.
### Historia om datamaskinar
Datamaskinar har gjennomgått stor utvikling gjennom tidene. Frå dei første mekaniske reknemaskinane, til dei avanserte mikroprosessorane som ligg i kjernen til dei fleste teknologiane vi har i dag. Innovasjonar i mikroarkitekturen - den fysiske implementasjonen av settet med instruksjonar maskina kan utføre, ofte referert til som maskinas "instruksjonssettakritektur" - har vore ein stor pådrivar for denne utviklinga. Her er mikroarkitekturen tilpassa for å effektivt utføre instruksjonssettakritekturen, og omvendt. Saman dannar dei fundamentet for den digitale logikken som er essensiell for funksjonaliteta til ei datamaskin.

### Grunnleggjande datamaskinterminologi
####**Datamaskin:**
Ei datamaskin er ei elektronisk eining som kan behandle og lagre data ved å utføre eit sett med instruksjonar kalt eit program. Datamaskinar utfører eit breidd spekter av funksjonar, frå enkle kalkulasjonar til komplekse databehandlingsoppgåver. Dei viktigste komponentane i ei datamaskin inkluderer:
- **Input-einingar:** Utstyr som tastatur, mus, og mikrofon som lét brukarane leggje inn data til datamaskina.
- **Output-einingar:** Desse inkluderer skjermar, skrivarar og høgtalarar som datamaskina brukar for å presentere resultata av prosesseringa.
- **Prosesseringseiningar:** Oftast referert til som sentralprosessoren (CPU), er dette "hjernen" i datamaskina som utfører programinstruksjonane.
- **Lagringseining:** Omfattar komponentar som harddiskar, SSD-er og USB-stasjoner som lagrar data permanent eller midlertidig.

####**Bit og Byte:**
- **Bit:** Ein bit er den mest grunnleggjande eininga av digital informasjon og kan ha ein av to verdier, 0 eller 1. 
- **Byte:** Ein byte består av 8 bits og er ei standard eining for å måle datamengde. Bytes blir brukt til å representere ein karakter som bokstavar, tal, eller symbol i digitale systemer.

####**Programvare vs. Maskinvare:**
- **Programvare:** Dette er dei instruksjonane og dataane som køyrer på og kan installerast på maskinvara. Programvare inkluderer operativsystem, applikasjonar og drivarar.
- **Maskinvare:** Dette er dei fysiske einingane som utgjer ei datamaskin, inkludert prosessoren, minnet, hovudkortet, lagringseiningar og periferiutstyr.

####**Operativsystem:**
Eit operativsystem (OS) er eit program som fungerer som ein mellommann mellom brukeren og maskinvara til datamaskina. Det administrerer systemressursar og gir brukarar eit grensesnitt for å køyre applikasjonar. OS handterer oppgåver som filhandtering, minnehandtering, prosesskontroll og styring av periferiutstyr.

####**Nettverk:**
Et datanettverk er ein gruppe av datamaskiner og andre einingar som er forbunde samen for å dele ressursar og data. Internettet er eit globalt system av samenkopla datanettverk som brukar internettprotokollen (IP) for å knytte saman einingar over heile verda, tillét datamaskinar å kommunisere, og dele informasjon på tvers av lange avstandar.

####**Brukergrensesnitt:**
Brukergrensesnittet er det punktet der menneske samhandlar med datamaskiner. Det finnes to hovedtyper:
- **Grafiske brukergrensesnitt (GUI):** Tillét brukarar å samhandle med datamaskinar gjennom visuelle element som vindu, ikon og menyar.
- **Kommandolinje-grensesnitt (CLI):** Tillét brukarar å samhandle med datamaskinen gjennom tekstkommandoar. CLI er kraftigare men kan være meir komplekst å bruke og krev kjennskap til spesifikke kommandospråk.
- 
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
10. [*Framtidige trender*](#del10)

   <!-- Introduksjon                                    Kap 1,2               -->
   <!-- Instruksjonssett                                Kap 5                 -->
   <!-- Single-cycle (bottom-up, top down)              Kap 2.1, 4.1          -->
   <!-- Digitalteknikk                                  Kap 3 + kompendium    -->
   <!-- Single-cycle + interupts, traps                 Kap 2.1, 4.1, 5.6.5   -->
   <!-- Pipeline                                        Kap 4.4.4, 4.3        -->
   <!-- Hazards, Forwarding, Branch Prediction          Kap 4.5.2, 4.4        -->
   <!-- Memory + Cache                                  Kap 4.5               -->
   <!-- Virtuelt minne                                  Kap 6.1               -->
   <!-- Flerkjerneprosessorer og minnesystemene deres                         -->
   <!-- Grafikkprosessorer og akseleratorer                                   -->
   <!-- Sikkerhet: studerer kjente hull                                       -->

<a name="del2"></a>
## 2. Grunnleggjande om digital logikk
### Digital logikk og viktigheten av denne
Digital logikk er studiet av elektroniske system som nyttar binære tal for å representere og manipulere informasjon. Dette konseptet er grunnmuren for alle datamaskinar og mange andre typar elektroniske einingar. Ved å bruke binærsystemet, klarar digital logikk å utføre komplekse berekningar og datahandtering gjennom relativt enkle operasjonar. Desse operasjonane blir utført ved hjelp av logiske portar, slik som AND, OR og NOT. Dei ulike portane har ulike eigenskapar som vi skal sjå på seinare. Ved å kombinere desse grunnleggjande operasjonane i meir kompliserte kretsar, kan digital logikk utføre alle typar datamaskininstruksjonar. Dette gjer det mogleg for elektroniske einingar å køyre program, prosessere data og simulere menneskeleg tenkning i form av kunstig intelligens.

### Binære system og datarepresentasjon

Det binære tallsystemet dannar grunnlaget for all digital logikk og databehandling. Der det desimale systemet brukar ti siffer (0-9), opererer det binære systemet kun med to, 0 og 1. Desse siffera svarar til dei to moglege tilstandane i digitale kretsar, herfrå referert til som av(0) og på(1). Dette samsvarar godt med den binære naturen til elektroniske komponentar som kan vere i nettopp to tilstandar - at elektrisk strøm flyt gjennom (1), eller ikkje (0).

Innan datamaskingar og elektroniske einingar blir all informasjon koda binært. Til dømes bruker ASCII sekvensar beståande av 0 og 1 for å representere bokstavar og teikn. "A" kan altså skrivast 01000001. På same måte kan bilete og lyd også omformast til binær form ved hjelp av ulike kodingssystem. Bilete blir koda som ei samling av pikslar, der kvar piksel har ein binær verdi som representerer farge og intensitet. Lydfiler blir tilsvarande representert med binær data som skildrar amplituden til bølgja over tid. Desse binære representasjonane tillét lagring, manipulering og overføring av komplekse data i elektroniske system, og det gjer det mogleg for datamaskinar å prosessere og "forstå" eit mangfold av informasjonstypar gjennom deira grunnleggjande digitale logikk.


### Grunnleggjande digitale komponentar
Grunnleggjande digitale komponentar er dei byggjesteinane som digitale kretsar er konstruert frå. Kvar og ein utfører fundamentale funksjonar som tillét konstruksjon av meir komplekse digitale system.

Logiske portar er dei mest grunnleggjande komponentane i digital logikk. For å produsere ein binær utgong, utfører dei enkle operasjonar på dei binære inngongane. Nedanfor kan ein sjå korleis dei ulike portane fungerer.

| A | B | A _AND_ B |A _OR_ B |A _NAND_ B|A _NOR_ B |A _XOR_ B |A _XNOR_ B |_NOT_ A  |
|---|---|--------|--------|--------|--------|--------|--------|--------|
| 0 | 0 |   0    |   0    |   1    |   1    |   0    |   1    |   1    |
| 0 | 1 |   0    |   1    |   1    |   0    |   1    |   0    |   -    |
| 1 | 0 |   0    |   1    |   1    |   0    |   1    |   0    |   0    |
| 1 | 1 |   1    |   1    |   0    |   0    |   0    |   1    |   -    |

**Flip-flops** er bi-stabile einingar som kan lagre ein tilstand (0/1). Dei er kritiske for minnefunksjonar i digitale kretsar sidan dei kan "flippe" mellom to tilstandar, og "floppe" tilbake. Denne eigenskapen gjer at desse komponentane dannar grunnlaget for lagringseningar som register og minneceller.

**Multiplexarar (MUX)** og **Demultiplexarar (DEMUX)** er komponentar som hhv. handterer signalvegar. Ein MUX vel ein av fleire inngongssignal og sender den til ein enkelt utgong, basert på ein kontrollinngong. Ein DEMUX tek eit enkelt inngongssignal og distribuerer det til ein av fleire utgongar, også styrt av ein kontrollinngong. 

Kodarar og dekodarar er komponentar som omformar informasjon frå ei form til ei anna. Ein koder tek fleire inngongssignal og omformar dei til ein enklare, binær representasjon. Til dømes kan ein 4-til-2-linjers koder ta fire inngongar og redusere dei til to utgongssignal. Ein dekoder gjer det motsatte; dei tek ein binær kode og ekspanderer den til fleire utgongar. Ein 2-til-4-linjers dekoder vil ta to binære inngongar og tilby fire relaterte utgongar. 

Desse kompnentane kan kombinerast for å lage meir komplekse kretsar som tellarar, minnebankar, aritmetiske logikkeiningar (ALU), og heile mikroprosessorar. Til dømes kan ei enkel datalagringseining byggjast ved å koble saman fleire flip-flops, medan ein MUX kan brukast i ein ALU for å velje mellom forskjellige aritmetiske og logiske operasjonar basert på ein kode som indikerer ønska operasjon. 

<a name="del3"></a>
## 3. Arkitektur og organisasjon i ei datamaskin
<a name="vonneumann"></a>
### Von Neumann-arkitekturen

Den grunnleggjande strukturen til Von Neumann er basert på fire hovudkomponentar:
- **Kontrolleining (CU):** Tolkar og utfører instruksjonar frå minnet.
- **Aritmetisk/logisk eining (ALU):** Utfører matematiske og logiske operasjonar.
- **Minne:** Lagrar både instruksjonar og data.
- **Input/Output (I/O):** Handterer kommunikasjon mellom datamaskina og omverdenen.

Von Neumann-arkitekturen representerer eit fundamentalt skifte i designet av datamaskinar, ved å innføre eit konsept der både instruksjonar og data er lagra i det same minneområdet. Dette var ei revolusjonerande utvikling samanligna med dei tidlege maskinane som var hardkoda for å utføre spesifikke oppgåver, då det vart mogleg for datamaskinar å bli omprogrammerte kun ved å endre innhaldet i minnet - utan behov for nokre fysiske endringar i maskinvara. Bakgrunnen for denne arkitekturen er idéen om ein "stored-program computer". Dette tillét maskina å utføre eit bredt spekter av oppgåver ved å hente og utføre instruksjonane sekvensielt, ein prosess som er kjenta i lineære sekvensiell prosessering. Denne prosesseringa blir styrt av programteljaren (PC), som innehar ei kritisk rolle i å halde styr på adressa til neste instruksjon som skal utførast. Etter at instruksjonen er henta, aukar PC-en verdien sin for å peike på den påfølgjande instruksjon i minnet, med mindre sjølve instruksjonen angir eit hopp i sekvensen. 

Når ein instruksjon er henta frå minnet, går CPU-en gjennom ein instruksjonssyklus som byrjar med å dekode instruksjonen for å forstå kva for ein operasjon som skal utførast. Etterpå blir operasjonen utført, dette kan innebere alt frå aritimetiske berekningar til datamanipulasjon eller interaksjon med andre systemkomponentar. Resultatet av operasjonen blir anten midlertidig lagra i registeret til CPU-en for rask tilgong, eller skriven tilbake til minnet for seinare bruk. Viktigheita av denne arkitekturen ligg i enkelheita og effektiviteten den gir. Dette har gjort det mogleg å designe og konstrurere datamaskinar som kan utføre eit bredt utval av oppgåver ved å køyre forskjellige program utan å måtte endre maskinvara. Dette er grunnlaget for moderne PU og har leia til ei eksplosiv vekst i dataprogram og applikasjonar. 

<a name=buss></a>
Denne sekvensielle tilnærminga til databehandling blir transportert gjennom eit system av databussar, med kontrollsignal som dirigerer aktivitetane i CPU-en basert på den dekoda instruksjonen. Harvard-arktitekturen, til dømes, nyttar seg av separate lagrings- og bussystem for instruksjonar og data, noko som potensielt aukar hastigheita på dataflyten og reduserer ventetida for operasjonane. 

Gjennom kontinuerlige forbetringar og innovasjonar i mikroarkitekturen - den fysiske implementeringa av settet med instruksjonar som CPU-en kan utføre - har moderne prosessorar blitt betydeleg mykje raskare og meir effektive.

Von Neumann-arkitekturen har ikkje berre fordelar. På grunn at delinga av minne for både instruksjonane og data, oppstår det som blir kalla Von Neumann-flaskehalsen; eit problem der hastigheita på dataflyten mellom prosessoren og minnet begrensar ytinga til systemet. Sidan begge operasjonane, henting av instruksjonar og lesing/skriving av data, må dele den same kommuniksjonskanalen, kan maskina oppleve ein flaskehals der hastigheita til prosessoren overgår minnebåndsbreidda. Dette har leia til forskning og utvikling av andre arkitekturar, som Hardvard-arkitekturen der instruksjonar og data er lagra i separate minneblokker, samt forskjellege cache-strategiar for å minimere ventetida forbunde med minneaksess.


### Kjernekomponentar i ei datamaskin
#### CPU - Central Processing Unit
CPU, eller prosessoren, er hjernen til datamaskina og ansvarleg for å tolke og utføre dei fleste av instruksjonane frå dei andre komponentane og programvara til datamaskina. Den består av fleire nøkkelkomponentar:
- **Register:** Små lagringsområde som blir brukt for å utføre operasjonar og midlertidig halde på data.
- **Kontrolleining (CU):** Dirigerer operasjonane til CPU-en ved å hente, tolke og utføre instruksjonar.
- **Aritmetisk/logisk eining (ALU):** Utfører matematiske, logiske og avgjersleoperasjonar.


#### Minne
Det finst ulike typar minne i ei datamaskin: 
- **RAM (Random Access Memory):** Voltatilt* minne som blir brukt for å lagre data og instruksjonar som ei datamaksin treng medan den er i bruk.
- **ROM (Read-Only Memory):** Ikkje-voltatilt minne som inneheld essensiell data som ikkje blir endra, ofte brukt for oppstartsprosessar.
- **Cache:** Hurtigminne som lagrar kopiar av data frå ofte brukte hovudminneområde.
- **Virtuelt minne:** Ein metode for å utvide det fysiske minnet ved å bruke ein del av harddisken som om det var RAM.

Minnehierarkiet, frå hurtig og dyr cache til treigare og billigare RAM og lagring, er essensielt for å balansere kostnad og yting i maskina. "Random Access" refererer til evna til å få tilgong til dataelement direkte og i vilkårleg rekkefølgje, noko som er kritisk for effektiviteten til mange operasjonar.

<a name="voltatilt"></a>
> *Voltatil: I datamaskinkontekst refererer det til ein type minne som krev straum for å behalde lagra informasjon. Ettersom RAM er voltatilt, tyder det at alt som er lagra der, går tapt dersom/når datamaskina blir skrudd av.


#### I/O - Input/Output
I/O-einingar tillét ein datamaskin å kommunisere med omverda og brukaren. Dei inkluderer alt frå tastatur og mus, til skjermar, printarar og [nettverkskort](#nettverkskort).

Desse einingane kommuniserer med CPU og minne gjennom I/O-bussar, som er dataspor som fraktar informasjonen fram og tilbake. Desse bussane er avgjerande for datamaskina si evne til å overføre data til og fra I/O-einingar, og effektiviteta av desse bussane påverkar direkte ytinga til systemet. 


### Instruksjonssettarkitektur

Eit instruksjonssett er ei samling av kommandoar som CPU-en kan gjenkjenne og utføre. Det definerer dei lågnivå operasjonane som prosessoren kan utføre og spelar ei kritisk rolle i CPU-funksjonalitet. Desse kommandoane er grunnlaget for all programvare, sidan høgare-nivå språk til slutt må oversettje til desse instruksjonane for at CPU-en skal kunne utføre dei. 

RISC (Reduced Instruction Set Computer) og CISC (Complex Instruction Set Computer) er to forskjellege typar arkitekturar basert på instruksjonssett. RISC-arkitektur fokuserer på å ha eit mindre og meir optimisert sett av instruksjonar som ofte kan utførast i éin klokkesyklus. CISC derimot, inkluderer eit breiare og meir komplekst sett av instruksjonar som kan utføre meir kompliserte oppgåver pr instruksjon, men kan kreve fleire klokkesyklusar for å utføre. 

Ein typisk instruksjonssettarkitektur inneheld fleire typar instruksjonar:
- **Aritmetiske instruksjonar:** Utfører matematiske operasjonar som addisjon og subtraksjon.
- **Kontrollinstruksjonar:** Endrar sekvensen av utførte instruksjonar, f.eks. ved løkker og betinga sprang.
- **Dataoverføringsinstruksjonar:** Flyttar data mellom register, mellom minne og register, eller mellom I/O-einingar og register.

CPU-en utfører instruksjonar gjennom ein syklus som inkluderer henting av instruksjonen frå minnet, dekoding for å forstå instruksjonen, gjennomføring av dei naudsynte operasjonane, og til slutt lagring av resultatet. Pipelining er ein teknikk der CPU-en byrjar utføringa av ein ny instruksjon før den forrige er fullført, noko som lignar på eit samleband, slik at fleire instruksjonar kan vere under behandling samstundes. Dette aukar ytinga ved å redusere ventetida mellom instruksjonar

Mikroarkitekturen refererer til den spesifikke måten ein CPU er designa på for å implementere eit instruksjonssett. Det er mikroarkitekturen som avgjer korleis instruksjonane faktisk blir utført - timing, pipelining, typar og antal register, og andre lavnivå operasjonsdetaljar.

Medan instruksjonssettarkitekturen forblir konstant, kan mikroarkitekturen endrast for å forbetre ytinga. Til dømes, ved å forbetre pipelining, auke storleiken på cache, eller leggje til funksjonar som out-of-order execution, kan ein prosessor gjere meir arbeid pr klokkesyklus utan å endre det grunnleggjande settet med instruksjonar det støttar. 

<a name="del4"></a>
## 4. Mikroarkitektur
### Design og implementasjon av ein CPU
Mikroarkitekturen i ein CPU refererer til den fysiske realiseringa og organiseringa av prosessorens funksjoner, som må være i stand til å utføre instruksjonssettarkitketuren. Den styrer korleis instruksjonane blir handtert, behandla og utført på maskinvarenivå, og er essensiell for å bestemme ytinga og effektiviteten til prosessoren. 

Hjartet av CPU-en består av fleire kritiske komponentar:
- **Rekneregister:** Små hurtige lagringsområde som blir brukt for å midlertidig halde på data og instruksjoner som er under behandling.
- **Kontrolleiing (CU):** Dirigerer operasjonen av CPU-en ved å hente instruksjonar frå minnet, dekode dei og sende naudsame signal til ALU og andre komponentar for å utføre desse instruksjonane.
- **Aritmetisk logisk eining (ALU):** Utfører aritmetiske og logiske operasjonar.
- **Hurtigbufferminne (Cache):** Raskt minne som lagrar kopiar av ofte brukt data frå hovudminne for å redusere tida det tek for å hente den.

Desse komponentane er organisert på ein slik måte at dei jobbar saman i ein koordinert sekvens for å utføre komplekse instruksjonar raskt og effektivt. 

CPU-design inkluderer utvikling av ein instruksjonssyklus og datapath som saman legg føresentader for korleis instruksjonar skal bli henta, dekoda, utført og korleis resultat blir lagra. Datapathen er den faktiske "stien" dataen flyt gjennom. Dekodinga av instruksjonar er ein kritisk del, ettersom den overset instruksjonar til signal som fortel dei ulike delane i CPU-en kva dei skal gjere. 

Implementasjon av mikroarkitekturen på silisium inneber bruk av halvleiarteknologi for å lage integrerte kretsar. Dei grunnleggjande byggjesteinane er transistorar, som fungerer som elektroniske brytarar. Desse transistorane blir kombinert for å lage logiske portar som AND, OR og NOT, som igjen byggjer opp meir komplekse funksjonar som ALU, register og kontrolleiningar. 

Desse komponentane blir nøye organisert på ein silisium-chip gjennom ein prosess som blir kalla VLSI-design (Very Large Scale Integration). Denne prosessen inneber skapinga av mikroskopiske strukturar som formar dei individuelle funksjonelle einingane i CPU-en, som deretter blir testa og optimalisert for yting og energieffektivitet.


### Pipeline-prosessering og optimalisering av yting
Pipelining er ein teknikk der fleire instruksjonar overlapper i utføringa ved å dele instruksjonshandlinga i fleire steg eller "stages". Ein CPU-pipeline liknar eit samleband i ein fabrikk, der kvar del av ein instruksjon  blir behandla i eit separat trinn av pipeline. Dei vanlegaste trinna er henting, dekoding, utføring, minnetilgong og skriv tilbake (fetch, decode, execute, memory access og write back). Medan ein instruksjon blir utført, kan neste instruksjon bli dekoda, og neste etter der bli henta, etc. Dette aukar effektiviteten. 

Fordelar: 
- **Auke i throughput:** Ved at fleire instruksjonar blir behandla samstundes, aukar antalet fullførte instruksjonar pr tidseining.
- **Betre nytta ressursar:** Sidan kvart trinn i pipeline er aktivt og produktivt, tyder det at ressursane til CPU-en (td. ALU eller minnetilgongseiningar) konstant er i bruk.

Ulemper:
- **Hazards:** Dette er problem som oppstår når fleire instruksjonar som er i pipeline påverkar kvarandre. Det finst tre hovudtypar av hazards: data hazards, control hazards og structural hazards.
- **Minimering av hazards:** For å handtere desse problema, blir det implementert teknikkar som pipeline scheduling som omorganiserer rekkefølgja av instruksjonar og out-of-order execution, noko som tillét instruksjonar etter ein hazard å fullføre før instruksjonen som forårsaka hazard.

For å optimialisere ytinga, kan ein bruke følgjande teknikkar:
- **Prediksjon av forgreiningar:** Dette hjelp med å reduserer ventetida ved å gjette vegen ei forgreining vil ta, og lastar inn instruksjonar på forhand basert på denne gjetninga.
- **Superskalær arkitektur:** tillét at fleire instruksjonar blir henta, dekoda og utfør samstundes, noko som ytterlegare aukar gjennomstrømmningsraten.
- **Parallellitet på fleire nivå:** Inkluderer teknikkar som multithreading, kor ein enkelt CPU kan utføre fleire threads parallelt, og multicore-prosessering, der fleire CPU-kjerner i ein enkelt chip jobbar parallelt for å behandle fleire oppgåver samstundes.

Samla sett forbetrar desse teknikkane ytinga ved å maksimere utnyttinga av ressursar og redusere ventetida, noko som er avgjerande for å møte dagens krav til datamaskinkraft og effektivitet. 

### Kontrolleining og aritmetisk/logisk eining
Kontrolleininga (CU) er ein kritisk komponent i CPU-en som styrer og koordinerer aktiviteten til dei andre komponentane i prosessoren. Hovudfunksjonen til CU-en er å tolke instruksjonane som blir henta frå minnet og deretter generere dei naudsynte signala for å utføre desse instruksjonane. Den styrer dataflyten inn og ut av prosessoren og sørger for å at dei riktige operasjonane blir utført på dei riktige tidspunkta. 

For å utføre instruksjonar, bryt CU-en dei ned i mindre trinn som vert kalla mikrooperasjonar. Desse inkluderer operasjonar som er å flytte data mellom register, utføre aritmetiske og logiske operasjonar, og kommunisere med minnet. Mikrooperasjonar er grunnleggjande handlingar som er lette å handtere for hardwaren som tilhøyrer CPU-en. CU-en sikrar at desse operasjonane blir utført i korrekt sekvens for å fullføre den opprinnelege instruksjonen. 

ALU-en er den delen av CPU-en som utfører alle dei matematiske berekningane og logiske operasjonane. Når det er naudsynt med bereknigar, sender CU-en data og operasjonstype til ALU-en, som deretter utfører operasjonen og sender resultatet tilbake, anten for vidare behandling eller for lagring i minnet.

Samspelet mellom CU og ALU er avgjerande for operasjonane CPU-en skal utføre. CU-en gir instruksjonar og kontrollerer handlingane til ALU-en ved å fortelje kva for nokre operasjonar som skal utførast og når. ALU-en mottek og utfører desse operasjonane, og returnerer resultat til CU for vidare handling. Denne tilbakekoplingsløkkja er grunnleggjande for alle funksjonane til prosessoren og evna til å utføre komplekse instruksjonar. 

Moderne CPU-design står ovanfor fleire utfordringar, spesielt med tanke på straumforbruk og varmeproduksjon. For å takle desse utfordringane bruker både CU og ALU avanserte teknikkar for straumforsyning, som å reduserer klokkehastigheita eller spenningsnivåa når maksimal yting ikkje er naudsynt. Dei kan også bruke meir sofistikert kjøleteknologi og termisk design for å handtere varme. I tillegg bidreg finare produksjonsteknologiar til å redusere straumforbruket ved å tillate lågare spenningsnivå og redusere lekkasjestraumar i transistorar.


<a name="del5"></a>
## 5. Minnehandtering og lager
### Typar minne
### RAM - Random Access Memory
RAM er hovudminnet til ei datamaskin og fungerer som ein midlertidig lagringsplass for data og program som er aktive eller i bruk. Det er "tilfeldig tilgang" fordi CPU-en har evna til å få tilgong til data lagra i kva som helst del av minnet direkte og i kva som helst rekkefølgje, samanlikna med sekvensiell tilgong som i magnetband.

Det finst to hovudtypar RAM: 
- Statisk RAM (SRAM): Dette er raskare og meir påliteleg enn DRAM, men er også dyrare. SRAM brukar fleire transistorar pr minnecelle og held på dataen så lenge det er tilførsel av straum. Det blir ofte brukt i cache pga den høge hastigheita.
- Dynamisk RAM (DRAM): Dette er den vanlegaste typen RAM og blir brukt som hovudminnet i dei fleste datamaskinar. DRAM lagrar kvar bit av data i ein separat kondensator innanfor ein integrert krets, som må friskast opp periodisk for å behalde dataen. DRAM er treigare enn SRAM, men det er billegare og kan lagre meir data pr minnechip.

#### ROM - Read Only Memory
ROM er ein type ikkje-flyktig minne som beheld informasjonen sin sjølv når straumen er av. Det er ofte brukt til å lage firmware eller oppstartsprogramvare (BIOS/UEFI) som maskina treng for å starte opp. ROM-innhald er vanlegvis programmert av produsenten og det er ikkje meint at brukaren skal endre dette. 

#### Cache
Cache er ein liten mengde hurtig, men dyr, SRAM som blir brukt av CPU-en til å redusere gjennomsnittleg tilgongstid til data frå hovudminnet. Cacheminne fungerer som ei mellommlagringseining for ofte brukt data, slik at CPU-en kan unngå den tidskrevande prosessen med å hente data frå det treigare hovudminnet. 

Cacheminne er organisert i ulike nivå:
- **L1-cache:** Dette er første og raskaste cache, ofte bygd direkte inn i prosessorkjerna. Den har svært låg latens og er designa for å gi rask tilgong til den mest kritiske dataen.
- **L2-cache:** Ligg ofte på same chip som CPU-en, men kan vere ein separat cache for kvar prosessorkjerne. Den er større enn L1-cache, men har også litt høgare latens.
- **L3-cache:** Denne cachen er vanlegvis delt mellom kjernene på ein CPU og er større enn både L1 og L2, men har større latens. L3-cache hjelp til med å redusere belastninga på hovudminnet ved å lagre data som er rimeleg ofte brukt.

Desse ulike nivåa av cache arbeider saman for å forbetre den generelle ytinga til datamaskina ved å redusere den tida det tek for prosessoren å få tilgong til dataa og instruksjonar den treng for å utføre oppgåver.

### Minnehierarki og lagringsteknologi
Minnehierarkiet i ei datamaskin er eit strukturert oppsett av minne og lagringseiningar som varierer i hastigheit, storleik og avstand til CPU-en. Øvst i hierarkiet finn ein CPU-registera som er den raskaste formen for minnelagring, men også den med minst kapasitet og direkte tilkopla til CPU-en. Deretter føl cache-minnet (L1, L2 og L3), som fungerer som midlertidlig lagringsplass for å minimere antal langsame minneaksessar som CPU-en må utføre. 

Under cache ligg hovudminnet, eller RAM, som har større kapasitet enn registera og cache, men er treigare og framleis [voltatilt](#voltatilt). Lagringseiningar som SSD (Solid State Drives) og HDD (Hard Disk Drives) utgjer neste nivå i hierarkiet. Desse er betydeleg treigare enn RAM, men tilbyr mykje større lagringskapasitet og er ikkje-flyktige, noko som tyder at dei held på dataen sjølv om systemet er skrudd av.
- Solid State Drives (SSD): SSD brukar flash-basert minne, noko som er raskare, meir påliteleg og meir energi effektivt enn tradisjonelle harddiskar. Dei har ingen bevegelige delar, noko som reduserer risikoen for mekaniske feil og gjer dei meir holdbare. SSD er derimot dyrare pg GB enn HDD.
- Harddiskar (HDD): Disse einingane lagrar data magnetisk på roterande plater. Sjølv om dei er treigare enn SSD, spesielt når det gjeld tilgongstid og dataoverføringshastigheit, tilbyr HDD meir lagringskapasitet for mengane og er derfor eit meir kostnadseffektivt alternativ for mykje lagring.
- Optisk lagring: Dette inkluderer medier som CD, DVD og Blu-ray-plater. Sjølv om dei er relevante for distribusjon av media og arkivering, har optisk lagrning blitt mindre populær som primær lagringsløysing på grunn av avgrensingar i kapasitet og hastighet samanlikna med SSD og HDD.


![alt text](https://runestone.academy/ns/books/published/welcomecs2/external/ComputerArchitecture/Images/Memory-Hierarchy.jpg)

Minnehierarkiet påverkar systemet si generelle yting på grunn av dei hastigheitsskilnadane mellom dei ulike lagringseiningane. Ein CPU kan utføre operasjonar mykje raskare enn det er mogleg å lese og skrive til RAM, som igjen er mykje raskare enn sekundære lagringseiningar som SSD og HDD. Derfor brukar ein hurtige, men dyre og små minneeiningar (som cache) til å lagre data og instruksjoner som CPU-en treng umiddelbart, medan større og treigare einingar blir brukt til å lagre større mengder data som ikkje krever rask tilgong.

Balansen mellom hastigheit og kapasitet er avgjerande for optimal yting. For mykje fokus på kapasitet kan føre til ein flaksehals dersom data ikkje blir flytta raskt nok til og fra lagringseiningane. På andre sida, hvis systemet har for mye rask, underutnytta minne, kan det vere eit spørsmål om ineffektiv ressursbruk. Moderne system brukar ein kombinasjon av RAM, SSD og nokre gonger HDD for å skape ei balansert og kostnadseffektiv løysing.

### Virtualisering og verning av minne
Virtuelt minne er ein teknikk som blir brukt av OS for å gi applikasjonar inntrykk av at det er meir minne tilgjengeleg enn det som faktisk eksisterer. Dette kan ein oppnå ved å  bruke ein del av lagringsplassen på harddisken som om det var ekstra RAM. Dette tillét OS handtere større program eller fleire program samstundes enn det ville vært mogleg med berre den fysiske RAM. 

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
Inngong/utgongsarkitekturen (I/O-arkitekturen) er eit kritisk subsystem i ei datamaskin som handlar om korleis data flyttar seg mellom CPU-en og dei eksterne einingane som skjermar, tastatur, [nettverkskort](#nettverkskort) og lagringseiningar. Denne arkitekturen fungerer som ei bru som koblar den raske og komplekse verda til CPU-en med den treigare og mer varierte verda til periferiutstyr. I/O-arkitekturen må handtere ein stor variasjon i einingshastigheiter og kommunikasjonsprotokollar.

Det finst fleire metodar for å kontrollere I/O-operasjonar:
- Programstyrt I/O: Dette er den enklaste metoden der CPU-en aktivt ventar på og sjekkar statusen til ei I/O-eining. Dette er ikkje effektivt sidan det bind CPU-en til I/O-prosessen og kan føre til mykje unødvendig venting.
- Avbruddsstyrt I/O: Her blir CPU-en frigjort til å utføre andre oppgåver medan I/O-operasjonen pågår. Når I/O-operasjonen er ferdig, sender eininga eit avbrudd til CPU-en, som da kan handtere overføringa av data.
- Direkte minnetilgong (DMA): DMA tillét I/O-einingar å sende og motta data direkte til og frå hovudminnet, utan konstant overvåkning frå CPU-en. Dette frigjer CPU-en frå å måtte kopiere data frå ein buffer til ein annan og forbetrar ytinga til systemet betydeleg.

Datamaskinar opererer i to modusar: brukermodus og kernelmodus (også kalla supervisormodus). Brukermodus er der vanlege appliksajonar køyrer; desse applikasjonane har begrensa tilgong til systemressursar og kan ikkje direkte utføre I/O-operasjonar. Kernelmodus er der kjerna til OS køyrer og har full tilgong til maskinvara og kan utføre I/O-operasjonar.

Når ein applikasjon i brukermodus treng å utføre ein I/O-operasjon, må den gjere eit systemkall til OS, som då kan bytte til kernelmodus for å utføre I/O-operasjonen på ein sikker og kontrollert måte. Dette skjer for å beskytte systemet mot skadeleg eller feilaktig kode og for å sikre at I/O-operasjonane ikkje forstyrrar kvarandre, noko som er essensielt for stabilitet og sikkerhet i systemet.


### Bussystem og kommunikasjon
Kommunikasjon over bussystemet involverer overføring av data, adresser og kontrollsignal:
- Når CPU-en treng å lese data frå minnet, sender den ei adresse over adresse[bussen](#buss) til minnet.
- Minnet svarar ved å sende den førespurte dataen over databussen tilbake til CPU-en.
- Kontrollbussen styrar prosessen, for eksempel ved å signalisere om det er ein lese- eller skriveoperasjon.

I I/O-kommunikasjon er det mange protokollar og standardar som sørgjer for at ulike einingar kan jobbe saman. Nokre av dei viktigaste inkluderer: 
- USB (Universal Serial Bus): Ein vanleg grensesnittstandard for å koble til periferiutstyr til ei datamaskin.
- SATA (Serial ATA): Eit bussgrensesnitt for å koble til masselagringseiningar som harddiskar og SSDar.
- PCIe (Peripheral Component Interconnect Express): Ein standard for høghastigheitskommunikasjon mellom hovudkort og visse hardware-einingar som grafikkort og [nettverkskort](#nettverkskort).

Bandbreidde og latens er to viktige faktorar som påverkar ytinga til bussystemet:
- Bandbreidde: Dette refererer til mengden data som kan overførast over bussen i ein gitt tidsperiode, ofte måla i gigatransaksjoner pr sekund (GT/s) eller gigabyte pr sekund (GB/s).
- Latens: Tida det tek for eit signal å reise frå sender til mottakar over bussen.

Høg bandbreidde og lav latens er ideelle for å maksimiere gjennomstrøymninga og forbetre den generelle ytinga til datamaskina. Moderne bussystem som PCIe har utvikla seg for å tilby høg bandbreidde og låg latens for å støtte raskare dataoverføringar og meir effektiv kommunikasjon mellom CPU-en og andre systemkomponentar.



### Eksempel på I/O-einingar
I/O-einingar er kategorisert basert på deira funksjon og bruk:
- Lagringseiningar: Dette inkluderer HDD, SSD, USB-flashstasjonar og optiske stasjonar (CD/DVD/Blu-ray). Dei lagrar data og programvare for langsiktig bruk.
- Peikeeiningar: Mus og touchpads tillét brukeren å interagere med datamaskinen sitt grafiske brukergrensesnitt.
- Tastatur: Blir brukt for inntasting av tekst og kommandoar til datamaskina.
- Skjermar: Viser grafisk og tekstbasert informasjon til brukaren, enten via LCD, LED eller andre skjermteknologiar.
- Skrivarar: Gjer digital informasjon om til fysiske dokument.

Eksterne I/O-einingar som skrivarar og [nettverkskort](#nettverkskort) kommuniserer med CPU-en gjennom ulike portar og bussar som USB, Ethernet eller via trådlause tilkoblingar som WiFi eller Bluetooth. Drivere er spesialiserte programvarer som gjev OS instruksjonar om korleis det skal kommunisere med maskinvaren. Den sørgjer for at kommandoen som blir sendt frå CPU1en blir omgjort til ei form som eininga kan forstå og handle etter.

Interne I/O-einingar HDD og SSD er kopla direkte til hovudkortet via internbussen, som SATA eller PCIe. Dei er integrert i funksjonaliteten til systemet og fungerer som det primære lagringsmediumet, der OS, applikasjonar og brukerdata befinn seg. 

- Tastetrykk: Når ein tast blir trykka på tastaturet, blir det generert eit elektronisk signal som blir sendt til CPU-en via I/O-bussen. OS mottek signalet som ei avbryting, tolkar kva for ein tast det gjeld og produserer den tilsvarande karakteren på skjermen eller utfører ein tilknytta kommando.
- Filskriving: Når ei fil skal lagrast på ein harddisk, sender OS ein kommando til lagringskontrolleren med informasjon om fildataen og kvar dei skal lagrast. Kontrolleren utfører skriveoperasjonen ved å organisere dataen i dei adresserbare områda i lagringseininga. Under prosessen brukar ein både programvare (filer og filsystem) og maskinvare (skrive-/lesehovud i ein HDD eller flashminnekontrollarar i ein SSD) for å sikre korrekt lagring og henting av data. 


<a name="del7"></a>
## 7. Parallelle datamaskinar
### Typar av paralelle arkitekturar
I ei verden der datamengen og kompleksisteten i berekningar fortsetter å vekse, har behoved for raskare og meir effektive databehandlingsmetodar aldri vore større. Paralelle datamaskinar møter dette behovet ved å utføre fleire regningar samstundes, i staden for sekvensielt. Dette kan ein oppnå gjennom ei rekke arkitekturar der kvar har sine unike eigenskapar og anvendingsområde. Desse arkitekturtypane kan kategoriserast etter korleis dei organiserer data- og instruksjonsstraumar, og er fundamentalt forskjellege i måten dei handterer operasjonar på.

Den mest grunnleggjande klassifiersinga av parallelle arkitekturar kjem fra Flynn-s taksonomi, som deler dei inn i fire distinkte kategorier basert på antalet instruksjons- og datastraumar dei handterer på same tid. Disse kategoriane er SISD, Multiple Data Streams (SIMD), Multiple Instruction Streams, Single Data Stream (MISD), og Multiple Instruction Streams, Multiple Data Streams (MIMD). Kvar kategori representerer ein unik tilnærming til parallelle berekningar og åpner for forskjellige moglegheiter og utfordringar når det gjeld implementering og yting.

- SISD - Single Instruction Stream, Single Data Stream: Dette er den tradisjonelle seriemodellen der éin prosessor utfører éin instruksjon om gongen på eit dataelement om gongen. Eit typisk eksempel er den klassiske [Von Neumann](#vonneumann)-arkitekturen.
- SIMD - Single Instruction Stream, Multiple Data Stream: SIMD-maskinar kan utføre same instruksjon på mange dataelement samstundes. Dette er nyttig for oppgåver som krever dei same operasjonane på store datasett, som grafikkbehandling og vitenskaplege simuleringar. Grafikkprosessorar (GPUs) er eit eksempel på SIMD-arkitektur.
- MISD - Multiple Instruction Stream, Single Data Stream: Denne arkitekturen er sjeldan brukt og litt av ein teorietisk kuriositet, der fleire instruksjonar opererer på same data. Eit hypotetisk brukseksempel kan vere feiltolerante system der fleire prosessorar køyrer forskjellege algoritmar på same data for å sjekke feil. 
- MIMD - Multiple Instruction Stream, Multiple Data Stream: MIMD-system har mange prosessorar som arbeider uavhengig av kvarandre, kvar med sin eigen instruksjonsstraum og datasett. Dette er vanleg i moderne fleirkjerneprosessorar og distribuerte system kor fleire prosessorar kan jobbe med forskjellege oppgåver samstundes.

Innan SIMD-arkitekturen, er vektormaskinar sentrale aktørar. Desse systema er optimalisert for å utføre operasjonar på vektorar av data med ein enkel instruksjon, noko som er ideelt for oppgåver som krever einsartet behandling av datakolleksjonar. Ved å utnytte vektormaskinar kan berekninger i applikasjonar som grafikkbehandling og vitenskapelege simuleringar bli utført raskare og meir effektivt.

Vektormaskinar er ein type datamaskinarkitektur som er spesielt utforma for å utføre matematiske operasjonar på vektorar -  som er ein sekvens av data - svært raskt og effektivt vha SIMD prinsipp. Denne arkitekturen er spesielt godt eigna for vitenskaplege og tekniske berekringar som krever tung dataflyt og numeriske operasjonar som vektoraddisjon eller skalarprodukt. 

Ei vektormaskin har eit sett med vektorregister som kan lagre fleire dataelement og ei vektoreining som kan utføre ein operasjon på alle elementa i eit vektorregister på ein gong. Dette reduserer antal operasjonar som må bli utført sekvensielt og aukar datagjennomstraumninga betrakteleg. Td, i staden for å utføre ein addisjon mange gonger for kvart par av tal i to lister, vil ei vektormaskin utføre addisjonen på alle para samstundes.

Bruken av vektormaskinar var meir framståande i tida før moderne fleirkjenrneprosessorar og parallell databehandling vart vanleg. Dei blei brukt i superdatamaskinar og var sentrale i forskning og industrielle applikasjonar som krev stor berekningskraft, som aerodynamiske simuleringar, vermodellering, og i ulike typar av dynamiske systemanalysar. Sjølv om vektormaskinar ikkje lenger er så vanlege, lev konsepta og teknikkane som vart innført videre i moderne vektorprosessering og GPU-er som ofte anvender SIMD-arkitektur for å oppnå høg yting i grafikkrendering og andre beregningsoppgåver.

Arrayprosessorar, ofte referert til som SIMD-arrayprosessorarm er ei anna form for spesialiserte datamaskinar som er designa for høy yting parallell databehandling, lik vektormaskinar, men med ei meir distribuert tilnærming til databehandlinga. Dei består av eit stort antal prosesseringseiningar, eller "element", ordna i eit grid-liknande mønster, og kvar prosesseringseining utfører den same operasjonen samstundes på forskjellege dataelement. 

I ein arrayprosessor kan dataen vere organisert i ei matrise, og kvar prosessor i arrayet kan til dømes utføre ein operasjon på eit tilsvarande element i matrisa. Denne parallelliteten gjer det mogleg for svært effektiv databehandling, spesielt for oppgåver som naturleg kan delast opp i mange mindre, repeterande operasjonar - som biletbehandling, lydanalyse og visse former for numeriske simulieringar som krev matriseoperasjonar eller parallell behandling av store datasett.

Fordelen med arrayprosessorar ligg i evna deira til å redusere tida det tek for å utføre store mengder av repeterande berekningar. Sidan kvar prosessor i arrayet jobbar uavhengig av dei andre, men likevell i synkronisert fasjon, kan arrayprosessorar raskt utføre operasjonar over omfattande datastrukturar, noko som gjer dei ideelle for spesifikke typar algoritmar og appliksasjonar. 

Historisk sett har arrayprosessorar vore brukt i spesielle-formåls-datamaskinar for oppgåver som krev høg parallellyting. I moderne databehandling finn ein liknande konsept i bruk i GPU-ar, der hundrevis av kjerner kan jobbe på ulike delar av eit problem samstundes, og i distribuerte databehandlingsplattformar som brukar eit nettverk av datamaskinar for å utføre store berekningar parallelt


### Multithreading og multiprocessing
Medan arrayprosessorar representerer ei fysisk form for parallellitet ved å ha mange prosesseringseiningar som jobbar samstundes på forskjellege delar av ei datamengde, representerer multithreadding ei logisk form for parallellitet der fleire trådar kan køyrast på ein eller fleire CPU-kjernar for å forbetre utnyttinga av ressursar og gjennomstraumninga. Arrayprosessering aukar effektiviteten gjennom maskinvare, med mange prosessorar som jobbar parallelt, medan multiprosessering gjer det gjennom programvare ved tillate ein enkelt CPU-kjerne å handtere fleire oppgåver nesten samstundes.

Multithreading er ein teknikk som tillét ei enkelt CPU-kjerne å køyre fleire trådar (nærast sjølvstendige sekvensar av instruksjonar) samstundes. DEtte kan auke effektiviteta og ytinga ved at CPU-en kan bytte til ein anna tråd medane den andre ventar på data frå minnet eller fullføring av I/O-operasjonar, til dømes. Dette sørgjer for betre utnytting av prosessoren ved å redusere perioden der den ellers ville vore inaktiv. OS styrer tidsdelinga mellom dei ulike trådane, slik at kvar får køyretid på CPU-en. 

Multiprocessing derimot refererer til til bruk av to eller fleire sjølvstendige prosessorer innanfor eit enkelt datamaskinsystem for å utføre fleire oppgåver parallelt. Kvar prosessor jobbar med si eiga oppgåve eller fleire oppgåver i eit fleirtråda miljø. Dette aukar ytinga ved at fleire prosessorar kan jobbe på forskjellege delar av eit problem eller handtere fleire uavhengige oppgåver samstundes.
- SMP - Symmetrisk multiprosessering: I SMP-system har alle prosessorane tilgong til eit felles hovudminnes og I/O-ressursar, og OS behandlar alle prosessorane på same måte. Dette forenklar programmeringa og systemadministrasjonen, men kan også føre til flaskehalsar hvis mange prosessorar forsøkjer å få tilgong til sei same ressursane samstundes.
- AMP - Asymmetrisk Multiprosessering: AMP-systemer tildeler forskjellege roller eller oppgåver til kvar prosessor. Til dømes kan ein prosessor handtere I/O-operasjonar medan ien annan handterer brukar applikasjonar. Dette kan optimalisere utinga for bestemte applikasjonar, men kan vere meir komplekst å administrere og programmere for.

Hyper-threading er ein teknologi utvikla av Intel som tillét ei enkelt prosessorkjerne å køyre to trådar samstundes. Dette kan ein oppnå ved å duplisere visse delar av prosessoren, som tilstandsinformasjon og programteljarar, medan dei deler på eksekvenseringsressursane* til kjernen. Resultatet er at OS of applikasjonane ser ut som det er fleire logiske kjerner tilgjengeleg, noko som kan forbetre ytinga i multitråda applikasjonar og miljø der det er mange parallelt køyrande oppgåver. Hyper-threading kan bidra til betre utnytting av prosessorkapasiteten ved å fylle yting. 

> Eksekvenseringsressursar: Dei maskinvarekomponentane som er naudsynte for å utføre instruksjonar. Td CPU-kjerner, register, ALU, CU, Cache, etc. 


### Skalering og parallell yting
Amdahl-s lov er et viktig prinsipp innan datavitskap som relaterer seg til begrensingane av forbetring av yting i parallellprosessering. Lova seier at den maksimale forbetringa kan bli oppnådd ved å leggje til fleire prosessorar er begrensa av den delen av programmet som må køyrast sekvensielt. Dersom ein del av eit program ikkje kan parallelliserast, vil ytinga til heile programmet i beste fall berre kunne forbetrast marginelt uansett kor mange ekstra prosessorar som blir lagt til. 

Skaleringseffektivitet i parallell databehandling refererer til korleis ytinga til eit system blir forbetra når antalet prosessorar blir auka. Ideelt sett skulle vi ønska lineær skalering, der å doble antal prosessorar også dobla ytinga. Imidlertid er det sjeldan man oppnår perfekt skalering på grunn av diverse overhead og flaskehalsar. Skaleringseffekten blir ofte dårlegare etter kvart som ein legg til fleire prosessorar. 

Nokre av dei vanlegaste flaksehalsane og former for overhead inkluderer:
- Synkroniseringskostnadar: Når trådar eller prosessar må vente på kvarandre for å få tilgong til delte ressursar, kan det oppstå betydeleg overhead.
- Kommunikasjonslatens: Tida det tek for data å bli overført mellom prosessorar kan bli ein betydeleg flaskehald, spesielt i distribuerte system.
- Minnebandbreidde: Begrensingar i kor raskt data kan flyttast til og frå minnet kan redusere dei potensielle forbetringane i yting frå parallellisering.

Det finst fleire programmeringsmodellar og rammeverk for å hjelpe utviklarar med å skrive parallell kode:
- OpenMP - Open Multi-Processing: Eit rammeverk som støttar fleirtråda programmering i C, C++ og Fortran, og som er utforma for å vere enkel å bruke for å skape parallellitet på delte minnesystem.
- MPI - Message Passing Interface: Ein standard og rammeverk for kommunikasjon mellom prosessar som kan køyre på same eller forskjellege maskinar, noko som gjer det ideelt for distribuerte system.

Effektiv parallell kode krev nøye overtenking av korleis arbeidet og data blir delt mellom prosessar, korleis ein unngår synkroniseringsproblem of korleis ein kan minimere kommunikasjon og synkroniseringsoverhead. Programmeringsmodellane tilbyr verkty og konstruksjonar for å hjelpe med desse aspekta, med krev framleis betydeleg innsikt og erfaring for å sikre kode som skalerer godt på parallell maskinvare.


<a name="del8"></a>
## 8. Operativsystem og maskinvaregrensesnitt
### Rolla til OS
Operativsystemet fungerer som ein mellommann mellom brukar applikasjonar og den fysiske maskinvara til datamaskina. Det er kritisk for funksjonaliteten, ettersom det styrer maskinvara og koordinerer utføringa av programvara. OS sørgjer for at applikasjonar har tilgong til maskinvara dei treng, utan at kvar applikasjon treng gå inneha kompleks kode for å handtere direkte maskinvareinteraksjon. Dette abstraksjonslaget gjer det mogleg for portabilitet av programvare mellom ulike maskinvareplattformer og handterer ressursdeling mellom prosessar og brukarar. 

Gjennom brukergrensesnittet som OS tilbyr, kan brukarar interagere med datamaskina. Dette kan variere fra ei enkel kommandolinje (CLI) - der brukarar skriv kommandoar - til eit grafisk brukargrensesnitt (GUI), som tillét interaksjon gjennom grafiske symbol, vindu og menyar. Brukergrensesnittet er avgjerande for brukervenlegheit og effektiviteten til korleis folk brukar datamaskinar ved å tilby ein tilgjengeleg og intuitiv måte å køyre appliksjonar og tilgong til systemressursar. 

OS rolle i programutføringa er essensiell. Når ein program skal køyrast, sørgjer OS for at programmet blir lasta inn i minnet, at det blir tildelt nok prosessortid og at det har naudsynte tillatingar. Det handterer også oppretting og administrasjon av prosessar og trådar, og sikrar at applikasjonar ikkje forstyrrar kvarandre ved å isolere dei i separate minneområde. I tillegg handterer OS I/O-operasjonar, både synkron og asynkron kommunikasjon med eksterne einingar, og gir filsystemtenester som tillét lagring og hentign av data på ein effektiv og organisert måte.


### Styring av ressursar og maskingvareabstraksjon
OS er ansvarleg for forvaltninga av ressursane til datamaskina, eit kritisk aspekt for å sikre at systemet opererer effektivt og rettferdig. Forvaltninga inkluderer tildeling og overvåknig av CPU-syklusar for å sørgje for at kva prosess får naudsynt prosessortid, styring av fysisk og virtuelt minne for å sikre at applikasjonar har plass til å køyre og data til å operere med, og koordinering av tilgong til lagringsplass for å oppbevare og hente data på ein sikker og effektiv måte.

Vidare handterer OS tildelinga av I/O-einingar, overvaker datastraumar og sikrar at einingatr som HDD, tastatur, mus og [nettverkskort](#nettverkskort) fungerer utan konfliktar. Dette inkluderer å handtere avbrot fra I/O-einingar, bufferhandtering og caching for å optimaliserer ytinga. OS brukar planleggjarar og algorimar for å balansere lasta, fordele ressursar dynamisk og handtere køar for ressursar som er i høg etterspurnad, alt for å maksimere gjennomstraumning og redusere ventetida.

OS tilbyr eit viktig abstraksjonslag mellom programvaren som køyrer på datamaskina og den underliggjande maskinvara. Denne abstraksjonen forenklaer utviklinga av programvare ved å skjule kompleksitetet i maskinvara og dei lågnivå operasjonane som vert kravd for å kommunisere direkte med den. I staden for å skrive kode som snakkar direkte med ein spesifikk type disk eller [nettverkskort](#nettverkskort), kan utviklarar bruke standardiserte appliksjonsprogrammeringsgrensesnitt (API) som OS tilbyr.

API fungerer som ein grensesnittkontrakt mellom programvaren og operativsystemet, som deretter overset desse kalla til dei naudsynte maskinvareoperasjonane. Dette tyder at utviklarar kan skrive kode som er portabel over ulike maskinvareplattformar og OS, og dei kan stole på at OS vil handtere detaljane i ressursforvaltning, prosess- og minnehandtering, og I/O-operasjonar på ein effektiv måte. Abstraksjonslaget tillét også at systemet kan oppdaterast eller endrast utan at programvaren som køyrer på toppen treng å blir omskriven, så lenge API-kontraktane forblir konsekvente.

<a name="drivar"></a>
### Drivarar og interruptshandtering
Einingsdrivarar er spesialiserte programvaremodular som fungerer som tolkar mellom OS og maskinvarekomponentane. Kvar einingsdrivar er skreddersydd for å handtere kommuniksasjonen med ei spesifikk maskinvareeining. Når OS gir ein kommando som skal utførast av ei hardwareeining, til dømes å skrive data til ein harddisk eller sende ein utskriftsjobb til ein printar, overset einingsdrivaren denne kommandoen til eit språk eininga forstår.

Drivarane er avgjerande for at OS skal kunne tilby eit standardisert grensesnitt for applikasjonar, uavhengig den varierte og komplekse naturen til ein spesifikk hardware. Uten drivarar måtte OS inneheldt direkte støtte for kvar enkelt hardwarekomponent, noko som hadde vore uoverkommeleg og gjeve det enorme spekteret av maskinvare som finst. 

Interrupts er signal sendt til CPU-en frå maskinvareeiningar eller programvare når ei hending som krev merksemd, oppstår. Desse signala fortel prosessoren at den må avbryte den noverande prosessen og utføre ei anna oppgåve umiddelbart. Til dømes, når data kjem fram via [nettverkskortet](#nettverkskort), vil kortet sende eit interrupt til CPU-en for å indikere at data burde handterast så snart som mogleg.

OS har ein interruptshandterar eller interrupt service routine (ISR), som prioriterer og handterer desse interruptsa. Når eit interrupt blir oppdaga, stoppar CPU-en den noverande prosessen (etter gjeldande instruksjon er fullført), lagrar tilstanden og køyrer ein førehandsbestemt ISR som behandlar hendinga. Etter at ISR er fullført, gjenopptek CPU-en den forrige prosessen. 

Dette systemet gjer det mogleg for effektiv handtering av hardwarehendingar, sikrar at data blir behandla i ei rettferdig og tidseffektiv rekkefølgje, og at prosessoren kan halde fram med si primære oppgåve med minimal forstyrring.



<a name="del9"></a>
## 9. Datamaskinnettverk
### Grunnleggjande nettverkskomponentar
I eit datanettverk er det fleire nøkkelkomponentar som spelar viktige roller i å fasilitere og administere kommunikasjon mellom einingar:
- Ruter: Rutarar er einingar som styrer trafikk mellom forskjellege nettverk. Dei analyserer informasjonen som blir sendt over nettverket og vel den beste veien for data å reise over internett eller intranett.
- Svitsj: Svitsjar blir brukt i eit nettverk for å kople saman ulike einingar på same nettverk og styrer dataen til rett mottakar ved å bruke MAC-adresser.
- Hub: Ein hub er ei enkel nettverkseining som koblar saman fleire datamaskinar eller andre nettverkseiningar, og fungerer som eit felles tilkoplingspunkt. Data send til ein hub vil bli formidla ut til alle portar, noko som reduserer effektiviteten.
- Bru: Bruer blir brukt til å kople saman to segment av eit nettverk og opererer på datalinklaget i OSI-modellen. Dei filtrerer nettverkstrafikk for å redusere kollisjonar og kan isolere trafikkproblem.
- Endepunkt einingar: Også kalla klent eller tener/server. Inkluderer datamaskinar, mobile og smarte einingar, servarar og alle andre gadgets som kan kople til nettverket for å sende og motta data.

Dataoverføring innan nettverk kan skje over ulike medier:
- Kabel: Ethernetkablar (td CAT5, CAT6) er dei mest vanlege kabla media og blir brukt for å kople einingar soman innan lokale nettverk. Fiberkablar brukar lys for å overføre data og tillét mykje raskare hastigheiter over lengre avstandar enn tradisjonelle koparkablar.
- Trådlaus: WiFi og Bluetooth er dei mest kjende trådlause teknologiane. WiFi blir ofte brukt for trådlause lokale nettverk (WLAN), medan Bluetooth er brukt for korte avstandar og personlege nettverk.

<a name="nettverkskort"></a>
Nettverkskort, eller Network Interface Cards (NICs), er maskinvareeiningar som let datamaskinar og andre einingar koble seg til eiit nettverk. I ein kabla konfigurasjon har NIC en port som kan tilkoblast nettverkskabelen. I ein trådlaus konfigurasjon, som WiFi, tillét NIC eininga å kommunisere via radiobølgjer. Kvar NIC har ei unik MAC-adresse som identifiserer eininga på lokalnettverket. OS på datamaskina samhandlar med NIC via ein [drivar](#drivar) som kontrollerer dataoverføringane og tolkar lågniva nettverkskommunikasjon for applikasjonane som køyrer på maskina.


### Datakommunikasjon og protokollar
Dataoverføring refererer til prosessen med å sende informasjon frå ei eining eller eit system til eit anna, gjenno ei form for kommunikasjonskanal. Dei grunnleggjande prinsippa for dataoverføring inneber signalering og moduleringsmetodar.
- Signalering: Dette er prosessen med å sende informasjon over kom.kanalar, anten det er via elektriske signal over kabel eller radiobølgjer i trådlause nettverk.
- Modulering: Dette er teknikken som blir brukt for å tilpasse digitale eller analoge signal slik at dei effektivt kan bli sendt over eit kom.medium. I digitale nettverk brukar ein ofte modulasjonsteknikkar som amplitude-modulasjon (AM), frekvens-modulasjon (FM) eller fase-modulasjon (PM) for å overføre data.

Protokollar i nettverkskommunikasjon er eit sett med reglar og konvensjonar for datautveksling mellom einingar. Dei sikrar at einingar frå forskjellege produsentar og med forskjellege OS kan kommunisere med kvarandre. Nokre viktige protokollar inkluderer:
- TCP/IP - Transmission Controll Protocol/Internet Protocol: Grunnlaget for datautveksling over internett, som sikrar at dataen når fram til riktig stad og i riktig rekkefølgje. 
- UDP - User Datagram Protocol: Ein enklare, tilstandslaus protokoll samanlikna med TCP, ofte brukt i situasjonar der hastigheit er viktigare enn pålitelegheit. 
- HTTP - Hypertext Transfer Protocol: Brukt for datakommunikasjon på WWW, definerer korleis meldingar blir sendt og mottatt i nettlesarar og webservarar.
- FTP - File Transfer Protocol: Brukt for overføring av filer mellom ein klient og ein server på eit nettverk.

Sikkerheit i datakom. er avgjerande, spesielt når det gjeld konfidensiell informasjon. Kryptering er prosessen med å kode data slik at berre autoriserte partar har tilgong og kan lese det. 
- SSL/TLS - Secure Sockets Layer/Transport Layer Security: Desse er kryptografiske protokollar som gjev sikker kommunikasjon over eit datanettverk. Dei blir ofte brukt for å sikre transaksjonar på nett, som online shopping og nettbank.
- Kryptering: Det er mange krypteringsalgoritmar og protokollar som blir brukt for å sikre at data som blir overført over usikre nettverk ikkje kan bli avlytta eller manipulert.

Sikkerheitsprotokollar som SSL/TLS brukar kryptering og autentisering for å sikre at kommunikasjonen mellom klienten og serveren er privat og at partane er dei dei gjev seg ut for å vere. Sikkerheit i nettverkskom. omfattar også andre tiltak som brannmurar, antivirusprogramvare og diverse overvakningssystem for å beskytte mot og oppdate ondsinna aktivitet.

### Nettverksarkitektur og infrastruktur
Nettverkstopologi refererer til den geografiske organiseringa av elementa i eit nettverk, inklusive nodar og sambindingar. Forskjellege topologiar har ulike fordelar og ulemper:
- Stjerne-topologi: I ein stjerne-topologi blir alle nodane (datamaskinar, skrivarar, etc.) direkte til ein sentral node, ofte ein svitsj eller hub. Dette tillét enkel installasjon og feilsøking, men dersom den sentrale noden feiler, kan heile nettverket gå ned.
- Ring-topologi: Nodane er kopla i sirkel. Data reiser i ein retning rundt ringen og passerer gjennom kvar node. Dersom ein node eller sambinding blir brutt, kan heile nettverket stoppe opp, med mindre det er implementert ein form for redundans.
- Buss-topologi: Alle einingar er kobla til ei sentral linje eller "buss". Dette var meir vanleg i eldre nettverk, men er sårbar for feil ettersom ein feil på bussen kan påvirke heile nettverket.
- Mesh-topologi: Kvar node er kopla til ein eller fleire andre nodar, noko som tyder at det er fleire moglege vegar data kan ta frå ein node til ein annan. Dette gjev høg redundans og pålitelegheit, men kan vere kostbart og komplekts å implementere.

Nettverksinfrastrukturen inneheld den fysiske og logiske delen av nettverket, samt dei sentrale tjenestene som held det funsjonelt:
- DNS - Domain Name System: Omset menneskevenlege domenenavn til IP-adreser som maskinvara kan forstå og rute.
- DHCP - Dynamic Host Config. Protocol: Deler ut IP-adresser til einingar på eit nettverk, noko som gjer det enkelt å leggje til nye einingar utan manuell konfig.
- Lagringsnettverk: Omfattar teknologi som SAN (Storage Area Network) og NAS (Network Attached Storage), som gjev nettverkstilkopla lagring for å forenkle datalagring og tilgong i store nettverk.

Internett er det globale systemet av samankopla datanettverk som brukar TCP/IP-protokollen for å lenke einingar over heile verda. Det er ope for alle og inneheld eit bredt spekter av offentleg tilgjengeleg informasjon.

Intranett derimot, er eit privar nettverk som nyttar internetteknologi, men som er begrensa til ein organisasjon. Dei tilbyr liknande tenester som internett, som websider og e-post, men innhaldet er avgrensa til medlem av organisasjonen og vanlegvis beskytta frå utenforståande med brannmur og andre sikkerheitstiltak. Intranett blir brukt til å dele informasjon, OS og tenester innanfor ein organisasjon på ein sikker og kontrollerbar måte.


<a name="del10"></a>
## 10. Framtidige trender
### Nye teknologiar på horisonten
Kvantedatamaskiner representerer eit radikalt avvik fra klassisk databehandling ved å nytte prinsipp fra kvantemekanikken. Medan tradisjonelle datamaskinar brukar bits som representerer anten 0 eller 1, opererer kvantedatamaskiner med kvantebits, eller qubits, som kan eksistere i fleire tilstandar samstundes gjennom eit fenomen kjent som superposisjon. I tillegg til superposisjon tillét kvantefletting qubits å vere korrelert på ein måte som ikkje finst i klassisk databehandling, noko som potensielt tillét kvantedatamaskiner å utføre mange berekningar parallelt.

Dette kan føre til enorm auke i  hastigheiter for visse typar berekningar, som faktorisering av store tall (viktig i kryptografi) og søk i databasar. Kvantedatamaskiner har også potensialet til å revolusjonere felt som materialvitskap og legemiddeldesign ved å nøyaktig simulere åtferda til atom og molekyl, noko som er ei ekstremt krevjande oppgåve for klassiske datamaskiner.

Utviklingen av AI-chips er eit svar på behovet for meir effektiv databehandling i kunstig intelligens og maskinlæring. Desse spesialiserte prosessorane, ofte referert til som nevrale nettverksprosessorar eller maskinlæringsakseleratorar, er designa for å optimalisere ytinga av algoritmar brukt i AI, som djup læring og nevrale nettverk.

AI-chips er i stand til å handtere parallelle berekningar og høg gjennomstraumning av data, noko som er essensielt for å trene og køyre komplekse nevrale nettverk. Dei er meir effektive enn generelle CPU-er for desse oppgåvene fordi dei er skreddersydd for matematiske operasjoner som er hyppige i AI, som tensor og matrise-multiplikasjoner. Desse chipsa blir stadig meir integrert i forbrukerelektronikk, datasenter, og ved kanten av nettverk (edge computing), og bidreg til raskare og meir effektiv AI-behandling i eit bredt spekter av applikasjonar, fra språkgjenkjenning til bildeanalyse.


### Påverknaden av datatryggleik og kryptografi
Framveksten av nye teknologiar som internett-tilkopla einingar (IoT), kunstig intelligens, og automatisering, fører med seg ein auke i trusler og utfordringer i cybersikkerheitslandskapet. Avanserte datasikkerheitstiltak blir naudsynte for å beskytte både infrastruktur og data mot ei stadig voksande rekkje cyberangrep. Dette inneber å designe framtidige system med innebygd sikkerheit frå grunnen av, kjent som "security by design", som inkluderer robust autentisering, autorisering, kryptering, og nettverkssikkerheitstiltak.

For å vere meir motstandsdyktige mot cyberangrep, vil framtidige system trenge å implementere avanserte teknikkar som automatisk trusseldeteksjon og respons, samt bruk av maskinlæring for å forutseie og forhindre angrep før dei skjer. Implementering av sikkerheitsoppdateringar og lappesikkerhet må også være dynamisk og i stand til å reagere raskt på nye sårbarheiter.

Kryptografi spelar ei kritisk rolle i å sikre kommunikasjon og informasjon, spesielt når det gjeld å beskytte mot avlytting og sikre integritet og autentisitet hos datamaskinar. Med framveksten av kvantedatamaskinar står mange tradisjonelle kryptografiske algoritmar, spesielt dei som er basert på faktorisering av store tal (som RSA) eller diskrete logaritmeproblem, overfor trusselen om å bli gjort forelda. Kvantedatamaskinar har potensial til å løyse desse problema på ein brøkdel av tida det tek for dagens beste superdatamaskinar.

Som svar på denne trusselen, blir det forska på kvantresistente kryptografiske algoritmar, nokon gonger referert til som post-kvantekryptografi. Desse algoritmene er designa for å vere sikre sjølv i ei verd der kvantedatamaskinar er vanlege. For eksempel utviklar forskarar algoritmar basert på problem ein antar er vanskelege for kvantedatamaskiner å løyse, slik som nettverkskoding og multivariate kryptografiske likningar.

I tillegg spelar kryptografi ein viktig rolle i utviklinga av sikre kommunikasjonsprotokollar som Quantum Key Distribution (QKD), som brukar prinsipp for kvantemekanikk for å garantere sikker nøkkelutveksling, en prosess som er grunnleggjende for all kryptert kommunikasjon.

For å møte desse og framtidige utfordringar, vil det vere essensielt med ei kontinuerleg utvikling og tilpassing av kryptografiske metoder som kan motstå nye truslar og bevare sikkerheita og privatlivet i den digitale tidsalderen.


### Etiske og samfunnsmessige utfordringare med teknologisk utvikling
Teknologiske framsteg, spesielt innan datainnsamling og -analyse, aukar bekymringene knytta til personvern. Smarte einingar, sosiale medium og big data-algoritmar kan samle inn og analysere personlege data på ein skala som tidlegare var uhøyrd, noko som gjev bedrifter og myndigheiter potensialet til å overvake, profilere og målrette individ på måtar som kan opplevast som inngripande. Samfunnet og lovgjevarar verda over responderer med nye regler og reguleringar, som EUs General Data Protection Regulation (GDPR), som tek sikte på å beskytte personopplysninger og gje individ kontroll over egen data.

Automatisering og kunstig intelligens bringer store endringar til arbeidsmarkedet. Medan nokre jobbar, spesielt dei som inneber repeterande eller forutsigbare oppgåver, står i fare for å bli automatisert bort, kan det også bli skapt nye jobbar i sektorar som teknologiutvikling, systemvedlikehold og dataanalyse. Det er ei aukande erkjenning at utdannings- og omskoleringssystem må tilpassast for å hjelpe arbeidstakarar med å tilpasse seg desse forandringane.

Teknologisk utvikling kan forsterke eksisterande sosiale og økonomiske ulikskapar gjennom det digitale skiljet – skilnaden mellom dei som har tilgong til moderne informasjons- og kommunikasjonsteknologi, og dei som ikkje har det. Dette skiljet kan sjåast globalt mellom ulike land, så vel som innad i land, mellom ulike samfunnslag. Ulik tilgong til teknologi påverkar utdanning, jobbmolegheiter og til og med tilgong til offentlege tenester.

Ansvarleg innovasjon handlar om å utvikle ny teknologi på ein måte som erkjenner etiske, sosiale, miljømessige og økonomiske konsekvensar. Dette inneber ei forplikting til openheit, inkludering og berekraft i utviklingsprosessen. Utviklarar og forskarar blir bedt om å engasjere seg med interessenter, inkludert publikum, for å forstå breiare samfunnseffekter av deira arbeid og å implementere designprinsipp som respekterer brukerane sine rettigheiter og velvære. Ved å fremje ansvarleg innovasjon, blir det sikra at teknologi ikkje berre driv fraover for sin eigen del, men også bidreg positivt til samfunnet.


