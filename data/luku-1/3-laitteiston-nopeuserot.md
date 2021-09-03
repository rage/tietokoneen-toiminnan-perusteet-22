---
path: "/luku-1/3-laitteiston-nopeuserot"
title: "Laitteiston nopeuserot"
---

<div>
<lead>Ihmisen näkökulmasta tietokone tuntuu kovin nopealta ja niinhän se onkin! Tietokone pystyy tekemään miljardeja tai biljoonia laskutoimituksia sekunnissa. Tietokoneen sisällä eri laitteiden ja komponenttien nopeuserot ovat kuitenkin valtavia. Eri nopeuksisia laitteita on paljon ja silti niiden pitää toimia hyvin yhteen. Tutustumme tässä aliluvussa näihin nopeuseroihin ja niiden vaikutuksiin tietokoneiden ja tietokonejärjestelmien suunnittelussa.</lead>
</div>

## Laitteiston nopeuserot
Meille ihmisille ei ole juurikaan väliä, tapahtuuko jokin asia millisekunnissa ([ms](https://fi.wiktionary.org/wiki/millisekunti)), mikrosekunnissa ([µs](https://fi.wiktionary.org/wiki/mikrosekunti)) vai nanosekunnissa ([ns](https://fi.wiktionary.org/wiki/nanosekunti)), koska ne kaikki ovat ihmisen aikaskaalassa se ja sama silmänräpäys.

Tietokoneelle asia on ihan erilainen. Millisekunti on miljoona nanosekuntia ja on hyvinkin merkittävää, kestääkö jonkin asian tekeminen esimerkiksi 5 ms tai 5 ns. Yksi nanosekunti on niin lyhyt aika, että valo ehtii tyhjiössä kulkea vain 30 cm sinä aikana. Sähkösignaalit tietokoneen laitteistossa kulkevat vielä hitaammin. Sen vuoksi tietokoneiden pitää olla pieniä, jos niistä halutaan nopeita!


<!-- Note: millisekunti, jne -->

<text-box variant="example" name="Milli-, mikro-, nano- ja pikosekunti">

Sekunti = 1 000 ms = 1 000 000 µs = 1 000 000 000 ns = 1 000 000 000 000 ps.
<br>
Millisekunti = 1 ms = 0.001 sekuntia = 1 000 µs = 1 000 000 000 ps.
<br>
Mikrosekunti = 1 µs = 0.000 001 sekuntia = 1 000 ns = 1 000 000 ps.
<br>
Nanosekunti = 1 ns = 0.000 000 001 sekuntia = 1 000 ps.
<br>
Pikosekunti = 1 ps = 0.000 000 000 001 sekuntia.

</text-box>

Vaikka tietokonelaitteistoja kehitetään nopeammiksi koko ajan ja nykyisetkin laitteistot ovat kovin erilaisia keskenään, niin jonkinlaisia suuntaa antavia nopeuksia voidaan silti antaa. Ajatellaan esimerkiksi tilannetta, jossa haluamme lukea muuttujan X arvon. Jos arvo on suorittimen rekisterissä, siihen voisi kulua vaikkapa 1 ns. Vastaavasti sen saantiaika välimuistista voisi olla 4 ns, keskusmuistista 50 ns, [SSD](https://fi.wikipedia.org/wiki/SSD)-muistista 100 µs, kovalevyltä 10 ms ja internetpalvelimelta [Rio de Janeirosta](https://fi.wikipedia.org/wiki/Rio_de_Janeiro) 10 sekuntia.

## Juustokakkuesimerkki
Laitteiston ja koko tietokonejärjestelmän nopeuseroja voi illustroida Teemun juustokakkuesimerkillä. Esimerkki on vähän lapsellinen, mutta koeta kestää.

<!-- juustokakku kuva ch-1-3-juustokakku -->

![Kokki, jonka kädessä on kulho ja juustoa. Aika 0.5 sekuntia (rekisteri). Pöytä, jossa on valmiina juustoa. Aika 1-2 sekuntia (välimuisti). Suljettu jääkaappi, jonka sisällä on juustoa. Aika 25 sekuntia (muisti). Saturnus-raketti nousemassa ylös ja viemässä Apollo-alusta kohti kuuta, jossa on juustoa. Aika 10 päivää (levy). SpaceX:n BRF-raketti lähtee matkalle Orion-alus nokassaan kohti Jupiterin Europa-kuuta, jossa on juustoa. Aika 4 vuotta (pilvi, ihminen).](./ch-1-3-juustokakku.svg)
<div>
<illustrations motive="ch-1-3-juustokakku" totalheight="100%"></illustrations>
</div>

Teemu on tekemässä juustokakkua ja resepti vaatii nyt juuston lisäämisen kulhoon. Jos juusto on valmiiksi kädessä, sehän tipahtaa kulhoon yhdessä sekunnissa. Jos juusto pitää noukkia pöydältä, niin siihen menee muutama sekunti. Jääkaapista juuston hakuun menee vähän enemmän aikaa, kun Teemun pitää kävellä jääkaapille, avata sen ovi, ottaa juusto, sulkea jääkaapin ovi, kävellä takaisin pöydän ääreen, avata paketti ja laittaa juusto kulhoon. Tähän voisi kulua esim. 25 sekuntia.

Jos taas Teemu oli kokonaan unohtanut juuston eikä sitä löydy kaupoistakaan, niin onneksi juustoa löytyy kuusta. Teemu lähettää astronauttikaverinsa Tiinan lentämään Amsterdamin kautta avaruusasemalle Cape Canaveraliin, jossa häntä odottaa juuri kunnostettu [Saturn V -raketti](https://fi.wikipedia.org/wiki/Saturn_V) ja [Apollo-avaruusalus](https://fi.wikipedia.org/wiki/Apollo-komento-_ja_huoltomoduuli). Tiina lentää 2-3 päivää kuuhun, hakee sieltä juuston ja palaa takaisin maan kamaralle, lentää New Yorkin kautta takaisin Suomeen ja vihdoin antaa Teemulle juuston kulhoon laitettavaksi. Tähän menisi ehkä 10 päivää. Teemu ei tietenkään vain odottele Tiinaa ja juustoa, vaan tekee sillä aikaa paljon muuta. Hän käy vaikka lomalla Roomassa, lukee kirjoja tai pelaa [_Doom_](https://fi.wikipedia.org/wiki/Doom)'in taas alusta loppuun. Juustokakkuaineksetkin laitettiin pakastimeen odottamaan.

Entä jos käy niin onnettomasti, että Tiina palaa kuusta tyhjin käsin, kun sieltäkin oli juusto loppu? Nyt lähetetään Teemun toinen astronauttikaveri Arto etsimään juustoa Jupiterin [Europa](https://fi.wikipedia.org/wiki/Europa_(kuu))-kuusta. Arto on hyvää pataa [SpaceX](https://www.spacex.com/):n kanssa ja saa heiltä lainaksi [ITS](https://en.wikipedia.org/wiki/Interplanetary_Transport_System)-aluksen, joka lähetetään liikkeelle [BFR](https://en.wikipedia.org/wiki/BFR_(rocket))-raketilla. Matka kestää nelisen vuotta ja suurimpana riskinä on, että minkälaista juustoa Europa oikeastaan on. Se näyttää siniseltä, joten juusto voisi olla [Aura](https://fi.wikipedia.org/wiki/Aura_(juusto))-juustoa, mikä ei taas sovi Teemun reseptiin. Vaikeaksi menee.

## Nopeuserojen vaikutus
Juustokakkuesimerkin mukaiset valtaisat nopeuserot ovat normaaleja tietokoneissa. Konekäskyjä suoritetaan ns-aikaskaalassa ("juusto kädessä"), kun ihmisen kanssa kommunikoidaan sekunnin aikaskaalassa ("juusto Europa'ssa"). Sekunnissa on tuhat miljoonaa (1&nbsp;000&nbsp;000&nbsp;000) nanosekuntia. Yhden sekunnin aikana hyvä tietokone voi siis suorittaa miljardi konekäskyä. Jotkut tietokoneet ovat vielä nopeampia, koska ne suorittavat useaa konekäskyä samanaikaisesti. Jotkut tietokoneet ovat taas paljon hitaampia, koska se riittää niiden käyttötarkoitukseen.

Kuhunkin käyttötarkoitukseen on hyvä hankkia siihen sopiva järjestelmä. Esimerkiksi himopelaaja tarvitsee vähän paremman tietokoneen, koska pelien virtuaalitodellisuuden luominen teräväpiirtonäyttöjä varten vaatii paljon laskentatehoa. Pelkkään tekstin käsittelyyn ja verkkosurfaukseen riittää huomattavasti pelkistetympi laitteisto. Huippunopean koneen ostaminen sähköpostin lukemista varten on rahan heittämistä hukkaan. Toisaalta, eihän ihmiset osta [Ferrareitakaan](https://fi.wikipedia.org/wiki/Ferrari) vain sen takia, että niillä voisi ajaa kovaa. Jotkut saavat hyvän mielen ihan hienon laitteiston omistamisesta. Yritysmaailmassa näin ei tietenkään toimita. Jos joku on sijoittanut 20 000€ huippunopeaan laitteistoon kun 1 000€ maksava tavallinen PC olisi riittänyt, niin se ei tiedä hyvää urakehitykselle.

Tiedon hakuaika rekisteristä ("juusto kädessä") on nanosekunnin luokkaa. Välimuistista haku ("juusto pöydältä") on vain vähän hitaampaa. Keskusmuisti ("juusto jääkaapissa") on nykykoneilla jo ärsyttävän kaukana, esimerkiksi 50-100 ns. Suoritin yleensä kuitenkin vain "hyytyy paikalleen", kun se odottaa muistista haettavaa tietoa. Jotkut suorittimet kuitenkin hyödyntävät tämänkin odotusajan suorittamalla sillä aikaa jotain muuta ohjelmaa. Tämä ei ole mitenkään yksinkertaista ja toteutetaan ns. [hypersäikeistyksellä](https://fi.wikipedia.org/wiki/Hypers%C3%A4ikeistys).

Kovalevyt ja massamuistit ovat jo tosi kaukana suorittimen näkökulmasta. Pyörivät kovalevyt ("juusto kuussa") toimivat millisekunnin aikaskaalassa, kun taas mikropiireillä toteutetut [SSD](https://fi.wikipedia.org/wiki/SSD):t ("juusto Tukholmassa") ovat jotain 100 kertaa nopeampia, mutta silti vielä yli 1000 kertaa hitaampia kuin keskusmuisti. Suorittimen ei missään tapauksessa kannata vain odotella tiedon siirtoa massamuistista, vaan sillä aikaa suoritusvuoro annetaan muille ohjelmille. Käyttöjärjestelmä siirtää tiedonsiirtoa odottavan ohjelman "nukkumaan" ja "herättää" sen sitten tiedonsiirron valmistuttua.

Internetin pilvipalvelut ja ihminen ovat sitten taas noin tuhat kertaa kovalevyä hitaampia. Ne toimivat sekuntien aikaskaalassa ("juusto Europassa"). Niitä odotellessa kyseinen ohjelma ehtii "nukkua" pitkään. Jo muutaman sekunnin odotusaikana ehtii tehdä paljon muuta, vaikkakaan kotitietokoneessa ei välttämättä ole suurta joukkoa muita ohjelmia suoritusvuoroa odottamassa. Tiedon odotusajan voi silti hyödyntää käyttöjärjestelmän ylläpidolla tai vaikkapa etsimällä älyllistä elämää [SETI\@home](https://fi.wikipedia.org/wiki/SETI@home) joukkoistetun laskennan avulla. Siihen tarvitaankin enemmän kuin muutama sekunti aikaa. Toisaalta, jos mitään muuta ei tosiaankaan ole tehtävänä, niin laitteiston pitää odottaa tekemättä mitään hyödyllistä. Tällainen odottaminenkin on aktiivista ja tarkoittaa konekäskyjen suorittamista pienessä silmukassa, jossa koko ajan kysellään, että "onks tietoo jo?".

Älä tuijota liikaa juustokakkuesimerkin numeroarvoihin. Numeroarvot muuttuvat koko ajan teknologian kehittyessä ja eri laitteistoissa on muutenkin valtavia nopeuseroja. Suuruusluokkaerot ovat tärkeitä. Nopeuskuilu rekistereiden ja muistin välillä on vain kasvanut viime vuosina. Vastaavasti nopeuskuilu muistin ja levymuistin välillä on pysynyt suunnilleen samana, mutta viime aikoina yleistynyt nopeampi SSD-muisti massamuistina muuttaa järjestelmää jonkin verran. Toisaalta taas pilvipalveluiden yleistyminen on johtanut siihen, että järjestelmän massamuisti voi olla pilvessä. Me ihmiset emme ole muuttuneet mihinkään, joten käyttäjältä vastauksen saaminen kestää edelleenkin sekunteja. Tosin graafisen käyttöliittymän kautta ihminenkin voi syöttää suuren määrän tietoa nopeasti.

## Nopeuseroihin sopeutuminen
Erilaisten muistiteknologioiden suuret nopeuserot ovat vaikuttaneet ja vaikuttavat edelleenkin tietokoneiden ja käyttöjärjestelmien kehitykseen huomattavasti. Laitteistossa automaattisesti toimivat [välimuistit](https://fi.wikipedia.org/wiki/V%C3%A4limuisti) ovat ratkaisu suorittimen rekistereiden ja keskusmuistin välisen nopeuseron tuomiin ongelmiin. Nopeusero on vain kasvanut ja nyt välimuisteja on tehokkaissa koneissa jo kolmessa tai jopa neljässä eri tasossa. Välimuisteilla ohjelma saa käyttöönsä näennäisen muistialueen, joka on yhtä suuri kuin keskusmuisti, mutta lähes yhtä nopea kuin suorittimen rekisterit.

Vielä suurempi nopeusero keskusmuistin ja erilaisten massamuistien välillä on johtanut käyttöjärjestelmissä [virtuaalimuistin](https://fi.wikipedia.org/wiki/N%C3%A4enn%C3%A4ismuisti) kehittämiseen. Sen avulla saadaan ohjelman käyttöön näennäinen (virtuaalinen) muistialue, joka parhaimmillaan on yhtä suuri kuin massamuisti, mutta lähes yhtä nopea kuin keskusmuisti. Järjestelmän keskusmuisti tuntuu ja näyttää siis paljon suuremmalta kuin mitä se todellisuudessa on. Tiedostojen osalta keskusmuistissa pidettävä [levyvälimuisti](https://fi.wikipedia.org/wiki/V%C3%A4limuisti) ratkoo tätä samaa ongelmaa pitämällä keskusmuistissa kopioita juuri nyt käytössä olevista massamuistin tiedostoista. Massamuistissa olevat tiedostot tuntuvat nyt olevan paljon lähempänä kuin mitä ne todellisuudessa ovat.

Oman tietokoneen massamuistin ja Internetissä olevien palvelimien välistä nopeuseroa kurotaan umpeen [välityspalvelimilla](https://fi.wikipedia.org/wiki/V%C3%A4lityspalvelin) (proxy). Esimerkiksi, [Los Angelesissa](https://fi.wikipedia.org/wiki/Los_Angeles) olevan paljon käytetyn kissankuvasivuston tiedostoja voi olla valmiiksi kopioituna verkkopalvelujen tarjoajan omalle välityspalvelimelle Suomessa. Näin paljon käytettyihin kissakuviin pääsee käsiksi nopeasti ja tiedonsiirron määrä Los Angelesista Suomeen vähenee huomattavasti.

<!-- kuva: muistihierarkia ch-1-3-muistihierarkia-draft -->

![Kolme sisäkkäistä aluetta. Sisimpänä on laitteisto, jossa on rekisterit, muisti ja niiden välissä välimuistit. Nuoli menee muistista välimuistien läpi rekistereihin. Keskellä on järjestelmätaso, jolla on laitteisto, massamuisti ja niiden välissä käyttöjärjestelmän ylläpitämä virtuaalimuisti ja levyvälimuisti. Nuoli menee massamuistista virtuaalimuistin ja levyvälimuistin läpi muistiin. Uloin alue on internet, jossa on tämä järjestelmän, pilvipalvelu/www ja niiden välissä välityspalvelin eli proxy. Nuoli pilvipalvelusta proxyn kautta massamuistiin. Laitteiston nopeus on ns-luokkaa, järjestelmän massamuistin nopeus ms-luokkaa. Pilvipalveluiden ja muun internetin nopeus on sekuntien luokkaa.](./ch-1-3-muistihierarkia.svg)
<div>
<illustrations motive="ch-1-3-muistihierarkia" frombottom="0" totalheight="100%"></illustrations>
</div>

<!-- quiz 1.3.1-11 Väitteet tietokoneen nopeudesta, etc -->

<div><quiz id="7ae733dc-a56c-5fd5-aa56-475fa462de82"></quiz></div>
<div><quiz id="cce3a767-6f60-5664-985d-23a01ec113a5"></quiz></div>
<div><quiz id="d28314c2-4294-527f-987a-d6ee81ccb402"></quiz></div>
<div><quiz id="a6b07eba-fbc6-5920-9d40-2075bb16eecd"></quiz></div>
<div><quiz id="e81fc774-8b0f-5d10-8e10-24dc528b7a7e"></quiz></div>
<div><quiz id="e26cdabb-0bf9-5bd4-86c0-dab3d7d720e2"></quiz></div>
<div><quiz id="c9597b3c-c2ad-58a5-9d86-76819a92938d"></quiz></div>
<div><quiz id="dd54cc74-ffa5-509a-91fb-0dd6b8df70aa"></quiz></div>
<div><quiz id="0cd52733-489a-5ec5-acfc-2543c8b0913b"></quiz></div>
<div><quiz id="dc92de7d-bcc5-59b1-8a5e-d00524112875"></quiz></div>
<div><quiz id="8bb8b7ae-0c5b-5e40-a4ab-f0a1584b81cb"></quiz></div>

<!-- Luvun 1 yhteenveto, mitä tuli opittua quiz 1.summary -->

<text-box variant="example" name="Historiaa:  Z1">

Konrad Zuse kehitti Saksassa 1935-1936 mekaanisen tietokoneen Z1. Se oli oikeastaan laskin, jolle ohjelma syötettiin reikänauhalta. Laitteisto toimi kampea kääntämällä ja siinä oli 64 sanan (á 24 bittiä) muisti. Kertolaskuun kului noin 5 sekuntia.

<!-- kuva: ch-1-3-z1    -->

![Kolme valokuvaa Z1 replikasta Berliinin tiedemuseossa. Alkuperäinen Z1 tuhoutui Berliin pommituksissa 1943. Ylhäällä yleiskuva laitteistoissa monine hammasrattaineen. Alhaalla vasemmalla kuva ohjelman sisältävästä reikänauhasta ja oikealla kuva mekaanisista biteistä.](./ch-1-3-z1.svg)
<div>
<illustrations motive="ch-1-3-z1"></illustrations>
</div>

</text-box>

## Yhteenveto
Ensimmäinen luku käsitteli tietokonejärjestelmää ja sen osia. Sen jälkeen tutustuimme ohjelman käsitteeseen ja ohjelmien erilaisiin esitysmuotoihin vain ihmisen luettavissa olevista algoritmeista numeeriseen konekieleen. Lopuksi kävimme läpi tietokonejärjestelmän valtavia nopeuseroja ja niiden vaikutuksia järjestelmän käyttöön ja toteutukseen.

Vastaa alla olevaan kyselyyn kun olet valmis ensimmäisen luvun tehtävien kanssa.
<div><quiz id="89e67798-ae64-51b0-b21e-c8156f97a095"></quiz></div>
