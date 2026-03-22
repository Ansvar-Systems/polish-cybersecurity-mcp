/**
 * Seed the CERT Polska database with sample guidance documents, advisories,
 * and frameworks for testing.
 *
 * Includes representative CERT Polska / CSIRT NASK cybersecurity guidelines,
 * KSC framework materials, and sample security advisories in Polish.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force   # drop and recreate
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CERT_PL_DB_PATH"] ?? "data/cert_pl.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "ksc-framework",
    name: "Krajowy System Cyberbezpieczenstwa (KSC)",
    name_en: "National Cybersecurity System",
    description: "Krajowy System Cyberbezpieczenstwa oparty na ustawie o KSC z 2018 roku (nowelizowanej w 2023 r. w zwiazku z transpozycja NIS2). Obejmuje CSIRT-y poziomow krajowych, operatorow uslug kluczowych i dostawcow uslug cyfrowych.",
    document_count: 45,
  },
  {
    id: "cert-polska-guides",
    name: "Poradniki CERT Polska",
    name_en: "CERT Polska Guides",
    description: "Praktyczne poradniki techniczne CERT Polska dotyczace cyberbezpieczenstwa: zarzadzanie podatnosciami, reagowanie na incydenty, bezpieczenstwo sieci, ochrona przed phishingiem i ransomware.",
    document_count: 38,
  },
  {
    id: "nis2-pl",
    name: "Transpozycja dyrektywy NIS2 w Polsce",
    name_en: "NIS2 Directive Transposition in Poland",
    description: "Wytyczne dotyczace transpozycji dyrektywy NIS2 (UE 2022/2555) do prawa polskiego. Obejmuje zmiany w ustawie o KSC, kategorie podmiotow, wymagania bezpieczenstwa i obowiazki notyfikacyjne.",
    document_count: 16,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);
for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}
console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "CERT-PL-2023-01",
    title: "Poradnik: Zarzadzanie podatnosciami w organizacji",
    title_en: "Guide: Vulnerability Management in Organisations",
    date: "2023-04-18",
    type: "technical_guideline",
    series: "CERT-PL",
    summary: "Praktyczny poradnik do budowy procesu zarzadzania podatnosciami. Obejmuje identyfikacje, klasyfikacje CVSS, priorytyzacje, remediacje i monitorowanie podatnosci w infrastrukturze IT i OT.",
    full_text: "Zarzadzanie podatnosciami jest kluczowym procesem cyklu zycia bezpieczenstwa informacji. Niniejszy poradnik opisuje systematyczne podejscie do tego zagadnienia.\n\nEtapy procesu:\n\n1. Identyfikacja podatnosci:\n- Automatyczne skanery (OpenVAS, Nessus, Qualys, Tenable)\n- Analiza zaleznosci oprogramowania (OWASP Dependency Check, Snyk)\n- Testy penetracyjne (co najmniej raz w roku dla krytycznych systemow)\n- Zrodla informacji o podatnosciach: CERT Polska, ENISA, NVD/NIST, CVE MITRE\n\n2. Klasyfikacja i ocena ryzyka:\nSkala CVSS v3.1:\n- Krytyczne (9.0-10.0): natychmiastowe dzialanie\n- Wysokie (7.0-8.9): pilna remediacja\n- Srednie (4.0-6.9): planowa remediacja\n- Niskie (0.1-3.9): remediacja wedlug priorytetow\n\n3. Priorytyzacja:\nOkrem punktacji CVSS nalezy uwzglednic: wskaznik EPSS (prawdopodobienstwo wykorzystania), dostepnosc publicznego exploita (Exploit-DB, PoC GitHub), kriticzosc systemu dla dzialania firmy, ekspozycja na internet.\n\n4. Remediacja:\nRekomendowane SLA: Krytyczne 24h, Wysokie 7 dni, Srednie 30 dni, Niskie 90 dni.\n\n5. Weryfikacja:\nPo zastosowaniu poprawki nalezy zweryfikowac skutecznosc remediacji przez ponowne skanowanie.\n\n6. Raportowanie:\nSledz wskazniki: sredni czas remediacji (MTTR), liczba otwartych podatnosci wedlug priorytetu, przestrzeganie SLA.",
    topics: JSON.stringify(["podatnosci", "CVSS", "zarzadzanie ryzykiem", "patching", "bezpieczenstwo IT"]),
    status: "current",
  },
  {
    reference: "CERT-PL-2023-02",
    title: "Poradnik: Ochrona przed oprogramowaniem ransomware",
    title_en: "Guide: Protection Against Ransomware",
    date: "2023-07-20",
    type: "technical_guideline",
    series: "CERT-PL",
    summary: "Kompleksowy poradnik dotyczacy ochrony przed oprogramowaniem ransomware. Zawiera strategie prewencji, dobre praktyki w zakresie kopii zapasowych, procedury reagowania i postepowania po ataku.",
    full_text: "Ransomware pozostaje jednym z najczestszych i najbardziej dotkliwych zagrozef cybernetycznych. Niniejszy poradnik opisuje wielowarstwowe podejscie do ochrony.\n\nWektory atakow ransomware:\n- Phishing — zlosliwe zalaczniki lub linki w wiadomosciach e-mail\n- Podatne uslugi dostepne przez internet — RDP, VPN, serwery webowe\n- Podatnosci w oprogramowaniu (exploitation)\n- Atak przez lancuch dostaw — kompromitacja oprogramowania dostawcy\n\nSrodki prewencyjne:\n\n1. Kopie zapasowe (3-2-1-1 regula):\n- 3 kopie danych\n- 2 rozne nosniki\n- 1 kopia poza siedziba firmy (offsite)\n- 1 kopia offline (air-gapped)\n- Regularne testowanie przywracania (co najmniej kwartalnie)\n\n2. Zarzadzanie poprawkami:\n- Latasowanie krytycznych podatnosci w ciagu 24-48h\n- Szczegolna uwaga na systemy dostepne z internetu (VPN, RDP, serwery webowe)\n\n3. Ochrona punktow koncowych:\n- EDR/XDR z detekcja behawioralna\n- Blokowanie PowerShell i skryptow w nieznanych lokalizacjach\n- Wdrozenie Windows Defender Credential Guard\n\n4. Segmentacja sieci:\n- Minimalizuj mozliwosc ruchu bocznego (lateral movement)\n- Izoluj systemy OT/ICS od sieci IT\n- Stosuj mikrosegmentacje dla krytycznych zasobow\n\n5. Kontrola dostepu:\n- Wymagaj MFA dla wszystkich uzytkow z dostepem zdalnym\n- Stosuj zasade najmnijszych uprawnien\n- Wdrozy PAM (Privileged Access Management)\n\nPostepowanie po ataku ransomware:\n1. Izoluj zainfekowane systemy natychmiast\n2. Nie plac okupu — nie gwarantuje odzyskania danych, finansuje przestepczosc\n3. Zachowaj kopie zaszyfrowanych danych i dowody\n4. Zglosz incydent do CERT Polska i Policji\n5. Sprawdz dostepnosc narzedzi do odszyfrowania na No More Ransom",
    topics: JSON.stringify(["ransomware", "kopie zapasowe", "EDR", "incident response", "MFA", "bezpieczenstwo"]),
    status: "current",
  },
  {
    reference: "CERT-PL-KSC-2023-01",
    title: "Wytyczne dla operatorow uslug kluczowych w ramach KSC",
    title_en: "Guidelines for Operators of Key Services under KSC",
    date: "2023-09-01",
    type: "sector_guide",
    series: "KSC",
    summary: "Wytyczne dla operatorow uslug kluczowych (OUK) wynikajace z ustawy o Krajowym Systemie Cyberbezpieczenstwa i znowelizowanych przepisow implementujacych dyrektywe NIS2. Omawia wymagania bezpieczenstwa, obowiazki notyfikacyjne i nadzor.",
    full_text: "Ustawa o Krajowym Systemie Cyberbezpieczenstwa (Ustawa z dnia 5 lipca 2018 r. o KSC, Dz.U. 2018 poz. 1560) zostala znowelizowana w celu transpozycji dyrektywy NIS2.\n\nKategorie podmiotow:\n- Podmioty kluczowe (Essential Entities): energia, transport, bankowosc, infrastruktura rynkow finansowych, zdrowie, woda pitna, scieki, infrastruktura cyfrowa, zarzadzanie uslugami ICT, administracja publiczna, przestrzen kosmiczna\n- Podmioty wazne (Important Entities): uslugi pocztowe, gospodarka odpadami, produkcja chemikaliow, zywnosc, produkcja, uslugodawcy cyfrowi\n\nObowiazki operatorow:\n1. Szacowanie ryzyka i wdrozenie odpowiednich srodkow technicznych i organizacyjnych\n2. Zarzadzanie incydentami i ich notyfikacja\n3. Zapewnienie ciagloci dzialania, w tym plany BC/DR\n4. Zarzadzanie lancuchem dostaw pod katem cyberbezpieczenstwa\n5. Audyty bezpieczenstwa co najmniej raz na 2 lata\n\nNotyfikacja incydentow do CSIRT NASK / CERT Polska:\n- Wczesne ostrzezenie: w ciagu 24 godzin\n- Powiadomienie o incydencie: w ciagu 72 godzin\n- Raport koncowy: w ciagu miesiac\n\nNadzor i kary:\nOrgan nadzoru moze nakladac kary pieniezne: na podmioty kluczowe do 10 mln EUR lub 2% swiatowego obrotu, na podmioty wazne do 7 mln EUR lub 1,4% obrotu.",
    topics: JSON.stringify(["KSC", "operatorzy uslug kluczowych", "NIS2", "notyfikacja incydentow", "bezpieczenstwo"]),
    status: "current",
  },
  {
    reference: "CERT-PL-2022-04",
    title: "Poradnik: Bezpieczna konfiguracja srodowisk Active Directory",
    title_en: "Guide: Secure Configuration of Active Directory Environments",
    date: "2022-08-25",
    type: "technical_guideline",
    series: "CERT-PL",
    summary: "Poradnik dotyczacy zabezpieczenia srodowisk Microsoft Active Directory. Obejmuje bezpieczna konfiguracje kontrolerow domeny, zasady grup, zarzadzanie uprzywilejowanymi dostepami i ochrone przed atakami Pass-the-Hash i Kerberoasting.",
    full_text: "Active Directory (AD) jest krytycznym skladnikiem infrastruktury wielu organizacji i czestym celem atakow. Jego kompromitacja daje atakujacemu kontrole nad calym srodowiskiem.\n\nCzeste wektory atakow na AD:\n- Pass-the-Hash (PtH) i Pass-the-Ticket (PtT)\n- Kerberoasting (ataki na konta uslugowe)\n- DCSync (wyciaganie hasel z domeny)\n- BloodHound (analiza sciezek atakow)\n- Ataki na delegation\n\nKluczowe srodki zabezpieczajace:\n\n1. Tier model (model podzialu na poziomy):\n- Tier 0: kontrolery domeny, systemy PKI — dostep tylko dla administratorow AD\n- Tier 1: serwery aplikacyjne i bazodanowe\n- Tier 2: stacje robocze uzytkownikow\n- Bez przepływu poswiadczen z wyzszych tier do nizszych\n\n2. Protected Users Security Group:\n- Dodaj uprzywilejowane konta do grupy Protected Users\n- Uniemozliwia przechowywanie hasel w pamieci (ogranicza PtH)\n\n3. LAPS (Local Administrator Password Solution):\n- Wdrozy LAPS na wszystkich stacjach roboczych\n- Eliminuje jednakowe hasla lokalnych administratorow\n\n4. Credential Guard:\n- Wlacz Windows Defender Credential Guard\n- Chroni poswiadczenia LSA w izolowanym srodowisku\n\n5. Audyt i monitorowanie:\n- Wlacz zaawansowany audyt logowania\n- Monitoruj zdarzenia: 4624 (logowanie), 4625 (nieudane logowanie), 4768 (Kerberos TGT), 4769 (Kerberos service ticket)\n- Wdrozy SIEM z regula detekcji atakow na AD",
    topics: JSON.stringify(["Active Directory", "Kerberoasting", "Pass-the-Hash", "LAPS", "Credential Guard", "bezpieczenstwo sieci"]),
    status: "current",
  },
  {
    reference: "CERT-PL-2023-05",
    title: "Reagowanie na incydenty cyberbezpieczenstwa — Przewodnik praktyczny",
    title_en: "Cybersecurity Incident Response — Practical Guide",
    date: "2023-11-10",
    type: "technical_guideline",
    series: "CERT-PL",
    summary: "Przewodnik po fazach reagowania na incydenty cyberbezpieczenstwa: przygotowanie, wykrywanie, ograniczanie, eliminacja, odbudowa i analiza post-incydentowa. Uwzglednia wymagania notyfikacyjne KSC/NIS2.",
    full_text: "Skuteczne reagowanie na incydenty wymaga uprzedniego przygotowania i przestrzegania strukturyzowanego procesu. Niniejszy przewodnik opisuje podejscie zgodne z standardem NIST SP 800-61 i wymaganiami KSC/NIS2.\n\nFazy reagowania na incydenty:\n\n1. Przygotowanie:\n- Opracuj i przetestuj Plan Reagowania na Incydenty (PRI)\n- Powolaj i przeszkol Zespol Reagowania na Incydenty (CSIRT/CERT)\n- Przygotuj narzedzia: SIEM, EDR, narzedzia forensyczne, listy kontaktow\n- Zdefiniuj progi krytycznosci incydentow i procedury eskalacji\n\n2. Wykrywanie i analiza:\n- Monitoruj alerty z systemow bezpieczenstwa (SIEM, EDR, IDS/IPS)\n- Klasyfikuj incydent (rodzaj, zakres, krytycznosc)\n- Zabezpieczaj dowody cyfrowe (pamiec RAM, logi, obrazy dyskow)\n\n3. Ograniczanie:\n- Izoluj zainfekowane systemy od sieci\n- Blokuj komunikacje z serwerami C2\n- Dezaktywuj skompromitowane konta uzytkownikow\n\n4. Eliminacja:\n- Usun malware i artefakty ataku\n- Zidentyfikuj i wyeliminuj przyczyne glowna (root cause)\n- Zastosuj poprawki bezpieczenstwa\n\n5. Odbudowa:\n- Przywroc systemy z czystych kopii zapasowych\n- Zweryfikuj integralnosc danych i systemow\n- Wzmocnij monitorowanie po przywroceniu\n\n6. Dzialania po incydencie:\n- Przygotuj raport post-incydentowy w ciagu 30 dni\n- Zaktualizuj PRI na podstawie wyciagnietych wnioskow\n- Notyfikuj incydent do CERT Polska jesli obowiazkowe (KSC/NIS2 24h/72h)\n- Udostep IoC spolecznosci bezpieczenstwa przez CERT Polska",
    topics: JSON.stringify(["reagowanie na incydenty", "CSIRT", "forensika cyfrowa", "KSC", "NIS2", "notyfikacja"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status);
  }
});
insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "CERT-PL-2024-001",
    title: "Krytyczna podatnosc w urzadzeniach Fortinet FortiGate VPN — CVE-2024-21762",
    date: "2024-02-09",
    severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS 7.4.0-7.4.2", "Fortinet FortiOS 7.2.0-7.2.6", "Fortinet FortiProxy"]),
    summary: "Krytyczna podatnosc typu out-of-bounds write w FortiOS i FortiProxy jest aktywnie wykorzystywana. Umozliwia zdalne wykonanie kodu bez uwierzytelnienia.",
    full_text: "CERT Polska ostrzega przed aktywnym wykorzystywaniem podatnosci CVE-2024-21762 w urzadzeniach Fortinet FortiGate VPN. Podatnosc dotyczy komponentu SSL-VPN.\n\nCVSS v3.1: 9.6 (Krytyczna)\n\nWplyw: Nieuwierzytelniony atakujacy moze wykonac dowolny kod lub polecenia poprzez specjalnie spreparowane zadania HTTP.\n\nWersje podatne: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14; FortiProxy 7.4.0-7.4.2, 7.2.0-7.2.8, 7.0.0-7.0.14.\n\nZalecane dzialania:\n1. Zaktualizuj FortiOS do wersji 7.4.3, 7.2.7, 7.0.14 lub 6.4.15\n2. Jesli aktualizacja nie jest mozliwa natychmiast, zablokuj dostep do interfejsu administracyjnego z internetu\n3. Przejrzyj logi dostepu pod katem wskaznikow kompromitacji (IoC)\n4. Sprawdz liste IoC opublikowana przez Fortinet\n5. Zglos podejrzenie kompromitacji do CERT Polska",
    cve_references: JSON.stringify(["CVE-2024-21762"]),
  },
  {
    reference: "CERT-PL-2023-008",
    title: "Kampanie phishingowe wymierzone w polskie organizacje — uwagadnie na BEC",
    date: "2023-08-15",
    severity: "high",
    affected_products: JSON.stringify(["Microsoft 365", "Google Workspace", "Firmowe systemy pocztowe"]),
    summary: "CERT Polska odnotowuje wzrost liczby kampanii Business Email Compromise (BEC) skierowanych do polskich firm. Atakujacy podszywaja sie pod kontrahentow i kierownictwo w celu przejecia platnosci.",
    full_text: "CERT Polska zidentyfikowal kampanie Business Email Compromise (BEC) wymierzone w polskie organizacje z sektora produkcyjnego, finansowego i uslugowego.\n\nTechniki wykorzystywane w kampaniach:\n- Spear phishing — precyzyjne wiadomosci podszywajace sie pod kontrahentow\n- Lookalike domeny — np. firma-pl.com zamiast firma.pl\n- Reguly skrzynki email przesylajace kopie wiadomosci atakujacemu\n- Kompromitacja skrzynek pocztowych dostawcow dla zwiekszenia wiarygodnosci\n\nScenariusze atakow:\n- Podszywanie sie pod kontrahenta z pros ba o zmiane numeru konta bankowego\n- Sfabrykowane wiadomosci od CEO/CFO z poleceniem pilnego przelewu\n- Przejecie korespondencji w trakcie negocjacji umowy\n\nSrodki zapobiegawcze:\n1. Wdrozy MFA na wszystkich kontach email\n2. Skonfiguruj DMARC, DKIM i SPF dla domeny\n3. Weryfikuj telefonicznie (na znany numer) kazda pro sbe o zmiane danych bankowych\n4. Szkol pracownikow w rozpoznawaniu technik BEC\n5. Monitoruj reguly skrzynki i podejrzane przekierowania\n6. Wdrozy narzedzie do analizy naglowkow email",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "CERT-PL-2023-005",
    title: "Krytyczna podatnosc MOVEit Transfer — Masowa eksploatacja CVE-2023-34362",
    date: "2023-06-05",
    severity: "critical",
    affected_products: JSON.stringify(["Progress MOVEit Transfer", "Progress MOVEit Cloud"]),
    summary: "Krytyczna podatnosc SQL injection w MOVEit Transfer jest masowo eksploatowana przez grupe Cl0p. Polskie organizacje moze byc wsrod poszkodowanych — nalezy podjaC natychmiastowe dzialania.",
    full_text: "CERT Polska ostrzega przed masowa eksploatacja podatnosci CVE-2023-34362 w aplikacji Progress MOVEit Transfer przez grupe ransomware Cl0p.\n\nSzczegoly podatnosci: SQL injection w komponencie webowym umozliwia nieuwierzytelnionym atakujacym dostep do bazy danych i przesylanych plikow.\n\nZasiag atakow: Setki organizacji globalnie, w tym w Europie, potwierdzono jako ofiary. CERT Polska otrzymal zgloszenia od polskich organizacji.\n\nZalecane natychmiastowe dzialania:\n1. Zastosuj patch opublikowany przez Progress Software\n2. Zablokuj zewnetrzny dostep do MOVEit Transfer do czasu latania\n3. Przejrzyj logi HTTP pod katem wstrzykniecia SQL (szukaj 'machine_id' w zapytaniach)\n4. Ocen, czy doszlo do wycieku danych osobowych (obowiazek notyfikacji UODO w ciagu 72h)\n5. Zglos incydent do CERT Polska\n6. Sprawdz liste IoC z grupy Cl0p pod katem sladow aktywnosci",
    cve_references: JSON.stringify(["CVE-2023-34362"]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references);
  }
});
insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
