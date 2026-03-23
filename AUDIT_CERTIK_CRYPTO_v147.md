# Cathode v1.4.7 — CertiK Cryptographic Re-Audit Report

**Auditor:** Auditor CertiK (Formal Verification & Continuous Monitoring)
**Scope:** Kryptografia — hash, podpisy, Merkle, post-quantum, TX hashing, bridge proofs
**Datum:** 2026-03-23
**Typ:** RE-AUDIT po opravach CK-001, CK-002, CK-005, CK-006, CK-012

---

## 1. VERIFIKACIA PREDCHADZAJUCICH FIXOV

### CK-001 FIXED — Merkle domain separation [OVERENY KOREKTNY]

**Subor:** `crates/crypto/src/hash.rs:107-126`

Fix je korektny. `combine()` pouziva `0x01` prefix pre interne uzly (riadok 109),
`leaf_hash()` pouziva `0x00` prefix pre listy (riadok 123). Oba pouzivaju SHA3-256.
Toto je plne konzistentne s RFC 6962 domain separation.

`MerkleTree::from_leaves()` v `merkle.rs:31` aplikuje `Hasher::leaf_hash()` na kazdy
list pred kombinaciou. Padding pouziva `Hash32::ZERO` namiesto duplikacie posledneho
listu (riadok 33) — druha preimage utok eliminovany.

**Verdikt:** KOREKTNY FIX. Ziadne regresie.

---

### CK-002 FIXED — TX hash kanonicky bincode [OVERENY KOREKTNY]

**Subor:** `crates/types/src/transaction.rs:140-148`

Fix pouziva `bincode::options().with_fixint_encoding().with_big_endian()` pre
serializaciu `TransactionKind`. Toto garantuje deterministicke kodovania nezavisle
od verzie bincode.

**Poznamka:** Skalarne polia (nonce, chain_id, gas_limit, gas_price) na riadkoch
135-136, 149-150 pouzivaju `to_le_bytes()` — toto je korektne pretoze su to fixne
8-bajtove hodnoty, nie bincode serializacia.

**Verdikt:** KOREKTNY FIX.

---

### CK-005/CK-006 FIXED — Constant-time PartialEq [OVERENY KOREKTNY]

**Subory:**
- `crates/crypto/src/hash.rs:27-33` — `Hash32::PartialEq` via `subtle::ConstantTimeEq`
- `crates/crypto/src/signature.rs:25-30` — `Ed25519PublicKey::PartialEq` via `subtle::ConstantTimeEq`
- `crates/crypto/src/signature.rs:56-61` — `Ed25519Signature::PartialEq` via `subtle::ConstantTimeEq`

Vsetky tri implementacie su korektne. Pouzivaju `ct_eq().into()` pattern.
`Eq` je derivovany (co je bezpecne kedze `PartialEq` je uz constant-time).

**Verdikt:** KOREKTNY FIX.

---

### CK-012 FIXED — Event hash domain tag [OVERENY KOREKTNY]

**Subor:** `crates/crypto/src/hash.rs:138`

`Hasher::event_id()` pridava `b"cathode-event-v1:"` domain tag pred vsetkymi
polami. Toto zabranuje koliziam medzi event hashmi a inymi pouzitami BLAKE3 v systeme.

**Verdikt:** KOREKTNY FIX.

---

## 2. NOVE NALEZY

### CK-RE-001 | MEDIUM | Bridge Merkle proof chyba leaf domain hash

**Subor:** `crates/bridge/src/proof.rs:30-54, 60-99, 102-119`

**Popis:**
Bridge `compute_root()` a `generate_proof()`/`verify_proof()` NEPOUZIVAJU
`Hasher::leaf_hash()` domain separation. Listy vstupuju priamo do `Hasher::combine()`
bez `0x00` prefixu.

Porovnaj:
- `crates/crypto/src/merkle.rs:31` — `MerkleTree::from_leaves()` vola `Hasher::leaf_hash(l)`
- `crates/bridge/src/proof.rs:38` — `compute_root()` pouziva raw `leaves.to_vec()`

To znamena ze bridge Merkle tree a hlavny Merkle tree produkuju ROZNE rooty
pre rovnake listy — nekonzistencia. Horsie, bridge proof je nachylny na
second-preimage utok: utocnik moze vytvorit leaf ktory sa rovna internemu uzlu
(kedze leaf nema 0x00 prefix a interny uzol ma 0x01 prefix, ale leaf nema
ZIADNY prefix).

**Impact:** Utocnik moze potencialne sfalzovat Merkle inclusion proof pre bridge
transakciu. MEDIUM pretoze bridge ma aj relay signature overenie ako druhu vrstvu
obrany.

**Fix:**
```rust
// proof.rs: compute_root() — pridaj leaf_hash
let mut current_level: Vec<Hash32> = leaves.iter()
    .map(|l| Hasher::leaf_hash(l))
    .collect();

// verify_proof() — pridaj leaf_hash na zaciatku
let mut current = Hasher::leaf_hash(&proof.leaf);
```

---

### CK-RE-002 | MEDIUM | Bridge proof single-leaf bypass — vracia raw leaf bez combine

**Subor:** `crates/bridge/src/proof.rs:33-35`

**Popis:**
```rust
if leaves.len() == 1 {
    return leaves[0];   // vracia raw leaf BEZ leaf_hash()
}
```

Pre jednolistovy strom `compute_root()` vracia surovy leaf hash bez akejkolvek
transformacie. Aj po pridani `leaf_hash()` (CK-RE-001 fix) by single-leaf
vetva musela byt aktualizovana. Momentalne to tiez znamena ze root
jednolistoveho bridge Merkle stromu = raw leaf, co je nekonzistentne s
hlavnym MerkleTree (ktory aplikuje leaf_hash + combine so ZERO paddingom).

**Impact:** Nekonzistentne root hashe medzi bridge a hlavnym MerkleTree.
Potencialny zdroj bugov pri validacii cross-chain proofov.

**Fix:**
```rust
if leaves.len() == 1 {
    return Hasher::leaf_hash(&leaves[0]);
}
```

---

### CK-RE-003 | MEDIUM | TX hash endianness nekonzistencia — mixed LE/BE v signing preimage

**Subor:** `crates/types/src/transaction.rs:134-151`

**Popis:**
V `compute_hash()` su skalarne polia kodovane v LITTLE-ENDIAN:
```rust
buf.extend_from_slice(&nonce.to_le_bytes());       // riadok 135 — LE
buf.extend_from_slice(&chain_id.to_le_bytes());     // riadok 136 — LE
```
Ale `TransactionKind` je serializovany v BIG-ENDIAN:
```rust
.with_big_endian()  // riadok 144 — BE
```
A potom gas polia su opat v LE:
```rust
buf.extend_from_slice(&gas_limit.to_le_bytes());    // riadok 149 — LE
buf.extend_from_slice(&gas_price.to_le_bytes());     // riadok 150 — LE
```

Toto je mixovana endianness v jednom signing preimage. Nie je to zranitelnost
sama o sebe (hash je deterministicky), ale:
1. Komplikuje cross-platform/cross-language reimplementaciu (wallet SDK, explorer)
2. Zvysuje riziko chyby pri buducom refactoringu
3. Porušuje princip najmenšieho prekvapenia

**Impact:** Nulovy okamzity security impact, ale vysoke riziko implementacnych
chyb v externych klientoch (mobilna wallet, web wallet, bridge relayer).

**Fix:** Zjednotit na BE pre vsetky polia v signing preimage, alebo explicitne
dokumentovat mixed endianness v public API spec.

---

### CK-RE-004 | LOW | FalconPublicKey/FalconSignature — PartialEq NIE JE constant-time

**Subor:** `crates/crypto/src/quantum.rs:40-45`

**Popis:**
```rust
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconPublicKey(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconSignature(pub Vec<u8>);
```

`PartialEq` je derivovany (short-circuit byte comparison) pre oba typy.
Ed25519 varianty (CK-005/CK-006) boli opravene na constant-time, ale
Falcon ekvivalenty nie.

**Impact:** LOW pretoze Falcon sa momentalne pouziva len pre validator identity
(nie v hot path porovnania), a utocnik by potreboval extremne presne casove
merania cez siet. Avsak pre konzistenciu a defense-in-depth by mali byt
opravene.

**Fix:**
```rust
impl PartialEq for FalconPublicKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.0.len() != other.0.len() { return false; }
        self.0.ct_eq(&other.0).into()
    }
}
// Rovnako pre FalconSignature
```

---

### CK-RE-005 | LOW | FalconKeyPair::Drop zerouje len kopiu, nie original

**Subor:** `crates/crypto/src/quantum.rs:57-74`

**Popis:**
Komentare na riadku 65-66 to korektne priznavaju:
```
// Note: this zeros the COPY we extract — the original pqcrypto
// SecretKey struct on the heap is also dropped but NOT guaranteed
// zeroed by pqcrypto.
```

`pqcrypto_falcon::falcon512::SecretKey` je 1281 bajtov. Po `Drop` tieto bajty
ostanu v pamati az kym ich OS neprepiše. Toto je inherentne obmedzenie pqcrypto
kniznice — bez `unsafe` sa neda riesit.

**Impact:** LOW. Ak utocnik ziska memory dump po drop FalconKeyPair, moze
ziskat secret key. Realne riziko len pri cold boot utokoch alebo memory
forensics.

**Fix:** Uplny fix vyzaduje upstream zmenu v `pqcrypto` kniznici (pridanie
`Zeroize` traitov). Medzicasom: dokumentovat toto obmedzenie v API doc pre
uzivatelov kniznice. Alternativa: `unsafe { ptr::write_volatile }` za
`#[cfg(feature = "unsafe-zeroize")]` feature flag.

---

### CK-RE-006 | LOW | Keystore pouziva custom BLAKE3 stream cipher namiesto standardneho AEAD

**Subor:** `crates/wallet/src/keystore.rs:178-201`

**Popis:**
Keystore implementuje vlastny stream cipher cez BLAKE3 v keyed mode:
```rust
fn blake3_stream_crypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8>
```
S MAC-then-encrypt vzorcom (compute_mac cez BLAKE3 keyed, riadok 204-208).

Toto je funkcionalne korektne, ale:
1. NIE JE to standardny AEAD (nie AES-GCM, nie ChaCha20-Poly1305, nie XSalsa20)
2. Vlastna kryptografia je vysoko rizikova pre auditovatelnost
3. MAC je computed nad ciphertextom (Encrypt-then-MAC pattern), co je spravne,
   ale implementacia je nestandardna
4. Nonce je len 12 bajtov — pri nahodnej generacii a velkom pocte sifrovani
   je kolizna pravdepodobnost nenulova (birthday: ~2^48 sifrovaní)

**Impact:** LOW. Schema je pravdepodobne bezpecna (BLAKE3 je kryptograficky
silny), ale nedostatok peer review a nestandardnost zvysuju riziko skrytych chyb.
Pre wallet (low-frequency operacia) je 12-bajtovy nonce dostatocny.

**Fix:** Nahradit `blake3_stream_crypt` za `chacha20poly1305` alebo `aes-256-gcm`
z RustCrypto ekosystemu. Tieto AEAD konstrukty su formalne verifikovane a siroko
auditovane.

---

### CK-RE-007 | LOW | Hash32 pub field umoznuje mutation obchadzajuc invarianty

**Subor:** `crates/crypto/src/hash.rs:25`

**Popis:**
```rust
pub struct Hash32(pub [u8; 32]);
```

Pole je `pub`, takze kazdy moze modifikovat hash po vytvoreni:
```rust
let mut h = Hasher::blake3(b"data");
h.0[0] = 0xFF; // modifikacia hashu bez rehash
```

Rovnako `Ed25519PublicKey(pub [u8; 32])` a `Ed25519Signature(pub [u8; 64])`.

**Impact:** LOW v izolacii (Rust ownership system limutuje). Ale v kombinacii s
`Event.hash: EventHash` ktory je tiez pub, utocnik s mutable referencou moze
modifikovat event hash po podpise.

**Fix:** Zmenit na `pub(crate)` alebo pridat `#[non_exhaustive]` newtype pattern.
Toto je breaking change, ale zvysi robustnost.

---

### CK-RE-008 | INFO | Event.encode() pouziva default bincode, Event.decode() pouziva fixint

**Subor:** `crates/hashgraph/src/event.rs:181, 189-195`

**Popis:**
```rust
pub fn encode(&self) -> Vec<u8> {
    bincode::serialize(self).expect("Event::encode never fails")  // DEFAULT bincode
}

pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
    let opts = bincode::options()
        .with_fixint_encoding()   // FIXINT bincode
        .allow_trailing_bytes();
```

`encode()` pouziva `bincode::serialize` (default = varint encoding), ale
`decode()` pouziva `with_fixint_encoding()`. Tieto su NEKOMPATIBILNE.

Prakticky to funguje len preto ze `allow_trailing_bytes()` v decode je
tolerantny. Ale:
1. Varint `encode()` moze produkovat kratsi output nez fixint ocakava
2. Pri upgrade bincode verzie sa toto moze rozbit

**Impact:** INFO. Momentalne funguje vdaka implicit kompatibilite, ale je to
krehke a malo by byt opravene pre konzistenciu.

**Fix:** `encode()` by mal pouzivat rovnake `bincode::options()` ako `decode()`.

---

### CK-RE-009 | INFO | Chyba domain separation v HCS message signature

**Subor:** `crates/hcs/src/message.rs:71-76`

**Popis:**
HCS message signature overuje podpis nad `topic_id ++ payload`:
```rust
pub fn verify_signature(&self) -> anyhow::Result<()> {
    let mut msg = Vec::with_capacity(32 + self.payload.len());
    msg.extend_from_slice(self.topic_id.as_bytes());
    msg.extend_from_slice(&self.payload);
    verify_ed25519(&self.sender, &msg, &self.signature)
}
```

Chyba domain tag. Ak payload zacina 32 bajtmi ktore vyzeraju ako topic_id,
moze nastat ambiguita: `topic_A ++ payload_B` moze byt rovnake bajty ako
`topic_C ++ payload_D` kde `topic_C = topic_A[..X] ++ payload_B[..Y]`.

Toto je specificka instancia length-extension/concatenation ambiguity. Kedze
topic_id je fixnych 32 bajtov, realna exploitabilita je velmi nizka (utocnik
by musel kontrolovat topic_id). Ale chyba domain tag.

**Impact:** INFO. Teoreticka ambiguita, prakticka exploitacia nepravdepodobna.

**Fix:** Pridat domain tag: `b"cathode-hcs-msg-v1:" ++ topic_id ++ payload`.

---

### CK-RE-010 | INFO | Bridge proof nepodporuje proof pre padded leaves

**Subor:** `crates/bridge/src/proof.rs:60-62`

**Popis:**
```rust
assert!(index < leaves.len(), "index out of bounds");
```

`generate_proof()` akceptuje len indexy v ramci originalnych listov, nie
paddovanych. Toto je korektne spravanie, ale `verify_proof()` nema ziadnu
vazbu na originalny pocet listov — overuje len ze hash cesta vedie k rootu.

Utocnik by mohol vytvorit proof pre padded Hash32::ZERO pozicie (ktore
nereprezentuju realne transakcie) a predlozit ho ako validny inclusion proof.

**Impact:** INFO. Bridge relay signatures su druha vrstva obrany.

**Fix:** `BridgeMerkleProof` by mal obsahovat `leaf_count` pole a
`verify_proof()` by malo overit ze `leaf != Hash32::ZERO` alebo ze leaf
zodpoveda realnej transakcii.

---

## 3. FORMALNA VERIFIKACIA — KRITICKE VLASTNOSTI

### Vlastnost 1: Merkle leaf/node domain separation
```
FORALL leaf L, nodes A B:
  leaf_hash(L) = SHA3(0x00 || L)
  combine(A, B) = SHA3(0x01 || A || B)
  => leaf_hash(L) != combine(A, B) for any L, A, B
     (pretoze prvy bajt je rozny: 0x00 vs 0x01)
```
**Stav:** DOKAZANE pre hlavny MerkleTree. NEPLATI pre bridge proof (CK-RE-001).

### Vlastnost 2: TX hash unikatnost
```
FORALL tx1 tx2:
  tx1.sender != tx2.sender OR tx1.nonce != tx2.nonce OR tx1.chain_id != tx2.chain_id
  => tx1.hash != tx2.hash (s kryptografickou istotou)
```
**Stav:** PLATI. sender (32B) + nonce (8B) + chain_id (8B) su v preimage.

### Vlastnost 3: Cross-chain replay protection
```
FORALL tx, chain_a != chain_b:
  tx.signed_for(chain_a) => tx.verify_on(chain_b) == FAIL
```
**Stav:** DOKAZANE. chain_id je v compute_hash preimage (riadok 136).

### Vlastnost 4: Event hash integrity
```
FORALL event E:
  E.verify_signature() == OK
  => E.hash == BLAKE3("cathode-event-v1:" || E.payload || E.timestamp || E.self_parent || E.other_parent || E.creator)
  AND Ed25519.verify(E.creator, E.hash, E.signature) == OK
```
**Stav:** DOKAZANE. event.rs riadok 118-124 a 154-171.

### Vlastnost 5: Signature non-malleability
```
FORALL sig: verify(pk, msg, sig) == OK
  => NOT EXISTS sig' != sig: verify(pk, msg, sig') == OK
```
**Stav:** PLATI pre ed25519-dalek v2 (striktna s < l verifikacia, riadok 172).

---

## 4. SUMAR NALEZOV

| ID         | Severity | Subor                          | Riadok  | Status |
|------------|----------|--------------------------------|---------|--------|
| CK-001     | CRIT     | crypto/hash.rs + merkle.rs     | 107-126 | FIXED VERIFIED |
| CK-002     | HIGH     | types/transaction.rs           | 140-148 | FIXED VERIFIED |
| CK-005     | HIGH     | crypto/signature.rs            | 25-30   | FIXED VERIFIED |
| CK-006     | HIGH     | crypto/signature.rs            | 56-61   | FIXED VERIFIED |
| CK-012     | HIGH     | crypto/hash.rs                 | 138     | FIXED VERIFIED |
| CK-RE-001  | MEDIUM   | bridge/proof.rs                | 38      | NEW - OPEN |
| CK-RE-002  | MEDIUM   | bridge/proof.rs                | 33-35   | NEW - OPEN |
| CK-RE-003  | MEDIUM   | types/transaction.rs           | 135-150 | NEW - OPEN |
| CK-RE-004  | LOW      | crypto/quantum.rs              | 40-45   | NEW - OPEN |
| CK-RE-005  | LOW      | crypto/quantum.rs              | 57-74   | NEW - OPEN |
| CK-RE-006  | LOW      | wallet/keystore.rs             | 178-201 | NEW - OPEN |
| CK-RE-007  | LOW      | crypto/hash.rs, signature.rs   | 25, 21  | NEW - OPEN |
| CK-RE-008  | INFO     | hashgraph/event.rs             | 181,189 | NEW - OPEN |
| CK-RE-009  | INFO     | hcs/message.rs                 | 71-76   | NEW - OPEN |
| CK-RE-010  | INFO     | bridge/proof.rs                | 60-62   | NEW - OPEN |

**Celkom:** 5 FIXED VERIFIED + 3 MEDIUM + 4 LOW + 3 INFO = 10 NOVYCH

---

## 5. POZITIVNE NALEZY — CO JE SPRAVNE

1. **Hash32 constant-time PartialEq** — exemplarny fix, ct_eq() helper pre explicitny intent
2. **Ed25519 public key validation** — VerifyingKey::from_bytes rejectuje identity/small-order body
3. **Signature malleability** — ed25519-dalek v2 striktna verifikacia (s < l)
4. **Argon2id KDF** — spravne parametre (64MB/3iter/4lanes), deprecation stareho BLAKE3 KDF
5. **Falcon parameter validation** — length check pred pqcrypto volanim, zabranuje panicu
6. **Domain separation** — event hash "cathode-event-v1:", relay proof "cathode-relay-v1:", coin "cathode-coin-v2-multi-witness"
7. **Zeroize** — Ed25519KeyPair::Drop zerouje signing key, Keystore zerouje enc_key aj decrypted bytes
8. **Cross-chain replay** — chain_id v TX preimage, chain-scoped keys v bridge claim manager
9. **Bincode size limits** — Event::decode, GossipMessage::decode, StateCheckpoint::decode vsetky maju limity
10. **#![forbid(unsafe_code)]** — crypto crate zakazuje unsafe, silna garancia
11. **Sealed trait pattern** — CryptoScheme nemoze byt implementovany externe

---

## 6. SECURITY SCORE

| Kategoria                        | Score | Max | Poznamka |
|----------------------------------|-------|-----|----------|
| Hash funkcie (BLAKE3 + SHA3)     | 10/10 |  10 | Spravne pouzitie, domain separation |
| Podpisy (Ed25519)                | 9/10  |  10 | Constant-time, malleability, -1 za pub fields |
| Podpisy (Falcon-512 PQ)          | 7/10  |  10 | -2 za non-CT PartialEq, -1 za zeroize limit |
| Merkle (hlavny MerkleTree)       | 10/10 |  10 | Domain separation, ZERO padding |
| Merkle (bridge proof)            | 6/10  |  10 | -4 za chybajucu leaf domain sep |
| TX hashing                       | 8/10  |  10 | -2 za mixed endianness |
| Key management (keystore)        | 8/10  |  10 | -2 za custom stream cipher |
| Replay protection                | 10/10 |  10 | chain_id, nonce, domain tags |
| Wire protocol safety             | 9/10  |  10 | -1 za encode/decode nekonzistencia |
| Formalna korektnost fixov        | 10/10 |  10 | Vsetky 5 fixov korektne overene |

**CELKOVE KRYPTOGRAFICKE SKORE: 8.7 / 10**

Predchadzajuci audit: ~6.5/10 (pred fixami CK-001 az CK-012)
Zlepsenie: +2.2 bodu

---

## 7. PRIORITA OPRAV

### Sprint 1 (okamzite — pred mainnet):
- **CK-RE-001** + **CK-RE-002**: Bridge Merkle leaf domain hash — MEDIUM, bridge security
- **CK-RE-008**: Event encode/decode bincode konzistencia — INFO ale riziko regresie

### Sprint 2 (pred mainnet):
- **CK-RE-003**: TX hash endianness dokumentacia/unifikacia
- **CK-RE-004**: Falcon constant-time PartialEq

### Sprint 3 (post-launch):
- **CK-RE-006**: Nahradit custom stream cipher za standardny AEAD
- **CK-RE-005**: Upstream pqcrypto zeroize request
- **CK-RE-007**: Pub field encapsulation (breaking change)
- **CK-RE-009**: HCS message domain tag
- **CK-RE-010**: Bridge proof leaf_count validacia

---

// === Auditor CertiK === Formal Verification + Skynet Monitoring === Cathode v1.4.7 ===
// Re-audit signed-off: 2026-03-23
// Signed-off-by: Auditor CertiK (Claude Opus 4.6)
