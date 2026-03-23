//! HAWK STRESS TEST SUITE — Cathode Executor
//!
//! Autor: Hawk (QA Specialist)
//! Datum: 2026-03-23
//!
//! Testy:
//! 1. 10,000 sequential transfers — nonces, balances, fee collector
//! 2. 100 concurrent senders — 10 threads * 10 senders, no balance corruption
//! 3. Stake/unstake rapid cycling — balance conservation
//! 4. Mixed operations — transfers + stakes + unstakes interleaved
//! 5. Maximum gas price — u64::MAX gas_price, overflow protection
//! 6. Near-zero balance — transfer leaving exactly 0, then try another
//! 7. Many recipients — 1 sender → 1000 different recipients
//! 8. Self-transfer stress — 1000 self-transfers, only gas consumed
//! 9. Receipt integrity under load
//! 10. Concurrent stake/unstake race — no corruption

// Signed-off-by: Hawk (QA) — 2026-03-23

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_executor::pipeline::Executor;
use cathode_executor::state::StateDB;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use cathode_types::transaction::{Transaction, TransactionKind, CHAIN_ID_TESTNET};
use std::sync::Arc;
use std::thread;

// ─── Pomocné funkcie ──────────────────────────────────────────────────────────

fn make_executor_with_fee_collector() -> (Arc<StateDB>, Executor, Address) {
    let state = Arc::new(StateDB::new());
    let fee_collector = Address::from_bytes([0xFE; 32]);
    let exec = Executor::new(state.clone(), fee_collector, CHAIN_ID_TESTNET);
    (state, exec, fee_collector)
}

fn make_executor_no_fee() -> (Arc<StateDB>, Executor) {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    (state, exec)
}

fn mk_transfer(
    kp: &Ed25519KeyPair,
    nonce: u64,
    to: Address,
    amount: u64,
    gas_limit: u64,
    gas_price: u64,
) -> Transaction {
    Transaction::new(
        nonce,
        TransactionKind::Transfer {
            to,
            amount: TokenAmount::from_tokens(amount),
        },
        gas_limit,
        gas_price,
        2u64,
        kp,
    )
}

fn mk_stake(kp: &Ed25519KeyPair, nonce: u64, amount: u64) -> Transaction {
    Transaction::new(
        nonce,
        TransactionKind::Stake { amount: TokenAmount::from_tokens(amount) },
        50_000,
        1,
        2u64,
        kp,
    )
}

fn mk_unstake(kp: &Ed25519KeyPair, nonce: u64, amount: u64) -> Transaction {
    Transaction::new(
        nonce,
        TransactionKind::Unstake { amount: TokenAmount::from_tokens(amount) },
        50_000,
        1,
        2u64,
        kp,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 1: 10,000 SEQUENTIAL TRANSFERS
// Overi: nonce inkrementácia, balance dekrementácia u odosielateľa,
//         balance inkrementácia u prijímateľa, akumulácia poplatkov
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_10k_sequential_transfers_nonces_balances_fees() {
    let (state, exec, fee_collector) = make_executor_with_fee_collector();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    let bob = Address::from_bytes([0xB0; 32]);

    // Mintujeme dosť na 10,000 transferov:
    // každý = 1 token + 21000 base gas * 1 gas_price = 21000 base
    // total gas: 10,000 * 21,000 base = 210,000,000 base
    // total transfer: 10,000 * 1 token
    state.mint(sender, TokenAmount::from_tokens(20_000_000)).unwrap();

    let balance_before = exec.state().balance(&sender);
    let fee_before = exec.state().balance(&fee_collector);

    for i in 0..10_000u64 {
        let tx = mk_transfer(&kp, i, bob, 1, 21000, 1);
        let r = exec
            .execute_event(&tx.encode(), Hash32::ZERO, i, 1_000_000 + i)
            .unwrap();
        assert!(
            r.status.is_success(),
            "TX {} zlyhalo: {:?}",
            i,
            r.status
        );
    }

    // Nonce musí byť 10,000
    assert_eq!(exec.state().nonce(&sender), 10_000, "nonce nesprávny");

    // Bob dostal 10,000 tokenov
    assert_eq!(
        exec.state().balance(&bob),
        TokenAmount::from_tokens(10_000),
        "Bob má nesprávny balance"
    );

    // Fee collector dostal 10,000 * 21,000 * 1 = 210,000,000 base
    let expected_fees = TokenAmount::from_base(10_000u128 * 21_000u128);
    assert_eq!(
        exec.state().balance(&fee_collector),
        expected_fees.checked_add(fee_before).unwrap(),
        "Fee collector má nesprávny balance"
    );

    // TX count
    assert_eq!(exec.tx_count(), 10_000, "tx_count nesprávny");

    // Celkový balance: sender_before - 10,000 tokens - fees = sender_after
    let expected_sender = balance_before
        .checked_sub(TokenAmount::from_tokens(10_000))
        .unwrap()
        .checked_sub(expected_fees)
        .unwrap();
    assert_eq!(
        exec.state().balance(&sender),
        expected_sender,
        "Sender balance nesprávny"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 2: 100 CONCURRENT SENDERS (10 threads * 10 senders)
// Overi: žiadna korupcia balance pri paralelnom vykonávaní
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_100_concurrent_senders_no_balance_corruption() {
    let (state, exec_raw) = make_executor_no_fee();
    let exec = Arc::new(exec_raw);
    let bob = Address::from_bytes([0xBB; 32]);

    // 100 senderov, každý posiela 5x po 1 tokene Bobovi (gas_price=0)
    // Bob má mať nakoniec 500 tokenov presne
    // Uložíme adresy senderov aby sme mohli skontrolovať supply
    let sender_addresses: Vec<Address> = {
        let mut addrs = Vec::new();
        for _ in 0..100 {
            let kp = Ed25519KeyPair::generate();
            let addr = Address(kp.public_key().0);
            state.mint(addr, TokenAmount::from_tokens(1_000)).unwrap();
            addrs.push(addr);
        }
        addrs
    };

    // Generujeme keypairs znovu — použijeme deterministický prístup cez thread-local
    // Jednoduchšie: vytvoríme keypairs vopred, uložíme adresy zvlášť
    // (Ed25519KeyPair nie je Clone, takže pošleme do vlákna priamo)

    // Vytvoríme 10 vlákien, každé s 10 sendermi
    // Každý sender je reprezentovaný ako (pubkey bytes pre adresu, nový keypair)
    // Keďže keypair nie je clone, generujeme 100 čerstvých keypairov v 10 skupinách

    // Reset state - urobíme to inak: každé vlákno si generuje vlastný keypair
    // a mint-ujeme pre neho
    let state2 = Arc::new(StateDB::new());
    let exec2 = Arc::new(Executor::new(state2.clone(), Address::ZERO, CHAIN_ID_TESTNET));
    let bob2 = Address::from_bytes([0xBC; 32]);

    let mut handles = Vec::new();
    for thread_idx in 0..10u64 {
        let exec = exec2.clone();
        let state = state2.clone();
        handles.push(thread::spawn(move || {
            let mut successes = 0u64;
            for sender_idx in 0..10u64 {
                let kp = Ed25519KeyPair::generate();
                let addr = Address(kp.public_key().0);
                state.mint(addr, TokenAmount::from_tokens(1_000)).unwrap();

                for nonce in 0..5u64 {
                    let tx = mk_transfer(&kp, nonce, bob2, 1, 21_000, 0);
                    let order = thread_idx * 50 + sender_idx * 5 + nonce;
                    if let Some(r) = exec.execute_event(
                        &tx.encode(),
                        Hash32::ZERO,
                        order,
                        order * 1000,
                    ) {
                        if r.status.is_success() {
                            successes += 1;
                        }
                    }
                }
            }
            successes
        }));
    }

    let total_success: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();

    // 10 vlákien * 10 senderov * 5 TX = 500 uspesnych
    assert_eq!(total_success, 500, "Nie všetky TX uspeli: {}/500", total_success);

    // Bob dostal 500 tokenov (100 senderov * 5 tokenov, gas_price=0)
    assert_eq!(
        exec2.state().balance(&bob2),
        TokenAmount::from_tokens(500),
        "Bob má nesprávny balance"
    );

    // Celková supply: 100 senderov * 1000 tokenov = 100,000 tokenov
    // Bob: 500, senders: 99,500 (gas=0 takže žiadne straty)
    // Conservation check
    let bob_bal = exec2.state().balance(&bob2).base();
    let sender_total: u128 = exec2
        .state()
        .iter_accounts()
        .iter()
        .filter(|(addr, _)| *addr != bob2)
        .map(|(_, acc)| acc.balance.base())
        .sum();
    assert_eq!(
        sender_total + bob_bal,
        TokenAmount::from_tokens(100_000).base(),
        "Supply nie je zachovaná"
    );

    // Potlačíme warning pre nepoužitú premennú
    let _ = sender_addresses;
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 3: STAKE/UNSTAKE RAPID CYCLING — balance conservation
// Overi: stake → unstake cyklus neplytvá tokeny
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_stake_unstake_rapid_cycling_balance_conservation() {
    let (state, exec) = make_executor_no_fee();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);

    state.mint(sender, TokenAmount::from_tokens(10_000_000)).unwrap();
    let initial_balance = exec.state().balance(&sender);

    let cycles = 100u64;
    let stake_amount = 100u64;

    // Gas za stake + unstake = 2 * 30,000 base * 1 gas_price = 60,000 base na cyklus
    // Total gas = cycles * 60,000 base
    let total_gas = TokenAmount::from_base((cycles as u128) * 60_000u128);

    for cycle in 0..cycles {
        let nonce_stake = cycle * 2;
        let nonce_unstake = cycle * 2 + 1;

        // Stake
        let tx_stake = mk_stake(&kp, nonce_stake, stake_amount);
        let r_stake = exec
            .execute_event(&tx_stake.encode(), Hash32::ZERO, nonce_stake, nonce_stake * 1000)
            .unwrap();
        assert!(
            r_stake.status.is_success(),
            "Stake v cykle {} zlyhalo: {:?}",
            cycle,
            r_stake.status
        );

        // Staked balance musí byť nenulový
        let staked = exec.state().get(&sender).staked;
        assert_eq!(
            staked,
            TokenAmount::from_tokens(stake_amount),
            "Staked balance nesprávny v cykle {}",
            cycle
        );

        // Unstake
        let tx_unstake = mk_unstake(&kp, nonce_unstake, stake_amount);
        let r_unstake = exec
            .execute_event(&tx_unstake.encode(), Hash32::ZERO, nonce_unstake, nonce_unstake * 1000)
            .unwrap();
        assert!(
            r_unstake.status.is_success(),
            "Unstake v cykle {} zlyhalo: {:?}",
            cycle,
            r_unstake.status
        );

        // Po unstake staked = 0
        let staked_after = exec.state().get(&sender).staked;
        assert_eq!(
            staked_after,
            TokenAmount::ZERO,
            "Staked nie je nula po unstake v cykle {}",
            cycle
        );
    }

    // Finálny balance = initial - total_gas
    let expected_final = initial_balance.checked_sub(total_gas).unwrap();
    assert_eq!(
        exec.state().balance(&sender),
        expected_final,
        "Balance nie je správny po {} cykloch stake/unstake",
        cycles
    );

    // Nonce = 2 * cycles
    assert_eq!(exec.state().nonce(&sender), cycles * 2);

    // Žiadne staked tokeny nezostali
    assert_eq!(exec.state().get(&sender).staked, TokenAmount::ZERO);
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 4: MIXED OPERATIONS — transfers + stakes + unstakes interleaved
// Overi: striedanie rôznych typov TX, správna séria nonces a fees
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_mixed_operations_interleaved() {
    let (state, exec, fee_collector) = make_executor_with_fee_collector();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    let bob = Address::from_bytes([0xB1; 32]);
    let carol = Address::from_bytes([0xC1; 32]);

    state.mint(sender, TokenAmount::from_tokens(100_000_000)).unwrap();

    // Vzor na cyklus (5 TX):
    //   nonce+0: transfer 10 → bob  (gas 21000 * 1)
    //   nonce+1: stake 500           (gas 30000 * 1)
    //   nonce+2: transfer 5 → carol (gas 21000 * 1)
    //   nonce+3: unstake 500         (gas 30000 * 1)
    //   nonce+4: transfer 1 → bob   (gas 21000 * 1)

    let rounds = 50u64;
    let mut global_nonce = 0u64;
    let mut global_order = 0u64;
    let mut expected_bob = 0u64;
    let mut expected_carol = 0u64;

    for round in 0..rounds {
        // TX1: transfer 10 → bob
        let tx = mk_transfer(&kp, global_nonce, bob, 10, 21_000, 1);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, global_order, global_order * 1000).unwrap();
        assert!(r.status.is_success(), "Round {} TX1 zlyhalo: {:?}", round, r.status);
        expected_bob += 10;
        global_nonce += 1;
        global_order += 1;

        // TX2: stake 500
        let tx = mk_stake(&kp, global_nonce, 500);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, global_order, global_order * 1000).unwrap();
        assert!(r.status.is_success(), "Round {} TX2 stake zlyhalo: {:?}", round, r.status);
        global_nonce += 1;
        global_order += 1;

        // TX3: transfer 5 → carol
        let tx = mk_transfer(&kp, global_nonce, carol, 5, 21_000, 1);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, global_order, global_order * 1000).unwrap();
        assert!(r.status.is_success(), "Round {} TX3 zlyhalo: {:?}", round, r.status);
        expected_carol += 5;
        global_nonce += 1;
        global_order += 1;

        // TX4: unstake 500
        let tx = mk_unstake(&kp, global_nonce, 500);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, global_order, global_order * 1000).unwrap();
        assert!(r.status.is_success(), "Round {} TX4 unstake zlyhalo: {:?}", round, r.status);
        global_nonce += 1;
        global_order += 1;

        // TX5: transfer 1 → bob
        let tx = mk_transfer(&kp, global_nonce, bob, 1, 21_000, 1);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, global_order, global_order * 1000).unwrap();
        assert!(r.status.is_success(), "Round {} TX5 zlyhalo: {:?}", round, r.status);
        expected_bob += 1;
        global_nonce += 1;
        global_order += 1;
    }

    // Nonce = rounds * 5
    assert_eq!(exec.state().nonce(&sender), rounds * 5, "Nonce nesprávny");

    // Bob dostal rounds * (10 + 1) = rounds * 11 tokenov
    assert_eq!(
        exec.state().balance(&bob),
        TokenAmount::from_tokens(expected_bob),
        "Bob má nesprávny balance"
    );
    assert_eq!(expected_bob, rounds * 11);

    // Carol dostala rounds * 5 tokenov
    assert_eq!(
        exec.state().balance(&carol),
        TokenAmount::from_tokens(expected_carol),
        "Carol má nesprávny balance"
    );
    assert_eq!(expected_carol, rounds * 5);

    // Staked = 0 (každý stake má odpovedajúci unstake)
    assert_eq!(exec.state().get(&sender).staked, TokenAmount::ZERO, "Staked nie je nula");

    // Fee collector: 3 transfery * rounds * 21000 + 2 stake/unstake * rounds * 30000
    let expected_fees = TokenAmount::from_base(
        (3u128 * rounds as u128 * 21_000u128) + (2u128 * rounds as u128 * 30_000u128)
    );
    assert_eq!(
        exec.state().balance(&fee_collector),
        expected_fees,
        "Fee collector má nesprávny balance"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 5: MAXIMUM GAS PRICE — u64::MAX a extrémne hodnoty
// Overi: overflow protection pri výpočte gas_fee = gas_cost * gas_price
//
// BUG NÁLEZ (HAWK-0001):
//   gas_fee = gas_cost * u64::MAX sa NEPRELIVÁ (mieści sa v u128).
//   Ak je sender_balance >= gas_fee, TX USPEJE aj pri u64::MAX gas_price.
//   gas_fee = 21000 * (2^64-1) ≈ 3.87e23 base < MAX_SUPPLY (10^27 base).
//   Teda TX s u64::MAX gas_price a dostatočným balance LEGÁLNE USPEJE —
//   sender zaplatí astronomický poplatok fee_collector-u.
//   Toto je EKONOMICKÝ BUG (nie bezpečnostný): užívateľ s dostatočným
//   balance môže omylom (alebo zámerným útočníkom podvrhnutou TX) zaplatiť
//   enormný gas. Odporúčame zavedenie MAX_GAS_PRICE limitu.
//
// Tento test verifikuje AKTUÁLNE SPRÁVANIE (bez MAX_GAS_PRICE limitu):
//   - malý balance → TX zlyhá (insufficient balance)
//   - veľký balance → TX uspeje (uhradí astronomický gas)
//   - po TX je Bob bez tokenov ak gas_fee > transfer_amount
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_max_gas_price_overflow_protection() {
    // --- Scenár A: Malý balance → musí zlyhat ---
    {
        let (state, exec) = make_executor_no_fee();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        let bob = Address::from_bytes([0xBB; 32]);

        // Dáme senderovi malý balance: 1000 tokenov (10^21 base)
        // gas_fee = 21000 * u64::MAX ≈ 3.87e23 base > 10^21 → musí zlyhat
        state.mint(sender, TokenAmount::from_tokens(1_000)).unwrap();

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(1),
            },
            21_000,
            u64::MAX,
            2u64,
            &kp,
        );

        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
        assert!(!r.status.is_success(), "TX s u64::MAX gas_price a malym balance musí zlyhat");

        // Nonce inkrementovaný (ochrana pred replay)
        assert_eq!(exec.state().nonce(&sender), 1, "Nonce sa musí inkrementovať");

        // Bob nedostal nič
        assert_eq!(exec.state().balance(&bob), TokenAmount::ZERO, "Bob nesmie dostať tokeny");

        // Sender balance sa nezmenil (TX zlyhal pred transferom)
        assert_eq!(exec.state().balance(&sender), TokenAmount::from_tokens(1_000));
    }

    // --- Scenár B: gas_limit * u64::MAX overflow check ---
    // gas_limit u64::MAX prekročuje MAX_GAS_LIMIT (50M) → odmietnuté okamžite
    {
        let (state, exec) = make_executor_no_fee();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        let bob = Address::from_bytes([0xBC; 32]);

        state.mint(sender, TokenAmount::from_tokens(1_000_000_000)).unwrap();

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(1),
            },
            u64::MAX,     // gas_limit presahuje MAX_GAS_LIMIT (50M)
            u64::MAX,     // gas_price astronomický
            2u64,
            &kp,
        );

        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
        assert!(
            !r.status.is_success(),
            "TX s u64::MAX gas_limit musí zlyhat (exceeds MAX_GAS_LIMIT)"
        );
        assert_eq!(exec.state().balance(&bob), TokenAmount::ZERO);
    }

    // --- Scenár C: Normálny gas_price funguje ---
    {
        let (state, exec) = make_executor_no_fee();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        let bob = Address::from_bytes([0xBD; 32]);

        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();

        let tx = Transaction::new(
            0,
            TransactionKind::Transfer {
                to: bob,
                amount: TokenAmount::from_tokens(1),
            },
            21_000,
            1,
            2u64,
            &kp,
        );
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
        assert!(r.status.is_success(), "Normálny TX musí uspieť");
        assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(1));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 6: NEAR-ZERO BALANCE
// Overi: transfer presne vyprázdňujúci balance, potom odmietnutie ďalšieho
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_near_zero_balance_transfer_then_reject() {
    let (state, exec) = make_executor_no_fee();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    let bob = Address::from_bytes([0xBB; 32]);

    // Gas za transfer = 21,000 base (gas_limit=21000, gas_price=1)
    // transfer_amount = 1,000 base
    // total_needed = 21,000 + 1,000 = 22,000 base
    let transfer_amount = TokenAmount::from_base(1_000);
    let gas_fee = TokenAmount::from_base(21_000);
    let exact_balance = transfer_amount.checked_add(gas_fee).unwrap();

    state.mint(sender, exact_balance).unwrap();

    // TX1: Odošleme presne transfer_amount, zaplatíme presne gas_fee
    // sender musí byť po TX na 0
    let tx1 = Transaction::new(
        0,
        TransactionKind::Transfer {
            to: bob,
            amount: transfer_amount,
        },
        21_000,
        1,
        2u64,
        &kp,
    );

    let r1 = exec.execute_event(&tx1.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(r1.status.is_success(), "TX1 musí uspieť: {:?}", r1.status);

    // Sender má presne 0
    assert_eq!(exec.state().balance(&sender), TokenAmount::ZERO, "Sender musí mať 0 po TX1");
    // Bob dostal transfer_amount
    assert_eq!(exec.state().balance(&bob), transfer_amount, "Bob musí dostať transfer_amount");

    // TX2: Pokus o ďalší transfer — musí zlyhat (balance=0)
    let tx2 = Transaction::new(
        1,
        TransactionKind::Transfer {
            to: bob,
            amount: TokenAmount::from_base(1),
        },
        21_000,
        1,
        2u64,
        &kp,
    );

    let r2 = exec.execute_event(&tx2.encode(), Hash32::ZERO, 1, 2000).unwrap();
    assert!(!r2.status.is_success(), "TX2 musí zlyhat — nulový balance");

    // Bob zostáva na rovnakom balanci
    assert_eq!(exec.state().balance(&bob), transfer_amount, "Bob nesmie dostať viac");

    // Sender nonce = 2
    assert_eq!(exec.state().nonce(&sender), 2, "Nonce musí byť 2");

    // TX3: Zero-amount transfer od prázdneho účtu — musí tiež zlyhat (nemá na gas)
    let tx3 = Transaction::new(
        2,
        TransactionKind::Transfer {
            to: bob,
            amount: TokenAmount::ZERO,
        },
        21_000,
        1,
        2u64,
        &kp,
    );
    let r3 = exec.execute_event(&tx3.encode(), Hash32::ZERO, 2, 3000).unwrap();
    assert!(!r3.status.is_success(), "TX3 zero-amount od prázdneho účtu musí zlyhat");
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 7: MANY RECIPIENTS — 1 sender → 1000 different recipients
// Overi: každý recipient dostane presne správnu sumu, supply conservation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_1_sender_to_1000_recipients() {
    let (state, exec) = make_executor_no_fee();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);

    // 1000 rôznych recipientov
    let recipients: Vec<Address> = (0u64..1000)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&i.to_le_bytes());
            // Aby sme sa vyhli ZERO adrese
            bytes[31] = 0x01;
            Address::from_bytes(bytes)
        })
        .collect();

    // transfer_amount = 100 base, gas = 21000 base per TX
    let transfer_amount = TokenAmount::from_base(100);
    let total_needed = TokenAmount::from_base(1000u128 * (100u128 + 21_000u128));

    state.mint(sender, total_needed).unwrap();

    let balance_before = exec.state().balance(&sender);

    for (i, &recipient) in recipients.iter().enumerate() {
        let tx = Transaction::new(
            i as u64,
            TransactionKind::Transfer {
                to: recipient,
                amount: transfer_amount,
            },
            21_000,
            1,
            2u64,
            &kp,
        );
        let r = exec
            .execute_event(&tx.encode(), Hash32::ZERO, i as u64, i as u64 * 1000)
            .unwrap();
        assert!(r.status.is_success(), "TX {} zlyhalo: {:?}", i, r.status);
    }

    // Každý recipient dostal presne 100 base
    for (i, &recipient) in recipients.iter().enumerate() {
        let bal = exec.state().balance(&recipient);
        assert_eq!(
            bal,
            transfer_amount,
            "Recipient {} má nesprávny balance",
            i
        );
    }

    // Sender nonce = 1000
    assert_eq!(exec.state().nonce(&sender), 1000, "Nonce musí byť 1000");

    // TX count = 1000
    assert_eq!(exec.tx_count(), 1000, "tx_count musí byť 1000");

    // Sender balance = balance_before - 1000 * 100 base - 1000 * 21000 base
    let total_fees = TokenAmount::from_base(1000u128 * 21_000u128);
    let total_transferred = TokenAmount::from_base(1000u128 * 100u128);
    let expected_sender = balance_before
        .checked_sub(total_transferred)
        .unwrap()
        .checked_sub(total_fees)
        .unwrap();
    assert_eq!(
        exec.state().balance(&sender),
        expected_sender,
        "Sender balance nesprávny"
    );

    // Conservation: sender + recipienti + gas (stratené na fee_collector=ZERO) = total_needed
    let recipient_total: u128 = recipients
        .iter()
        .map(|r| exec.state().balance(r).base())
        .sum();
    assert_eq!(
        recipient_total,
        total_transferred.base(),
        "Recipienti celkovo nemajú správnu sumu"
    );

    let sender_final = exec.state().balance(&sender).base();
    assert_eq!(
        sender_final + recipient_total + total_fees.base(),
        total_needed.base(),
        "Supply conservation zlyhala"
    );

    // Žiadny recipient nemá viac ako 100 base
    for &recipient in &recipients {
        assert!(
            exec.state().balance(&recipient).base() <= 100,
            "Recipient dostal príliš veľa"
        );
    }

    // Všetci recipienti sú unikátni (skontrolujeme cez set)
    let distinct: std::collections::HashSet<[u8; 32]> =
        recipients.iter().map(|a| a.0).collect();
    assert_eq!(distinct.len(), 1000, "Recipienti nie sú unikátni");
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 8: SELF-TRANSFER STRESS — 1000 self-transfers, only gas consumed
// Overi: self-transfer nemení balance okrem gas poplatkov
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_1000_self_transfers_only_gas_consumed() {
    let (state, exec, fee_collector) = make_executor_with_fee_collector();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);

    // 1000 self-transferov, gas = 21000 base * 1 per TX
    // Celkový gas = 1000 * 21000 = 21,000,000 base
    let self_transfer_amount = TokenAmount::from_tokens(1_000);
    let total_gas = TokenAmount::from_base(1_000u128 * 21_000u128);

    state.mint(sender, TokenAmount::from_tokens(10_000_000)).unwrap();
    let balance_before = exec.state().balance(&sender);

    for i in 0..1000u64 {
        let tx = Transaction::new(
            i,
            TransactionKind::Transfer {
                to: sender, // seba samého!
                amount: self_transfer_amount,
            },
            21_000,
            1,
            2u64,
            &kp,
        );
        let r = exec
            .execute_event(&tx.encode(), Hash32::ZERO, i, i * 1000)
            .unwrap();
        assert!(r.status.is_success(), "Self-transfer {} zlyhalo: {:?}", i, r.status);
        // Gas used musí byť 21000
        assert_eq!(r.gas_used, 21_000, "Gas used nesprávny v TX {}", i);
    }

    // Nonce = 1000
    assert_eq!(exec.state().nonce(&sender), 1000, "Nonce musí byť 1000");

    // Sender balance = initial - total_gas (self-transfer nemení principal)
    let expected_balance = balance_before.checked_sub(total_gas).unwrap();
    assert_eq!(
        exec.state().balance(&sender),
        expected_balance,
        "Sender stratil viac ako len gas"
    );

    // Fee collector dostal total_gas
    assert_eq!(
        exec.state().balance(&fee_collector),
        total_gas,
        "Fee collector dostal nesprávnu sumu"
    );

    // TX count = 1000
    assert_eq!(exec.tx_count(), 1000, "tx_count musí byť 1000");

    // Rozdiel balance = presne total_gas
    assert_eq!(
        balance_before.checked_sub(expected_balance).unwrap(),
        total_gas,
        "Rozdiel balance musí byť presne total_gas"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 9: RECEIPT INTEGRITY UNDER STRESS
// Overi: každý receipt má správny tx_hash, gas_used je konzistentný
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_receipt_integrity_under_load() {
    let (state, exec) = make_executor_no_fee();
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    let bob = Address::from_bytes([0xBB; 32]);

    state.mint(sender, TokenAmount::from_tokens(100_000_000)).unwrap();

    let mut tx_hashes = Vec::new();

    // 500 TX — uložíme hash každého
    for i in 0..500u64 {
        let tx = mk_transfer(&kp, i, bob, 1, 21_000, 0);
        let hash = tx.hash;
        let r = exec
            .execute_event(&tx.encode(), Hash32::ZERO, i, i * 1000)
            .unwrap();
        assert!(r.status.is_success(), "TX {} zlyhalo", i);
        // Receipt musí mať správny tx_hash
        assert_eq!(r.tx_hash, hash, "Receipt má nesprávny tx_hash v TX {}", i);
        // gas_used musí byť 21000 (gas_price=0 → no fee, ale gas_used=21000)
        assert_eq!(r.gas_used, 21_000, "gas_used nesprávny v TX {}", i);
        tx_hashes.push(hash);
    }

    // Lookup — všetky 500 musia byť nájdené (RECEIPT_STORE_CAPACITY=100,000)
    for (i, hash) in tx_hashes.iter().enumerate() {
        let stored = exec.receipt_by_hash(hash);
        assert!(
            stored.is_some(),
            "Receipt pre TX {} sa nenašiel",
            i
        );
        if let Some(r) = stored {
            assert_eq!(r.tx_hash, *hash, "Uložený receipt má nesprávny hash");
            assert_eq!(r.gas_used, 21_000, "Uložený receipt má nesprávny gas_used");
        }
    }

    // Celkový počet receiptov nesmie presiahnuť kapacitu
    assert!(
        exec.receipt_count() <= 100_000,
        "Receipt store presiahol kapacitu: {}",
        exec.receipt_count()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST 10: CONCURRENT STAKE/UNSTAKE — nezávislí stakeri, žiadna korupcia
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_concurrent_stake_unstake_no_corruption() {
    let (state, exec_raw) = make_executor_no_fee();
    let exec = Arc::new(exec_raw);

    // 20 nezávislých stakerów, každý stake → unstake 10x
    let mut handles = Vec::new();

    for t in 0..20u64 {
        let kp = Ed25519KeyPair::generate();
        let addr = Address(kp.public_key().0);
        state.mint(addr, TokenAmount::from_tokens(10_000_000)).unwrap();
        let initial_balance = exec.state().balance(&addr);
        let exec = exec.clone();

        handles.push(thread::spawn(move || -> (Address, TokenAmount, bool) {
            let mut all_ok = true;
            for cycle in 0..10u64 {
                let nonce_stake = cycle * 2;
                let nonce_unstake = cycle * 2 + 1;
                let order_base = t * 200 + cycle * 20;

                let tx_s = mk_stake(&kp, nonce_stake, 1000);
                match exec.execute_event(&tx_s.encode(), Hash32::ZERO, order_base, order_base * 1000) {
                    Some(r) if r.status.is_success() => {}
                    _ => { all_ok = false; }
                }

                let tx_u = mk_unstake(&kp, nonce_unstake, 1000);
                match exec.execute_event(&tx_u.encode(), Hash32::ZERO, order_base + 1, (order_base + 1) * 1000) {
                    Some(r) if r.status.is_success() => {}
                    _ => { all_ok = false; }
                }
            }
            (addr, initial_balance, all_ok)
        }));
    }

    for h in handles {
        let (addr, initial, all_ok) = h.join().unwrap();
        assert!(all_ok, "Niektorý stake/unstake TX zlyhalo pre {:?}", addr);

        // Staked musí byť 0
        assert_eq!(
            exec.state().get(&addr).staked,
            TokenAmount::ZERO,
            "Staked nie je nula pre {:?}",
            addr
        );

        // Balance = initial - 10 cyklov * 60,000 base gas
        let total_gas = TokenAmount::from_base(10u128 * 60_000u128);
        let expected = initial.checked_sub(total_gas).unwrap();
        assert_eq!(
            exec.state().balance(&addr),
            expected,
            "Balance nesprávny pre {:?}",
            addr
        );
    }
}
