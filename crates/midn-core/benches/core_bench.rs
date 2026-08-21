// crates/midn-core/benches/core_bench.rs
//! midn-core benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-core
//!
//! ## Gates
//!
//! | Benchmark                    | Gate     | Rationale                                  |
//! |------------------------------|----------|--------------------------------------------|
//! | ecs_spawn                    | < 1 µs   | Build #7 baseline: 1.07 ns                 |
//! | ecs_spawn_with_all_components| < 5 µs   | Build #7 baseline: 397 ns (iter_batched)   |
//! | ecs_despawn_with_zeroize     | < 5 µs   | Build #7 baseline: 208 ns                  |
//! | ecs_lookup_auth_state        | < 100 ns | Build #7 baseline: 14 ns                   |
//! | registry_lookup              | < 100 ns | Build #7 baseline: 17 ns                   |
//! | hss_provision                | < 1 µs   | Build #7 baseline: 90 ns                   |

use criterion::{
    black_box, criterion_group, criterion_main,
    BatchSize, Criterion,
};

use midn_ecs::{
    AuthState, IdentityComponent, ImsiRegistry, SecurityContext, TunnelComponent, World,
};
use midn_core::hss::Hss;

// ── ECS world benchmarks ──────────────────────────────────────────────────────

fn bench_ecs_spawn(c: &mut Criterion) {
    // Gate: < 1 µs
    //
    // iter_batched, not a single shared World + plain b.iter: this is what
    // actually caused CI's benchmark job to die (SIGTERM, exit 143)
    // partway through collecting ecs_spawn's samples. A single World
    // shared across every warmup + measurement iteration never gets
    // despawned — Criterion auto-scales iteration count from an early,
    // cheap-looking estimate (this session: 44M iterations for a 5-second
    // window), and spawn() genuinely is O(1) per call, but with nothing
    // ever freed, that's 44M live entries accumulating across 7 component
    // Vecs (identity/auth/security/nas_security/tunnel/security5g/
    // nas_security5g) — real gigabytes of growth mid-benchmark, not a
    // black_box measurement artifact. iter_batched gives each batch a
    // fresh, small World, exactly like bench_ecs_spawn_with_all_components
    // immediately below already does, for the same underlying reason (see
    // that function's own comment) — this function just wasn't using the
    // same pattern despite sharing the risk.
    c.bench_function("ecs_spawn", |b| {
        b.iter_batched(
            || World::with_capacity(128),
            |mut world| {
                let id = world.spawn();
                black_box(id)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_ecs_spawn_with_all_components(c: &mut Criterion) {
    // Gate: < 5 µs
    // iter_batched: each sample gets a fresh World so we measure insert cost,
    // not HashMap resize.
    c.bench_function("ecs_spawn_with_all_components", |b| {
        b.iter_batched(
            || World::with_capacity(16),
            |mut world| {
                let id = world.spawn();
                world.insert_identity(id, IdentityComponent {
                    imsi: black_box(234_15_1234567890_u64),
                    enb_ue_s1ap_id: 0,
                    ue_ip: [10, 0, 0, 1],
                });
                world.set_auth_state(id, AuthState::Unauthenticated);
                world.insert_security(id, SecurityContext::new_empty());
                world.set_tunnel(id, TunnelComponent {
                    ul_teid: black_box(0x0001_0000),
                    dl_teid: 0,
                    enb_addr: [192, 168, 1, 100],
                });
                black_box(id)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_ecs_despawn_with_zeroize(c: &mut Criterion) {
    // Gate: < 5 µs — measures despawn + SecurityContext ZeroizeOnDrop.
    // The zeroize cost is the security contract — do NOT optimize it away.
    let mut group = c.benchmark_group("ecs_despawn");

    group.bench_function("with_security_context_zeroize", |b| {
        let mut world = World::with_capacity(4);

        let seed = world.spawn();
        world.insert_identity(seed, IdentityComponent {
            imsi: 234_15_0000000001_u64, enb_ue_s1ap_id: 0, ue_ip: [10, 0, 1, 1],
        });
        world.set_auth_state(seed, AuthState::Authenticated);
        let mut ctx = SecurityContext::new_empty();
        ctx.ck = [0xAA; 16];
        ctx.ik = [0xBB; 16];
        world.insert_security(seed, ctx);
        world.set_tunnel(seed, TunnelComponent { ul_teid: 1, dl_teid: 2, enb_addr: [192, 168, 0, 1] });

        b.iter(|| {
            world.despawn(black_box(seed));

            let id = world.spawn();
            world.insert_identity(id, IdentityComponent {
                imsi: 234_15_0000000001_u64, enb_ue_s1ap_id: 0, ue_ip: [10, 0, 1, 1],
            });
            world.set_auth_state(id, AuthState::Authenticated);
            let mut ctx = SecurityContext::new_empty();
            ctx.ck = [0xAA; 16];
            world.insert_security(id, ctx);
            world.set_tunnel(id, TunnelComponent { ul_teid: 1, dl_teid: 2, enb_addr: [192, 168, 0, 1] });
            black_box(id)
        })
    });

    group.finish();
}

fn bench_ecs_lookup(c: &mut Criterion) {
    let mut world = World::with_capacity(1024);

    for i in 0..1000u64 {
        let id = world.spawn();
        world.insert_identity(id, IdentityComponent { imsi: i, enb_ue_s1ap_id: 0, ue_ip: [0; 4] });
        world.set_auth_state(id, AuthState::Authenticated);
    }

    let mid = 500u32;

    // Gate: < 100 ns
    c.bench_function("ecs_lookup_auth_state", |b| {
        b.iter(|| world.auth_state(black_box(mid)))
    });

    c.bench_function("ecs_is_authenticated", |b| {
        b.iter(|| world.is_authenticated(black_box(mid)))
    });
}

fn bench_ecs_bulk_scan(c: &mut Criterion) {
    let mut world = World::with_capacity(16_384);

    for i in 0..10_000u64 {
        let id = world.spawn();
        world.insert_identity(id, IdentityComponent { imsi: i, enb_ue_s1ap_id: 0, ue_ip: [0; 4] });
        world.set_auth_state(id, if i % 3 == 0 {
            AuthState::Authenticated
        } else {
            AuthState::Unauthenticated
        });
    }

    // Informational — no gate. Dense Vec scan vs old HashMap.
    c.bench_function("ecs_authenticated_count_10k", |b| {
        b.iter(|| world.authenticated_count())
    });
}

// ── IMSI registry benchmarks ──────────────────────────────────────────────────

fn bench_registry(c: &mut Criterion) {
    let mut registry = ImsiRegistry::new();
    let mut world    = World::with_capacity(1024);

    for i in 0..500u64 {
        let id = world.spawn();
        registry.register(i * 10, id);
    }

    // Gate: < 100 ns
    c.bench_function("registry_lookup_hit", |b| {
        b.iter(|| registry.lookup(black_box(2500)))
    });

    c.bench_function("registry_lookup_miss", |b| {
        b.iter(|| registry.lookup(black_box(999_999_999)))
    });

    // Gate: < 500 ns
    //
    // iter_batched with a fresh, empty ImsiRegistry per batch, not the
    // shared `registry` above with an always-incrementing key — same
    // unbounded-growth class of bug bench_ecs_spawn had (found reading
    // this file while root-causing that one): `ImsiRegistry` is a
    // `HashMap<u64, EntityId>` internally, and a distinct key every single
    // one of tens of millions of iterations means the map itself grows
    // that large before the run ends, never actually measuring a steady-
    // state O(1) insert. The key value is irrelevant here (the map is
    // always empty beforehand), so no need to keep incrementing it.
    c.bench_function("registry_register", |b| {
        let id = world.spawn();
        b.iter_batched(
            ImsiRegistry::new,
            |mut reg| reg.register(black_box(12345), black_box(id)),
            BatchSize::SmallInput,
        )
    });
}

// ── HSS benchmarks ────────────────────────────────────────────────────────────

fn bench_hss_provision(c: &mut Criterion) {
    // Gate: < 1 µs
    //
    // iter_batched with a fresh Hss per batch, not a shared Hss with an
    // always-incrementing imsi — same unbounded-growth class of bug
    // bench_ecs_spawn had (see that function's comment): `Hss::subscribers`
    // is a `HashMap<u64, SubscriberRecord>`, and a distinct imsi every
    // iteration across tens of millions of them means the map grows that
    // large mid-run instead of measuring a steady-state single insert.
    // Fixed imsi value is fine — the map is always empty beforehand.
    c.bench_function("hss_provision_subscriber", |b| {
        let ki  = midn_auth::keys::AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = midn_auth::keys::OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();

        b.iter_batched(
            Hss::new,
            |mut hss| hss.provision(black_box(234_15_0000000001_u64), ki.clone(), opc.clone()),
            BatchSize::SmallInput,
        )
    });
}

fn bench_hss_lookup(c: &mut Criterion) {
    let mut hss = Hss::new();
    hss.provision_hex(
        234_15_1234567890_u64,
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "cd63cb71954a9f4e48a5994e37a02baf",
    ).unwrap();

    // Gate: < 50 ns
    c.bench_function("hss_lookup_miss", |b| {
        b.iter(|| hss.has_subscriber(black_box(999_99_9999999999_u64)))
    });

    c.bench_function("hss_lookup_hit", |b| {
        b.iter(|| hss.has_subscriber(black_box(234_15_1234567890_u64)))
    });
}

// ── Size / alignment verification ─────────────────────────────────────────────
//
// Wired into ecs_world_benches below (was dead code before this session —
// defined but never added to any criterion_group!, hence the "function
// bench_component_sizes is never used" warning in CI). Not a real
// benchmark (no c.bench_function call, just an assert), but criterion_group!
// still runs every listed function once when the harness starts, which is
// exactly the "runs whenever benchmarks run" regression guard this looks
// like it was meant to be.
fn bench_component_sizes(_c: &mut Criterion) {
    assert_eq!(core::mem::size_of::<TunnelComponent>(), 12,
        "TunnelComponent size regressed");
}

// ── Criterion groups ──────────────────────────────────────────────────────────

criterion_group!(
    ecs_world_benches,
    bench_ecs_spawn,
    bench_ecs_spawn_with_all_components,
    bench_ecs_despawn_with_zeroize,
    bench_ecs_lookup,
    bench_ecs_bulk_scan,
    bench_component_sizes,
);

criterion_group!(
    registry_benches,
    bench_registry,
);

criterion_group!(
    hss_benches,
    bench_hss_provision,
    bench_hss_lookup,
);

criterion_main!(ecs_world_benches, registry_benches, hss_benches);
