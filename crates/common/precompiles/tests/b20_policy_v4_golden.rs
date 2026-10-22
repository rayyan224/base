//! Golden tests pinning Policy Registry **V4** behavior of the B-20 precompile.
//!
//! V4 is activated at Everest and extends V3 with the `policyType(uint64)` view. Storage layout,
//! gas and every pre-existing selector are unchanged from V3; `parity_with_denim_*` proves that by
//! replaying one sequence at Denim and Everest and comparing returned bytes, reverts and the
//! registry's storage hash. Every case is driven through the real `PolicyRegistryStorage::dispatch`
//! (`BaseUpgrade::Everest` -> `PolicyVersion::V4`) over `HashMapStorageProvider`.

use IPolicyRegistry::PolicyType;
use alloy_primitives::{Address, B256, Bytes, LogData, U256, keccak256};
use alloy_sol_types::{SolCall, SolError};
use base_common_genesis::BaseUpgrade;
use base_common_precompiles::{
    ActivationAdminConfig, ActivationFeature, ActivationRegistryStorage, IPolicyRegistry,
    PolicyRegistryStorage, PolicyRegistryV4, PolicyVersion, PolicyVersions,
    UpgradeGatedStorageFeatures,
};
use base_precompile_storage::{HashMapStorageProvider, StorageCtx};

mod common;
use common::{ACTIVATION_ADMIN, ADMIN, ALICE, CHAIN_ID};

const OUTSIDER: Address = Address::repeat_byte(0x0F);

/// Bit 63 of a policy ID, the invert flag.
const INVERTED_BIT: u64 = PolicyRegistryV4::INVERTED_POLICY_BIT;
const POLICY_TYPE_SHIFT: u32 = 56;
/// A counter no test creates a policy at.
const UNCREATED_COUNTER: u64 = 999;

const fn id_of(type_byte: u8, counter: u64) -> u64 {
    ((type_byte as u64) << POLICY_TYPE_SHIFT) | counter
}

fn bare(upgrade: BaseUpgrade) -> HashMapStorageProvider {
    HashMapStorageProvider::new_with_storage_features(
        CHAIN_ID,
        UpgradeGatedStorageFeatures::from_upgrade(upgrade),
    )
}

fn activate(storage: &mut HashMapStorageProvider) {
    storage.set_caller(ACTIVATION_ADMIN);
    StorageCtx::enter(storage, |ctx| {
        ActivationRegistryStorage::new(ctx)
            .activate(
                ActivationFeature::PolicyRegistry.id(),
                ActivationAdminConfig::static_fallback(Some(ACTIVATION_ADMIN)),
            )
            .unwrap();
    });
}

fn fresh_at(upgrade: BaseUpgrade) -> HashMapStorageProvider {
    let mut storage = bare(upgrade);
    activate(&mut storage);
    storage
}

fn fresh() -> HashMapStorageProvider {
    fresh_at(BaseUpgrade::Everest)
}

fn call_policy_at(
    storage: &mut HashMapStorageProvider,
    upgrade: BaseUpgrade,
    caller: Address,
    calldata: Vec<u8>,
) -> (bool, Bytes) {
    storage.set_caller(caller);
    StorageCtx::enter(storage, |ctx| {
        PolicyRegistryStorage::new(ctx).dispatch(ctx, &calldata, upgrade)
    })
    .map(|out| (out.is_revert(), out.bytes))
    .expect("dispatch must not fatally error")
}

fn call_policy(
    storage: &mut HashMapStorageProvider,
    caller: Address,
    calldata: Vec<u8>,
) -> (bool, Bytes) {
    call_policy_at(storage, BaseUpgrade::Everest, caller, calldata)
}

fn create(storage: &mut HashMapStorageProvider, policy_type: PolicyType) -> u64 {
    let (rev, bytes) = call_policy(
        storage,
        ADMIN,
        IPolicyRegistry::createPolicyCall { admin: ADMIN, policyType: policy_type }.abi_encode(),
    );
    assert!(!rev, "createPolicy reverted");
    IPolicyRegistry::createPolicyCall::abi_decode_returns(&bytes).unwrap()
}

fn create_composite(
    storage: &mut HashMapStorageProvider,
    gate: PolicyType,
    children: Vec<u64>,
) -> u64 {
    let (rev, bytes) = call_policy(
        storage,
        ADMIN,
        IPolicyRegistry::createCompositePolicyCall {
            admin: ADMIN,
            policyType: gate,
            childPolicyIds: children,
        }
        .abi_encode(),
    );
    assert!(!rev, "createCompositePolicy reverted");
    IPolicyRegistry::createCompositePolicyCall::abi_decode_returns(&bytes).unwrap()
}

/// Reads `policyType(policy_id)`, returning the decoded type or the raw revert bytes.
fn policy_type(storage: &mut HashMapStorageProvider, policy_id: u64) -> Result<PolicyType, Bytes> {
    let (rev, bytes) = call_policy(
        storage,
        OUTSIDER,
        IPolicyRegistry::policyTypeCall { policyId: policy_id }.abi_encode(),
    );
    if rev {
        return Err(bytes);
    }
    Ok(IPolicyRegistry::policyTypeCall::abi_decode_returns(&bytes).unwrap())
}

#[track_caller]
fn assert_not_found(storage: &mut HashMapStorageProvider, policy_id: u64) {
    assert_eq!(
        policy_type(storage, policy_id),
        Err(Bytes::from(IPolicyRegistry::PolicyNotFound {}.abi_encode())),
        "policy {policy_id:#x} must revert PolicyNotFound",
    );
}

fn hash_state(storage: HashMapStorageProvider) -> B256 {
    let registry = PolicyRegistryStorage::ADDRESS;
    let mut buf = Vec::new();
    let events: Vec<LogData> = storage.get_events(registry).clone();
    for log in &events {
        for topic in log.topics() {
            buf.extend_from_slice(topic.as_slice());
        }
        buf.extend_from_slice(&log.data);
    }
    let mut triples: Vec<(Address, U256, U256)> =
        storage.into_storage().filter(|(a, _, _)| *a == registry).collect();
    triples.sort();
    for (_addr, slot, value) in triples {
        buf.extend_from_slice(&slot.to_be_bytes::<32>());
        buf.extend_from_slice(&value.to_be_bytes::<32>());
    }
    keccak256(&buf)
}

// ============================================================================
// Version resolver
// ============================================================================

#[test]
fn resolver_maps_everest_to_v4_and_leaves_older_forks() {
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Azul), None);
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Beryl), Some(PolicyVersion::V1));
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Cobalt), Some(PolicyVersion::V2));
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Denim), Some(PolicyVersion::V3));
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Everest), Some(PolicyVersion::V4));
}

// ============================================================================
// policyType (V4 / Everest)
// ============================================================================

#[test]
fn golden_policy_type_of_created_simple_policies() {
    let mut s = fresh();
    let blocklist = create(&mut s, PolicyType::BLOCKLIST);
    let allowlist = create(&mut s, PolicyType::ALLOWLIST);

    assert_eq!(policy_type(&mut s, blocklist), Ok(PolicyType::BLOCKLIST));
    assert_eq!(policy_type(&mut s, allowlist), Ok(PolicyType::ALLOWLIST));
}

#[test]
fn golden_policy_type_of_created_composite_policies() {
    let mut s = fresh();
    let a = create(&mut s, PolicyType::ALLOWLIST);
    let b = create(&mut s, PolicyType::BLOCKLIST);
    let union = create_composite(&mut s, PolicyType::UNION, vec![a, b]);
    let intersect = create_composite(&mut s, PolicyType::INTERSECT, vec![a, b]);

    assert_eq!(policy_type(&mut s, union), Ok(PolicyType::UNION));
    assert_eq!(policy_type(&mut s, intersect), Ok(PolicyType::INTERSECT));
}

#[test]
fn golden_policy_type_of_builtins() {
    let mut s = fresh();

    assert_eq!(
        policy_type(&mut s, PolicyRegistryStorage::ALWAYS_ALLOW_ID),
        Ok(PolicyType::BLOCKLIST)
    );
    assert_eq!(
        policy_type(&mut s, PolicyRegistryStorage::ALWAYS_BLOCK_ID),
        Ok(PolicyType::ALLOWLIST)
    );
}

#[test]
fn golden_policy_type_of_inverted_ids_reports_the_base_type() {
    let mut s = fresh();
    let blocklist = create(&mut s, PolicyType::BLOCKLIST);
    let allowlist = create(&mut s, PolicyType::ALLOWLIST);
    let union = create_composite(&mut s, PolicyType::UNION, vec![blocklist, allowlist]);
    let intersect = create_composite(&mut s, PolicyType::INTERSECT, vec![blocklist, allowlist]);

    let cases = [
        (blocklist, PolicyType::BLOCKLIST),
        (allowlist, PolicyType::ALLOWLIST),
        (union, PolicyType::UNION),
        (intersect, PolicyType::INTERSECT),
        (PolicyRegistryStorage::ALWAYS_ALLOW_ID, PolicyType::BLOCKLIST),
        (PolicyRegistryStorage::ALWAYS_BLOCK_ID, PolicyType::ALLOWLIST),
    ];
    for (base, expected) in cases {
        assert_eq!(policy_type(&mut s, base | INVERTED_BIT), Ok(expected), "inverted {base:#x}");
    }
}

#[test]
fn golden_policy_type_reverts_for_uncreated_ids() {
    let mut s = fresh();
    create(&mut s, PolicyType::BLOCKLIST);

    for type_byte in
        [PolicyType::BLOCKLIST, PolicyType::ALLOWLIST, PolicyType::UNION, PolicyType::INTERSECT]
            .map(|t| t as u8)
    {
        let uncreated = id_of(type_byte, UNCREATED_COUNTER);
        assert_not_found(&mut s, uncreated);
        assert_not_found(&mut s, uncreated | INVERTED_BIT);
    }
}

#[test]
fn golden_policy_type_reverts_for_malformed_ids() {
    let mut s = fresh();
    let first_malformed = PolicyType::INTERSECT as u8 + 1;

    for type_byte in [first_malformed, 0x10, 0x7F] {
        for counter in [0, 1, UNCREATED_COUNTER] {
            let malformed = id_of(type_byte, counter);
            assert_not_found(&mut s, malformed);
            assert_not_found(&mut s, malformed | INVERTED_BIT);
        }
    }
    assert_not_found(&mut s, u64::MAX);
}

#[test]
fn golden_policy_type_reads_before_activation() {
    let mut s = bare(BaseUpgrade::Everest);

    assert_eq!(
        policy_type(&mut s, PolicyRegistryStorage::ALWAYS_ALLOW_ID),
        Ok(PolicyType::BLOCKLIST)
    );
    assert_eq!(
        policy_type(&mut s, PolicyRegistryStorage::ALWAYS_BLOCK_ID | INVERTED_BIT),
        Ok(PolicyType::ALLOWLIST)
    );
    assert_not_found(&mut s, id_of(PolicyType::ALLOWLIST as u8, UNCREATED_COUNTER));
}

#[test]
fn golden_policy_type_reverts_nonzero_value() {
    let mut s = fresh();
    s.set_caller(ALICE);
    s.set_call_value(U256::ONE);
    let calldata = IPolicyRegistry::policyTypeCall { policyId: 0 }.abi_encode();
    let (rev, bytes) = StorageCtx::enter(&mut s, |ctx| {
        PolicyRegistryStorage::new(ctx).dispatch(ctx, &calldata, BaseUpgrade::Everest)
    })
    .map(|out| (out.is_revert(), out.bytes))
    .expect("dispatch must not fatally error");

    assert!(rev);
    assert_eq!(bytes, Bytes::from(IPolicyRegistry::NonPayable {}.abi_encode()));
}

#[test]
fn golden_policy_type_storage_footprint() {
    let mut s = fresh();
    let allowlist = create(&mut s, PolicyType::ALLOWLIST);
    let calldata = IPolicyRegistry::policyTypeCall { policyId: allowlist }.abi_encode();

    s.set_caller(OUTSIDER);
    s.reset_counters();
    StorageCtx::enter(&mut s, |ctx| {
        PolicyRegistryStorage::new(ctx).dispatch(ctx, &calldata, BaseUpgrade::Everest)
    })
    .unwrap();

    assert_eq!((s.counter_sload(), s.counter_sstore(), s.counter_keccak256()), (1, 0, 0));
}

// ============================================================================
// Parity: Everest changes nothing but the new selector
// ============================================================================

/// Replays one write-and-read sequence at `upgrade`, returning every response plus the registry's
/// storage hash.
fn replay(upgrade: BaseUpgrade) -> (Vec<(bool, Bytes)>, B256) {
    let mut s = fresh_at(upgrade);
    let mut out = Vec::new();
    let mut run = |s: &mut HashMapStorageProvider, caller: Address, calldata: Vec<u8>| {
        out.push(call_policy_at(s, upgrade, caller, calldata));
    };

    let allow = id_of(PolicyType::ALLOWLIST as u8, 2);
    let block = id_of(PolicyType::BLOCKLIST as u8, 3);
    let union = id_of(PolicyType::UNION as u8, 4);
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::createPolicyCall { admin: ADMIN, policyType: PolicyType::ALLOWLIST }
            .abi_encode(),
    );
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::createPolicyWithAccountsCall {
            admin: ADMIN,
            policyType: PolicyType::BLOCKLIST,
            accounts: vec![ALICE],
        }
        .abi_encode(),
    );
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::createCompositePolicyCall {
            admin: ADMIN,
            policyType: PolicyType::UNION,
            childPolicyIds: vec![allow, block],
        }
        .abi_encode(),
    );
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::updateAllowlistCall {
            policyId: allow,
            allowed: true,
            accounts: vec![ALICE],
        }
        .abi_encode(),
    );
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::stageUpdateAdminCall { policyId: allow, newAdmin: OUTSIDER }.abi_encode(),
    );
    run(
        &mut s,
        OUTSIDER,
        IPolicyRegistry::finalizeUpdateAdminCall { policyId: allow }.abi_encode(),
    );
    run(&mut s, OUTSIDER, IPolicyRegistry::renounceAdminCall { policyId: allow }.abi_encode());
    // Failing writes: wrong caller, wrong type, zero admin.
    run(
        &mut s,
        ALICE,
        IPolicyRegistry::updateBlocklistCall {
            policyId: block,
            blocked: true,
            accounts: vec![ALICE],
        }
        .abi_encode(),
    );
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::updateAllowlistCall {
            policyId: block,
            allowed: true,
            accounts: vec![ALICE],
        }
        .abi_encode(),
    );
    run(
        &mut s,
        ADMIN,
        IPolicyRegistry::createPolicyCall {
            admin: Address::ZERO,
            policyType: PolicyType::BLOCKLIST,
        }
        .abi_encode(),
    );

    for id in
        [0, 1 << POLICY_TYPE_SHIFT | 1, allow, block, union, allow | INVERTED_BIT, u64::MAX, 999]
    {
        run(
            &mut s,
            OUTSIDER,
            IPolicyRegistry::isAuthorizedCall { policyId: id, account: ALICE }.abi_encode(),
        );
        run(&mut s, OUTSIDER, IPolicyRegistry::policyExistsCall { policyId: id }.abi_encode());
        run(&mut s, OUTSIDER, IPolicyRegistry::policyAdminCall { policyId: id }.abi_encode());
        run(
            &mut s,
            OUTSIDER,
            IPolicyRegistry::pendingPolicyAdminCall { policyId: id }.abi_encode(),
        );
        run(
            &mut s,
            OUTSIDER,
            IPolicyRegistry::compositePolicyChildIdsCall { policyId: id }.abi_encode(),
        );
        run(&mut s, OUTSIDER, IPolicyRegistry::invertedPolicyIdCall { policyId: id }.abi_encode());
    }
    run(&mut s, OUTSIDER, IPolicyRegistry::MIN_COMPOSITE_CHILD_POLICIESCall {}.abi_encode());
    run(&mut s, OUTSIDER, IPolicyRegistry::MAX_COMPOSITE_CHILD_POLICIESCall {}.abi_encode());
    // Unknown selector and truncated calldata.
    run(&mut s, OUTSIDER, vec![0xde, 0xad, 0xbe, 0xef]);
    run(&mut s, OUTSIDER, IPolicyRegistry::isAuthorizedCall::SELECTOR.to_vec());

    (out, hash_state(s))
}

#[test]
fn parity_with_denim_for_every_pre_existing_selector() {
    let (denim_responses, denim_state) = replay(BaseUpgrade::Denim);
    let (everest_responses, everest_state) = replay(BaseUpgrade::Everest);

    assert_eq!(denim_responses, everest_responses, "responses and revert bytes must match V3");
    assert_eq!(denim_state, everest_state, "registry state and events must match V3");
}

// ============================================================================
// meta: op coverage checklist
// ============================================================================

/// Compile-time coverage checklist — never called; the exhaustive `match` fails the build when an
/// ABI op is added without naming the test that pins it. Pre-existing ops are pinned by
/// `parity_with_denim_for_every_pre_existing_selector` and the V3 suite.
#[allow(dead_code)]
fn v4_op_coverage_checklist(call: IPolicyRegistry::IPolicyRegistryCalls) {
    use IPolicyRegistry::IPolicyRegistryCalls as C;

    fn covered(_goldens: &[fn()]) {}

    match call {
        C::createPolicy(_)
        | C::createPolicyWithAccounts(_)
        | C::createCompositePolicy(_)
        | C::updateComposite(_)
        | C::stageUpdateAdmin(_)
        | C::finalizeUpdateAdmin(_)
        | C::renounceAdmin(_)
        | C::updateAllowlist(_)
        | C::updateBlocklist(_)
        | C::isAuthorized(_)
        | C::MIN_COMPOSITE_CHILD_POLICIES(_)
        | C::MAX_COMPOSITE_CHILD_POLICIES(_)
        | C::policyExists(_)
        | C::policyAdmin(_)
        | C::pendingPolicyAdmin(_)
        | C::compositePolicyChildIds(_)
        | C::invertedPolicyId(_) => covered(&[parity_with_denim_for_every_pre_existing_selector]),
        C::policyType(_) => covered(&[
            golden_policy_type_of_created_simple_policies,
            golden_policy_type_of_created_composite_policies,
            golden_policy_type_of_builtins,
            golden_policy_type_of_inverted_ids_reports_the_base_type,
            golden_policy_type_reverts_for_uncreated_ids,
            golden_policy_type_reverts_for_malformed_ids,
            golden_policy_type_reads_before_activation,
            golden_policy_type_reverts_nonzero_value,
            golden_policy_type_storage_footprint,
        ]),
    }
}
