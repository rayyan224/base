//! Parity tests pinning Policy Registry **V3** (activated at Denim) to V2 (Cobalt).
//!
//! V3 is a behavior-preserving scaffold, so one scripted call sequence is driven through the real
//! `PolicyRegistryStorage` dispatch at Cobalt and at Denim. Every call must return identical
//! revert flag, bytes and gas, and the registry must end with identical events and storage.

use IPolicyRegistry::PolicyType;
use alloy_primitives::{Address, Bytes, LogData, U256};
use alloy_sol_types::SolCall;
use base_common_genesis::BaseUpgrade;
use base_common_precompiles::{
    ActivationAdminConfig, ActivationFeature, ActivationRegistryStorage, IPolicyRegistry,
    PolicyAbi, PolicyRegistryStorage, PolicyVersion, PolicyVersions, UpgradeGatedStorageFeatures,
};
use base_precompile_storage::{HashMapStorageProvider, StorageCtx};

mod common;
use common::{ACTIVATION_ADMIN, ADMIN, ALICE, BOB, CHAIN_ID};

const OUTSIDER: Address = Address::repeat_byte(0x0F);

type CallRecord = (bool, Bytes, u64);
type Snapshot = (Vec<CallRecord>, Vec<LogData>, Vec<(Address, U256, U256)>);

struct Run {
    upgrade: BaseUpgrade,
    storage: HashMapStorageProvider,
    records: Vec<CallRecord>,
}

impl Run {
    fn new(upgrade: BaseUpgrade) -> Self {
        let mut storage = HashMapStorageProvider::new_with_storage_features(
            CHAIN_ID,
            UpgradeGatedStorageFeatures::from_upgrade(upgrade),
        );
        storage.set_caller(ACTIVATION_ADMIN);
        StorageCtx::enter(&mut storage, |ctx| {
            ActivationRegistryStorage::new(ctx)
                .activate(
                    ActivationFeature::PolicyRegistry.id(),
                    ActivationAdminConfig::static_fallback(Some(ACTIVATION_ADMIN)),
                )
                .unwrap();
        });
        Self { upgrade, storage, records: Vec::new() }
    }

    fn call(&mut self, caller: Address, calldata: Vec<u8>) -> CallRecord {
        self.storage.set_caller(caller);
        let upgrade = self.upgrade;
        let out = StorageCtx::enter(&mut self.storage, |ctx| {
            PolicyRegistryStorage::new(ctx).dispatch(ctx, &calldata, upgrade)
        })
        .expect("dispatch must not fatally error");
        let record = (out.is_revert(), out.bytes, out.gas_used);
        self.records.push(record.clone());
        record
    }

    fn create(&mut self, policy_type: PolicyType) -> u64 {
        let (rev, bytes, _) = self.call(
            ADMIN,
            IPolicyRegistry::createPolicyCall { admin: ADMIN, policyType: policy_type }
                .abi_encode(),
        );
        assert!(!rev);
        IPolicyRegistry::createPolicyCall::abi_decode_returns(&bytes).unwrap()
    }

    fn script(&mut self) {
        let a = self.create(PolicyType::ALLOWLIST);
        let b = self.create(PolicyType::ALLOWLIST);
        let blocklist = self.create(PolicyType::BLOCKLIST);

        self.call(
            ADMIN,
            IPolicyRegistry::createPolicyWithAccountsCall {
                admin: ADMIN,
                policyType: PolicyType::ALLOWLIST,
                accounts: vec![ALICE, BOB],
            }
            .abi_encode(),
        );
        self.call(
            ADMIN,
            IPolicyRegistry::updateAllowlistCall {
                policyId: a,
                allowed: true,
                accounts: vec![ALICE],
            }
            .abi_encode(),
        );
        self.call(
            ADMIN,
            IPolicyRegistry::updateBlocklistCall {
                policyId: blocklist,
                blocked: true,
                accounts: vec![BOB],
            }
            .abi_encode(),
        );
        self.call(
            ADMIN,
            IPolicyRegistry::createCompositePolicyCall {
                admin: ADMIN,
                policyType: PolicyType::UNION,
                childPolicyIds: vec![a, b],
            }
            .abi_encode(),
        );
        let composite = (u64::from(PolicyType::UNION as u8) << 56) | 5;
        self.call(
            ADMIN,
            IPolicyRegistry::updateCompositeCall {
                policyId: composite,
                childPolicyIds: vec![b, blocklist],
            }
            .abi_encode(),
        );
        self.call(
            ADMIN,
            IPolicyRegistry::stageUpdateAdminCall { policyId: a, newAdmin: BOB }.abi_encode(),
        );
        self.call(BOB, IPolicyRegistry::finalizeUpdateAdminCall { policyId: a }.abi_encode());
        self.call(BOB, IPolicyRegistry::renounceAdminCall { policyId: a }.abi_encode());

        for policy_id in [0, 1, a, b, blocklist, composite, 999] {
            self.call(
                OUTSIDER,
                IPolicyRegistry::isAuthorizedCall { policyId: policy_id, account: ALICE }
                    .abi_encode(),
            );
            self.call(
                OUTSIDER,
                IPolicyRegistry::policyExistsCall { policyId: policy_id }.abi_encode(),
            );
            self.call(
                OUTSIDER,
                IPolicyRegistry::policyAdminCall { policyId: policy_id }.abi_encode(),
            );
            self.call(
                OUTSIDER,
                IPolicyRegistry::pendingPolicyAdminCall { policyId: policy_id }.abi_encode(),
            );
            self.call(
                OUTSIDER,
                IPolicyRegistry::compositePolicyChildIdsCall { policyId: policy_id }.abi_encode(),
            );
        }
        self.call(OUTSIDER, IPolicyRegistry::MIN_COMPOSITE_CHILD_POLICIESCall {}.abi_encode());
        self.call(OUTSIDER, IPolicyRegistry::MAX_COMPOSITE_CHILD_POLICIESCall {}.abi_encode());

        // Reverts and wire rejections.
        self.call(
            ADMIN,
            IPolicyRegistry::createPolicyCall {
                admin: Address::ZERO,
                policyType: PolicyType::ALLOWLIST,
            }
            .abi_encode(),
        );
        self.call(
            OUTSIDER,
            IPolicyRegistry::updateAllowlistCall {
                policyId: b,
                allowed: true,
                accounts: vec![ALICE],
            }
            .abi_encode(),
        );
        self.call(
            ADMIN,
            IPolicyRegistry::createCompositePolicyCall {
                admin: ADMIN,
                policyType: PolicyType::INTERSECT,
                childPolicyIds: vec![b],
            }
            .abi_encode(),
        );
        self.call(
            ADMIN,
            IPolicyRegistry::createPolicyWithAccountsCall {
                admin: ADMIN,
                policyType: PolicyType::ALLOWLIST,
                accounts: vec![ALICE; 65],
            }
            .abi_encode(),
        );
        self.call(OUTSIDER, vec![0xde, 0xad, 0xbe, 0xef]);
        self.call(OUTSIDER, vec![0x01, 0x02]);
        let mut truncated =
            IPolicyRegistry::isAuthorizedCall { policyId: 0, account: ALICE }.abi_encode();
        truncated.truncate(20);
        self.call(OUTSIDER, truncated);
        let mut payable_probe = IPolicyRegistry::policyExistsCall { policyId: 0 }.abi_encode();
        payable_probe.extend_from_slice(&[0u8; 32]);
        self.call(OUTSIDER, payable_probe);
    }

    fn snapshot(self) -> Snapshot {
        let events = self.storage.get_events(PolicyRegistryStorage::ADDRESS).clone();
        let mut triples: Vec<(Address, U256, U256)> = self
            .storage
            .into_storage()
            .filter(|(address, _, _)| *address == PolicyRegistryStorage::ADDRESS)
            .collect();
        triples.sort();
        (self.records, events, triples)
    }
}

#[test]
fn denim_resolves_to_v3_and_older_forks_are_unchanged() {
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Azul), None);
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Beryl), Some(PolicyVersion::V1));
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Cobalt), Some(PolicyVersion::V2));
    assert_eq!(PolicyVersions::from_base_upgrade(BaseUpgrade::Denim), Some(PolicyVersion::V3));
    assert_eq!(PolicyVersion::V3.abi(), PolicyAbi::V2);
}

#[test]
fn denim_matches_cobalt_results_reverts_events_storage_and_gas() {
    let mut cobalt = Run::new(BaseUpgrade::Cobalt);
    cobalt.script();
    let mut denim = Run::new(BaseUpgrade::Denim);
    denim.script();

    let (cobalt_records, cobalt_events, cobalt_storage) = cobalt.snapshot();
    let (denim_records, denim_events, denim_storage) = denim.snapshot();

    assert!(cobalt_records.iter().any(|(revert, _, _)| *revert), "script must exercise reverts");
    assert!(cobalt_records.iter().any(|(revert, _, _)| !*revert));
    assert!(!cobalt_events.is_empty());
    assert_eq!(denim_records, cobalt_records);
    assert_eq!(denim_events, cobalt_events);
    assert_eq!(denim_storage, cobalt_storage);
}
