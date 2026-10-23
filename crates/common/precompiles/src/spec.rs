use base_common_genesis::BaseUpgrade;
use base_precompile_storage::StorageFeatures;

/// Resolves Base upgrades into fork-dependent persistent-storage features.
#[derive(Debug, Clone, Copy)]
pub struct UpgradeGatedStorageFeatures;

impl UpgradeGatedStorageFeatures {
    /// Returns the persistent-storage features active at `upgrade`.
    pub fn from_upgrade(upgrade: BaseUpgrade) -> StorageFeatures {
        if upgrade >= BaseUpgrade::Everest {
            StorageFeatures::Everest
        } else if upgrade >= BaseUpgrade::Cobalt {
            StorageFeatures::Cobalt
        } else {
            StorageFeatures::Legacy
        }
    }
}

/// A chain spec that can select Base precompile sets.
pub trait BasePrecompileSpec: Copy + Eq + From<BaseUpgrade> + Into<BaseUpgrade> {
    /// Returns the default precompile spec.
    fn default_precompile_spec() -> Self {
        BaseUpgrade::LATEST.into()
    }

    /// Returns the Base upgrade associated with this spec.
    fn upgrade(self) -> BaseUpgrade {
        self.into()
    }
}

impl<S> BasePrecompileSpec for S where S: Copy + Eq + From<BaseUpgrade> + Into<BaseUpgrade> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_features_follow_upgrade() {
        let upgrades = [
            BaseUpgrade::Bedrock,
            BaseUpgrade::Regolith,
            BaseUpgrade::Canyon,
            BaseUpgrade::Delta,
            BaseUpgrade::Ecotone,
            BaseUpgrade::Fjord,
            BaseUpgrade::Granite,
            BaseUpgrade::Holocene,
            BaseUpgrade::PectraBlobSchedule,
            BaseUpgrade::Isthmus,
            BaseUpgrade::Jovian,
            BaseUpgrade::Azul,
            BaseUpgrade::Beryl,
            BaseUpgrade::Cobalt,
            BaseUpgrade::Denim,
            BaseUpgrade::Everest,
            BaseUpgrade::Zenith,
        ];
        let mut previous = StorageFeatures::Legacy;
        for upgrade in upgrades {
            let features = UpgradeGatedStorageFeatures::from_upgrade(upgrade);
            assert!(features >= previous, "{upgrade:?} must not lower storage features");
            if upgrade < BaseUpgrade::Cobalt {
                assert_eq!(features, StorageFeatures::Legacy, "{upgrade:?}");
            } else if upgrade < BaseUpgrade::Everest {
                assert_eq!(features, StorageFeatures::Cobalt, "{upgrade:?}");
            } else {
                assert_eq!(features, StorageFeatures::Everest, "{upgrade:?}");
            }
            previous = features;
        }

        assert_eq!(
            UpgradeGatedStorageFeatures::from_upgrade(BaseUpgrade::Beryl),
            StorageFeatures::Legacy,
        );
        assert_eq!(
            UpgradeGatedStorageFeatures::from_upgrade(BaseUpgrade::Denim),
            StorageFeatures::Cobalt,
        );
        assert_eq!(
            UpgradeGatedStorageFeatures::from_upgrade(BaseUpgrade::Everest),
            StorageFeatures::Everest,
        );
        assert_eq!(
            UpgradeGatedStorageFeatures::from_upgrade(BaseUpgrade::Zenith),
            StorageFeatures::Everest,
        );
    }

    #[test]
    fn everest_keeps_cobalt_features() {
        assert!(StorageFeatures::Everest.dynamic_storage_tail_cleanup_enabled());
        assert!(StorageFeatures::Everest.selector_only_abi_decode_errors_enabled());
        assert!(StorageFeatures::Everest.batched_sload_discount_enabled());
        assert!(!StorageFeatures::Cobalt.batched_sload_discount_enabled());
        assert!(!StorageFeatures::Legacy.batched_sload_discount_enabled());
    }
}
