//! Precompile entry point for the EIP-8130 transaction context.

use alloy_evm::precompiles::PrecompilesMap;
use base_common_genesis::BaseUpgrade;

use crate::{TxContextStorage, UpgradeGatedStorageFeatures, macros::base_precompile};

/// Entry point for the EIP-8130 transaction context precompile.
///
/// Only installed at Cobalt or later (see `BasePrecompiles::install_with_observer`).
/// The caller passes the active `upgrade` through the constructor, and the wrapper
/// derives its storage features from it via `UpgradeGatedStorageFeatures::from_upgrade`
/// — the same signal every other install site consumes — so features stay locked to
/// the fork that drove the install decision.
#[derive(Debug, Default, Clone, Copy)]
pub struct TxContext;

impl TxContext {
    /// Installs the `TxContext` precompile, gated to the storage features
    /// active at `upgrade`.
    pub fn install(precompiles: &mut PrecompilesMap, upgrade: BaseUpgrade) {
        let storage_features = UpgradeGatedStorageFeatures::from_upgrade(upgrade);
        let precompile = base_precompile!(
            "TxContext",
            storage_features: storage_features,
            |ctx, calldata| TxContextStorage::new(ctx).dispatch(ctx, calldata, upgrade),
        );
        precompiles.extend_precompiles(core::iter::once((TxContextStorage::ADDRESS, precompile)));
    }
}

#[cfg(test)]
mod tests {
    use alloy_evm::{
        EvmInternals,
        eth::EthEvmContext,
        precompiles::{Precompile, PrecompileInput, PrecompilesMap},
    };
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::SolCall;
    use base_common_genesis::BaseUpgrade;
    use revm::{
        database::EmptyDB,
        precompile::{PrecompileHalt, PrecompileOutput, Precompiles},
        primitives::hardfork::SpecId,
    };
    use rstest::rstest;

    use crate::{CALLDATA_WORD_GAS, ITransactionContext, TxContext, TxContextStorage};

    fn call_with_gas(upgrade: BaseUpgrade, gas: u64) -> PrecompileOutput {
        let mut precompiles = PrecompilesMap::from_static(Precompiles::cancun());
        TxContext::install(&mut precompiles, upgrade);
        let precompile = precompiles.get(&TxContextStorage::ADDRESS).unwrap();

        let mut ctx = EthEvmContext::new(EmptyDB::default(), SpecId::AMSTERDAM);
        let data = ITransactionContext::getTransactionSenderCall {}.abi_encode();
        precompile
            .call(PrecompileInput {
                data: &data,
                gas,
                reservoir: 0,
                caller: Address::ZERO,
                value: U256::ZERO,
                target_address: TxContextStorage::ADDRESS,
                is_static: false,
                bytecode_address: TxContextStorage::ADDRESS,
                internals: EvmInternals::from_context(&mut ctx),
            })
            .expect("no fatal error")
    }

    #[test]
    fn install_places_wrapper_at_storage_address() {
        let mut precompiles = PrecompilesMap::from_static(Precompiles::cancun());
        TxContext::install(&mut precompiles, BaseUpgrade::Cobalt);

        assert!(precompiles.get(&TxContextStorage::ADDRESS).is_some());
    }

    #[rstest]
    #[case::everest_out_of_gas(BaseUpgrade::Everest, CALLDATA_WORD_GAS - 1)]
    #[case::zenith_out_of_gas(BaseUpgrade::Zenith, CALLDATA_WORD_GAS - 1)]
    fn calldata_gas_out_of_gas_halts_from_everest(#[case] upgrade: BaseUpgrade, #[case] gas: u64) {
        let output = call_with_gas(upgrade, gas);

        assert_eq!(output.halt_reason(), Some(&PrecompileHalt::OutOfGas));
    }

    #[rstest]
    #[case::denim_ignores_calldata_gas(BaseUpgrade::Denim, CALLDATA_WORD_GAS - 1, 3)]
    #[case::cobalt_ignores_calldata_gas(BaseUpgrade::Cobalt, CALLDATA_WORD_GAS - 1, 3)]
    #[case::everest_exact_gas(BaseUpgrade::Everest, 9, 9)]
    fn calldata_gas_succeeds_when_covered(
        #[case] upgrade: BaseUpgrade,
        #[case] gas: u64,
        #[case] gas_used: u64,
    ) {
        let output = call_with_gas(upgrade, gas);

        assert!(output.halt_reason().is_none() && !output.is_revert());
        assert_eq!(output.gas_used, gas_used);
    }
}
