//! ABI dispatch for the EIP-8130 transaction context precompile.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use base_common_genesis::BaseUpgrade;
use base_precompile_storage::{BasePrecompileError, PrecompileResult, StorageCtx};

use crate::{
    CALLDATA_WORD_GAS,
    ITransactionContext::{self, ITransactionContextCalls as C},
    macros::decode_precompile_call,
    tx_context::storage::TxContextStorage,
};

/// EIP-8130 getter output price per 32-byte word: the EVM copy-word cost
/// (`W_copy`, revm's `gas::COPY`). Output words are priced at `W_copy` per the
/// EIP-8130 output schedule; from Everest, input words are also priced at
/// [`CALLDATA_WORD_GAS`], like the nonce manager. `gas_matches_evm_reference`
/// pins this to revm's canonical constant as a drift tripwire.
const OUTPUT_WORD_GAS: u64 = 3;

impl TxContextStorage<'_> {
    /// ABI-dispatches transaction context calldata and prices encoded output.
    ///
    /// EIP-8130 charges [`OUTPUT_WORD_GAS`] per 32 bytes returned at every fork.
    /// From Everest it also charges [`CALLDATA_WORD_GAS`] per 32 bytes of input,
    /// before decode. The backing transient read is unmetered, so no TLOAD opcode
    /// charge is exposed to the caller.
    pub fn dispatch(
        &self,
        ctx: StorageCtx<'_>,
        calldata: &[u8],
        upgrade: BaseUpgrade,
    ) -> PrecompileResult {
        // Transaction-context getters are nonpayable; reject attached ETH first.
        if !ctx.call_value().is_zero() {
            return ctx
                .error_result(BasePrecompileError::revert(ITransactionContext::NonPayable {}));
        }
        // Everest+ charges calldata ingestion before decode, like the nonce manager; earlier forks are frozen.
        if upgrade >= BaseUpgrade::Everest {
            let calldata_cost =
                (calldata.len() as u64).div_ceil(32).saturating_mul(CALLDATA_WORD_GAS);
            if let Err(error) = ctx.deduct_gas(calldata_cost) {
                return ctx.error_result(error);
            }
        }
        let result = self.inner(calldata).and_then(|output| {
            let words = u64::try_from(output.len().div_ceil(32))
                .map_err(|_| BasePrecompileError::OutOfGas)?;
            let output_cost =
                words.checked_mul(OUTPUT_WORD_GAS).ok_or(BasePrecompileError::OutOfGas)?;
            ctx.deduct_gas(output_cost)?;
            Ok(output)
        });
        ctx.result_output(result, |output| output)
    }

    fn inner(&self, calldata: &[u8]) -> base_precompile_storage::Result<Bytes> {
        match decode_precompile_call!(calldata, ITransactionContext::ITransactionContextCalls) {
            C::getTransactionSender(_) => Ok(
                ITransactionContext::getTransactionSenderCall::abi_encode_returns(&self.sender()?)
                    .into(),
            ),
            C::getTransactionPayer(_) => {
                Ok(ITransactionContext::getTransactionPayerCall::abi_encode_returns(&self.payer()?)
                    .into())
            }
            C::getTransactionSenderActorId(_) => {
                Ok(ITransactionContext::getTransactionSenderActorIdCall::abi_encode_returns(
                    &self.sender_actor_id()?,
                )
                .into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, U256, address, b256};
    use alloy_sol_types::{SolCall, SolError};
    use base_common_genesis::BaseUpgrade;
    use base_precompile_storage::{HashMapStorageProvider, StorageCtx};
    use rstest::rstest;

    use crate::{CALLDATA_WORD_GAS, ITransactionContext, TxContextStorage};

    const SENDER: Address = address!("0x1111111111111111111111111111111111111111");
    const PAYER: Address = address!("0x2222222222222222222222222222222222222222");
    const SENDER_ACTOR_ID: B256 =
        b256!("0x3333333333333333333333333333333333333333333333333333333333333333");
    const ORIGIN: Address = address!("0x9999999999999999999999999999999999999999");
    const UNKNOWN_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn dispatch(storage: &mut HashMapStorageProvider, calldata: &[u8]) -> Vec<u8> {
        StorageCtx::enter(storage, |ctx| {
            TxContextStorage::new(ctx)
                .dispatch(ctx, calldata, BaseUpgrade::Cobalt)
                .expect("dispatch should not fail fatally")
                .bytes
                .to_vec()
        })
    }

    fn dispatch_at(
        storage: &mut HashMapStorageProvider,
        calldata: &[u8],
        upgrade: BaseUpgrade,
    ) -> base_precompile_storage::PrecompileResult {
        StorageCtx::enter(storage, |ctx| {
            TxContextStorage::new(ctx).dispatch(ctx, calldata, upgrade)
        })
    }

    fn oversized_unknown_calldata() -> Vec<u8> {
        let mut calldata = UNKNOWN_SELECTOR.to_vec();
        calldata.resize(100, 0);
        calldata
    }

    #[test]
    fn dispatch_returns_resolved_context() {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, |ctx| {
            TxContextStorage::new(ctx).set_context(SENDER, PAYER, SENDER_ACTOR_ID).unwrap();
        });

        let sender =
            dispatch(&mut storage, &ITransactionContext::getTransactionSenderCall {}.abi_encode());
        assert_eq!(
            ITransactionContext::getTransactionSenderCall::abi_decode_returns(&sender).unwrap(),
            SENDER
        );

        let payer =
            dispatch(&mut storage, &ITransactionContext::getTransactionPayerCall {}.abi_encode());
        assert_eq!(
            ITransactionContext::getTransactionPayerCall::abi_decode_returns(&payer).unwrap(),
            PAYER
        );

        let actor_id = dispatch(
            &mut storage,
            &ITransactionContext::getTransactionSenderActorIdCall {}.abi_encode(),
        );
        assert_eq!(
            ITransactionContext::getTransactionSenderActorIdCall::abi_decode_returns(&actor_id)
                .unwrap(),
            SENDER_ACTOR_ID
        );
    }

    /// Drift tripwire: `OUTPUT_WORD_GAS` is the EVM copy-word cost (`W_copy`). If
    /// revm reprices `gas::COPY`, this fails so the output-word charge is
    /// re-decided deliberately rather than tracked silently (mirrors the
    /// `Eip8130GasSchedule` primitive tripwire).
    #[test]
    fn gas_matches_evm_reference() {
        assert_eq!(super::OUTPUT_WORD_GAS, revm::interpreter::gas::COPY);
    }

    #[rstest]
    #[case::cobalt(BaseUpgrade::Cobalt)]
    #[case::denim(BaseUpgrade::Denim)]
    fn getters_charge_only_output_gas_before_everest(#[case] upgrade: BaseUpgrade) {
        let calls = [
            ITransactionContext::getTransactionSenderCall {}.abi_encode(),
            ITransactionContext::getTransactionPayerCall {}.abi_encode(),
            ITransactionContext::getTransactionSenderActorIdCall {}.abi_encode(),
        ];

        for calldata in calls {
            let mut storage = HashMapStorageProvider::new(1);
            let output =
                dispatch_at(&mut storage, &calldata, upgrade).expect("getter should succeed");

            assert_eq!(output.bytes.len(), 32);
            assert_eq!(storage.gas_deducted(), super::OUTPUT_WORD_GAS);
        }
    }

    #[rstest]
    #[case::everest(BaseUpgrade::Everest)]
    #[case::zenith(BaseUpgrade::Zenith)]
    fn getters_charge_calldata_and_output_gas_from_everest(#[case] upgrade: BaseUpgrade) {
        let calls = [
            ITransactionContext::getTransactionSenderCall {}.abi_encode(),
            ITransactionContext::getTransactionPayerCall {}.abi_encode(),
            ITransactionContext::getTransactionSenderActorIdCall {}.abi_encode(),
        ];

        for calldata in calls {
            let mut storage = HashMapStorageProvider::new(1);
            let output =
                dispatch_at(&mut storage, &calldata, upgrade).expect("getter should succeed");

            assert_eq!(output.bytes.len(), 32);
            assert_eq!(storage.gas_deducted(), CALLDATA_WORD_GAS + super::OUTPUT_WORD_GAS);
        }
    }

    #[test]
    fn everest_return_values_match_denim() {
        let calls = [
            ITransactionContext::getTransactionSenderCall {}.abi_encode(),
            ITransactionContext::getTransactionPayerCall {}.abi_encode(),
            ITransactionContext::getTransactionSenderActorIdCall {}.abi_encode(),
        ];

        for calldata in calls {
            let mut denim = HashMapStorageProvider::new(1);
            let mut everest = HashMapStorageProvider::new(1);
            for storage in [&mut denim, &mut everest] {
                StorageCtx::enter(storage, |ctx| {
                    TxContextStorage::new(ctx).set_context(SENDER, PAYER, SENDER_ACTOR_ID).unwrap();
                });
            }

            let denim_output =
                dispatch_at(&mut denim, &calldata, BaseUpgrade::Denim).expect("denim getter");
            let everest_output =
                dispatch_at(&mut everest, &calldata, BaseUpgrade::Everest).expect("everest getter");

            assert_eq!(denim_output.bytes, everest_output.bytes);
        }
    }

    #[test]
    fn dispatch_falls_back_to_origin_when_unset() {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_origin(ORIGIN);

        let sender =
            dispatch(&mut storage, &ITransactionContext::getTransactionSenderCall {}.abi_encode());
        assert_eq!(
            ITransactionContext::getTransactionSenderCall::abi_decode_returns(&sender).unwrap(),
            ORIGIN
        );

        let payer =
            dispatch(&mut storage, &ITransactionContext::getTransactionPayerCall {}.abi_encode());
        assert_eq!(
            ITransactionContext::getTransactionPayerCall::abi_decode_returns(&payer).unwrap(),
            ORIGIN
        );
    }

    #[rstest]
    #[case::cobalt(BaseUpgrade::Cobalt)]
    #[case::denim(BaseUpgrade::Denim)]
    #[case::everest(BaseUpgrade::Everest)]
    #[case::zenith(BaseUpgrade::Zenith)]
    fn dispatch_rejects_call_with_nonzero_value(#[case] upgrade: BaseUpgrade) {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_call_value(U256::from(1u64));
        let calldata = ITransactionContext::getTransactionSenderCall {}.abi_encode();

        let output = dispatch_at(&mut storage, &calldata, upgrade)
            .expect("nonzero value should revert, not fail fatally");

        assert!(output.is_revert());
        assert_eq!(output.bytes, Bytes::from(ITransactionContext::NonPayable {}.abi_encode()));
        assert_eq!(storage.gas_deducted(), 0);
    }

    #[rstest]
    #[case::cobalt(BaseUpgrade::Cobalt, 0)]
    #[case::denim(BaseUpgrade::Denim, 0)]
    #[case::everest(BaseUpgrade::Everest, CALLDATA_WORD_GAS)]
    #[case::zenith(BaseUpgrade::Zenith, CALLDATA_WORD_GAS)]
    fn dispatch_reverts_on_unknown_selector(#[case] upgrade: BaseUpgrade, #[case] gas: u64) {
        let mut storage = HashMapStorageProvider::new(1);
        let output = dispatch_at(&mut storage, &UNKNOWN_SELECTOR, upgrade)
            .expect("unknown selector should revert, not fail fatally");

        assert!(output.is_revert());
        assert_eq!(storage.gas_deducted(), gas);

        let mut cobalt = HashMapStorageProvider::new(1);
        let cobalt_output = dispatch_at(&mut cobalt, &UNKNOWN_SELECTOR, BaseUpgrade::Cobalt)
            .expect("unknown selector should revert");
        assert_eq!(output.bytes, cobalt_output.bytes);
    }

    #[rstest]
    #[case::cobalt(BaseUpgrade::Cobalt)]
    #[case::denim(BaseUpgrade::Denim)]
    fn oversized_unknown_calldata_charges_nothing_before_everest(#[case] upgrade: BaseUpgrade) {
        let mut storage = HashMapStorageProvider::new(1);
        let output = dispatch_at(&mut storage, &oversized_unknown_calldata(), upgrade)
            .expect("unknown selector should revert, not fail fatally");

        assert!(output.is_revert());
        assert_eq!(storage.gas_deducted(), 0);
    }

    #[rstest]
    #[case::everest(BaseUpgrade::Everest)]
    #[case::zenith(BaseUpgrade::Zenith)]
    fn oversized_unknown_calldata_charges_per_word_from_everest(#[case] upgrade: BaseUpgrade) {
        let mut storage = HashMapStorageProvider::new(1);
        let output = dispatch_at(&mut storage, &oversized_unknown_calldata(), upgrade)
            .expect("unknown selector should revert, not fail fatally");

        assert!(output.is_revert());
        assert_eq!(storage.gas_deducted(), 4 * CALLDATA_WORD_GAS);
    }
}
