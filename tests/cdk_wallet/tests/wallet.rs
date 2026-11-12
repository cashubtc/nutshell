use std::env;
use std::sync::Arc;
use std::time::Duration;

use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{
    CurrencyUnit, MeltQuoteState, PaymentMethod, SecretKey, SpendingConditions, State,
};
use cdk::wallet::{ReceiveOptions, SendOptions, Wallet};
use cdk::Amount;
use cdk_sqlite::wallet::memory;

async fn wallet(seed: [u8; 64]) -> Wallet {
    Wallet::new(
        &env::var("CDK_TEST_MINT_URL").expect("CDK_TEST_MINT_URL must point at the test mint"),
        CurrencyUnit::Sat,
        Arc::new(memory::empty().await.unwrap()),
        seed,
        None,
    )
    .unwrap()
}

async fn fund(wallet: &Wallet) {
    let quote = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(100.into()), None, None)
        .await
        .unwrap();
    let proofs = wallet
        .wait_and_mint_quote(quote, Default::default(), None, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(proofs.total_amount().unwrap(), 100.into());
    assert_eq!(wallet.total_balance().await.unwrap(), 100.into());
}

#[tokio::test]
async fn mint_quote_and_proofs() {
    let wallet = wallet(rand::random()).await;
    assert!(wallet.fetch_mint_info().await.unwrap().is_some());
    let expected_fee = env::var("CDK_TEST_INPUT_FEE_PPK")
        .expect("CDK_TEST_INPUT_FEE_PPK must match the test mint")
        .parse::<u64>()
        .unwrap();
    assert_eq!(
        wallet.active_keyset().await.unwrap().input_fee_ppk,
        expected_fee
    );
    fund(&wallet).await;
    let proofs = wallet.get_unspent_proofs().await.unwrap();
    assert!(proofs.iter().all(|proof| proof.dleq.is_some()));
    let states = wallet.check_proofs_spent(proofs).await.unwrap();
    assert!(!states.is_empty());
    assert!(states.iter().all(|proof| proof.state == State::Unspent));
}

async fn transfer(conditions: Option<SpendingConditions>, options: ReceiveOptions) {
    let sender = wallet(rand::random()).await;
    let receiver = wallet(rand::random()).await;
    fund(&sender).await;

    // 17 sats forces a swap of the initially minted denominations.
    let amount = Amount::from(17);
    let prepared = sender
        .prepare_send(
            amount,
            SendOptions {
                conditions,
                include_fee: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let fee = prepared.fee();
    let token = prepared.confirm(None).await.unwrap();
    receiver.verify_token_dleq(&token).await.unwrap();

    let encoded = token.to_string();
    let received = receiver.receive(&encoded, options.clone()).await.unwrap();
    assert_eq!(received, amount);
    assert_eq!(receiver.total_balance().await.unwrap(), amount);
    assert_eq!(
        sender.total_balance().await.unwrap(),
        Amount::from(100) - amount - fee
    );

    // A fresh wallet forces the replay through the mint rather than a local cache.
    let replay_wallet = wallet(rand::random()).await;
    assert!(replay_wallet.receive(&encoded, options).await.is_err());
    assert_eq!(replay_wallet.total_balance().await.unwrap(), Amount::ZERO);
    assert_eq!(receiver.total_balance().await.unwrap(), amount);
}

#[tokio::test]
async fn send_receive_and_double_spend() {
    transfer(None, ReceiveOptions::default()).await;
}

#[tokio::test]
async fn p2pk_send_receive() {
    let key = SecretKey::generate();
    transfer(
        Some(SpendingConditions::new_p2pk(key.public_key(), None)),
        ReceiveOptions {
            p2pk_signing_keys: vec![key],
            ..Default::default()
        },
    )
    .await;
}

#[tokio::test]
async fn htlc_send_receive() {
    let preimage = SecretKey::generate().to_secret_hex();
    transfer(
        Some(SpendingConditions::new_htlc(preimage.clone(), None).unwrap()),
        ReceiveOptions {
            preimages: vec![preimage],
            ..Default::default()
        },
    )
    .await;
}

#[tokio::test]
async fn restore_unspent_proofs_from_seed() {
    let seed = rand::random();
    let original = wallet(seed).await;
    let receiver = wallet(rand::random()).await;
    fund(&original).await;
    let token = original
        .prepare_send(
            17.into(),
            SendOptions {
                include_fee: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .confirm(None)
        .await
        .unwrap();
    receiver
        .receive(&token.to_string(), ReceiveOptions::default())
        .await
        .unwrap();

    let expected = original.total_balance().await.unwrap();
    let restored = wallet(seed).await;
    assert_eq!(restored.total_balance().await.unwrap(), Amount::ZERO);
    assert_eq!(restored.restore().await.unwrap().unspent, expected);
    assert_eq!(restored.total_balance().await.unwrap(), expected);

    // Restored signatures must remain spendable by CDK.
    let token = restored
        .prepare_send(10.into(), SendOptions::default())
        .await
        .unwrap()
        .confirm(None)
        .await
        .unwrap();
    receiver
        .receive(&token.to_string(), ReceiveOptions::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn melt_quote_payment_and_change() {
    let wallet = wallet(rand::random()).await;
    fund(&wallet).await;
    let quote = wallet
        .melt_quote(
            PaymentMethod::BOLT11,
            env::var("CDK_TEST_INVOICE").expect("CDK_TEST_INVOICE must be a FakeWallet invoice"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(quote.amount, 16.into());
    let prepared = wallet
        .prepare_melt(&quote.id, Default::default())
        .await
        .unwrap();
    let swap_fee = prepared.swap_fee();
    let result = prepared.confirm().await.unwrap();
    assert_eq!(result.state(), MeltQuoteState::Paid);
    assert_eq!(result.amount(), quote.amount);
    assert!(result.payment_proof().is_some());
    assert_eq!(
        wallet
            .check_melt_quote_status(&quote.id)
            .await
            .unwrap()
            .state,
        MeltQuoteState::Paid
    );
    assert_eq!(
        wallet.total_balance().await.unwrap(),
        Amount::from(100) - quote.amount - result.fee_paid() - swap_fee
    );
    assert!(
        result.change().is_some(),
        "melt must return unused proofs as change"
    );
}
