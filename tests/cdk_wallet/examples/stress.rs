//! Closed-loop load from independent, prewarmed CDK wallets.
use std::env;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context, Result};
use cdk::amount::SplitTarget;
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{CurrencyUnit, MeltQuoteState, PaymentMethod, Proofs};
use cdk::wallet::MeltOutcome;
use cdk::{Amount, Wallet};
use cdk_sqlite::wallet::memory;
use serde_json::json;
use tokio::task::JoinSet;

enum Operation {
    Mint,
    Swap(Proofs),
    Melt(Proofs, String),
}

async fn issue(wallet: &Wallet, count: usize, denomination: u64) -> Result<Proofs> {
    let amount = Amount::from(count as u64 * denomination);
    let quote = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(amount), None, None)
        .await?;
    wallet.check_mint_quote_status(&quote.id).await?;
    let split = SplitTarget::Values(vec![denomination.into(); count]);
    let proofs = wallet.mint(&quote.id, split, None).await?;
    ensure!(
        proofs.len() == count && proofs.iter().all(|p| p.amount == denomination.into()),
        "unexpected issuance"
    );
    Ok(proofs)
}

async fn execute(wallet: &Wallet, operation: Operation) -> Result<()> {
    match operation {
        Operation::Mint => {
            issue(wallet, 8, 1).await?;
        }
        Operation::Swap(proofs) => {
            let target = SplitTarget::Values(vec![1.into(); 8]);
            // With no send amount CDK stores all eight outputs as wallet change.
            wallet
                .swap(None, target, proofs, None, false, false)
                .await?;
        }
        Operation::Melt(proofs, invoice) => {
            let quote = wallet
                .melt_quote(PaymentMethod::BOLT11, invoice, None, None)
                .await?;
            ensure!(quote.amount == 16.into(), "unexpected invoice amount");
            let outcome = wallet
                .prepare_melt_proofs(&quote.id, proofs, Default::default())
                .await?
                .confirm_prefer_async()
                .await?;
            let result = match outcome {
                MeltOutcome::Paid(result) => result,
                MeltOutcome::Pending(_) => loop {
                    if let Some(result) = wallet
                        .finalize_pending_melts()
                        .await?
                        .into_iter()
                        .find(|result| result.quote_id() == quote.id)
                    {
                        break result;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                },
            };
            ensure!(
                result.state() == MeltQuoteState::Paid
                    && result.amount() == quote.amount
                    && result.payment_proof().is_some(),
                "melt did not settle"
            );
            let change = result
                .change()
                .context("missing melt change")?
                .total_amount()?;
            ensure!(
                result.amount() + result.fee_paid() + change == 32.into(),
                "unexpected melt change"
            );
        }
    }
    Ok(())
}

async fn prepare(
    url: &str,
    kind: &str,
    count: usize,
    invoices: Vec<String>,
) -> Result<(Wallet, Vec<Operation>)> {
    let wallet = Wallet::new(
        url,
        CurrencyUnit::Sat,
        Arc::new(memory::empty().await?),
        rand::random(),
        None,
    )?;
    wallet.disable_rate_limiting();
    ensure!(!wallet.is_rate_limited(), "client-side pacing is enabled");
    wallet.fetch_mint_info().await?;
    let mut operations = Vec::with_capacity(count);
    let mut invoices = invoices.into_iter();
    while operations.len() < count {
        let batch = (count - operations.len()).min(16);
        match kind {
            "mint" => operations.extend((0..batch).map(|_| Operation::Mint)),
            "swap" => {
                let proofs = issue(&wallet, batch * 8, 1).await?;
                operations.extend(proofs.chunks(8).map(|p| Operation::Swap(p.to_vec())));
            }
            "melt" => {
                for proof in issue(&wallet, batch, 32).await? {
                    operations.push(Operation::Melt(
                        vec![proof],
                        invoices.next().context("missing invoice")?,
                    ));
                }
            }
            _ => anyhow::bail!("unknown workload {kind}"),
        }
    }
    tokio::time::timeout(
        Duration::from_secs(30),
        execute(&wallet, operations.pop().context("missing warmup")?),
    )
    .await
    .context("warmup timed out")??;
    Ok((wallet, operations))
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6,
        "expected PORT WORKLOAD WALLETS ITERATIONS INVOICES"
    );
    let port: u16 = args[1].parse()?;
    let mint_url = format!("http://127.0.0.1:{port}");
    let clients: usize = args[3].parse()?;
    let iterations: usize = args[4].parse()?;
    ensure!(clients > 0 && iterations > 0, "empty workload");
    let per_wallet = iterations + 1;
    let invoices: Vec<String> = fs::read_to_string(&args[5])?
        .lines()
        .map(str::to_owned)
        .collect();
    const SETUP_TRIES: usize = 3;
    // Each warmup gets its own invoice. Measured invoices are used exactly once.
    let invoice_stride = iterations + SETUP_TRIES;
    ensure!(
        args[2] != "melt" || invoices.len() == clients * invoice_stride,
        "unexpected invoice count"
    );
    let mut prepared = vec![];
    let mut setup_errors = vec![];
    for lane in 0..clients {
        for attempt in 0..SETUP_TRIES {
            let mut bills = vec![];
            if args[2] == "melt" {
                let begin = lane * invoice_stride;
                bills.extend_from_slice(&invoices[begin..begin + iterations]);
                bills.push(invoices[begin + iterations + attempt].clone());
            }
            match prepare(&mint_url, &args[2], per_wallet, bills).await {
                Ok((wallet, operations)) => {
                    prepared.push((lane, wallet, operations));
                    break;
                }
                Err(error) => {
                    setup_errors.push(json!({"lane":lane,"reason":error.to_string()}));
                    if attempt + 1 == SETUP_TRIES {
                        return Err(error.context(format!("wallet {lane} setup")));
                    }
                }
            }
        }
    }
    println!("READY");
    io::stdout().flush()?;
    let mut line = String::new();
    ensure!(
        io::stdin().read_line(&mut line)? != 0,
        "runner disconnected"
    );

    let mut lanes = JoinSet::new();
    let start = Instant::now();
    for (lane, wallet, operations) in prepared {
        lanes.spawn(async move {
            let mut samples = vec![];
            for op in operations {
                let before = Instant::now();
                let result = tokio::time::timeout(Duration::from_secs(30), execute(&wallet, op))
                    .await
                    .unwrap_or_else(|_| Err(anyhow!("30s wallet timeout")));
                samples.push((
                    before.elapsed().as_micros(),
                    result.err().map(|e| e.to_string()),
                ));
            }
            // Exclude wallet destruction from the interval.
            (lane, samples, start.elapsed(), wallet)
        });
    }
    let mut rows = vec![];
    let mut elapsed = Duration::ZERO;
    while let Some(result) = lanes.join_next().await {
        let (lane, samples, finish, wallet) = result?;
        elapsed = elapsed.max(finish);
        rows.push((lane, samples, wallet));
    }
    println!("DONE");
    if args[2] == "swap" {
        for (_, results, wallet) in &rows {
            if results.iter().all(|(_, error)| error.is_none()) {
                let proofs = wallet.get_unspent_proofs().await?;
                ensure!(
                    proofs.len() == per_wallet * 8 && proofs.iter().all(|p| p.amount == 1.into()),
                    "swap balance or denominations changed"
                );
            }
        }
    }
    let mut samples = Vec::with_capacity(clients * iterations);
    for (lane, results, _) in rows {
        for (iteration, (us, error)) in results.into_iter().enumerate() {
            samples.push(json!({"lane": lane, "iteration": iteration, "us": us, "error": error}));
        }
    }
    println!(
        "{}",
        json!({"elapsed_s": elapsed.as_secs_f64(), "samples": samples, "setup_errors": setup_errors})
    );
    Ok(())
}
