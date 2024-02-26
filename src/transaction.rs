use std::collections::HashMap;

use reqwest::Request;
use serde::Deserialize;
use tower::Service;

use crate::{Client, EtherscanError, Response, Result};

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ContractExecutionStatus {
    is_error: String,
    err_description: String,
}

#[derive(Deserialize, Clone, Debug)]
struct TransactionReceiptStatus {
    status: String,
}

impl<S> Client<S>
where
    S: Service<Request, Response = reqwest::Response> + Clone,
    S::Error: std::fmt::Debug,
{
    /// Returns the status of a contract execution
    pub async fn check_contract_execution_status(
        &mut self,
        tx_hash: impl AsRef<str>,
    ) -> Result<()> {
        let query = self.create_query(
            "transaction",
            "getstatus",
            HashMap::from([("txhash", tx_hash.as_ref())]),
        );
        let response: Response<ContractExecutionStatus> = self.get_json(&query).await?;

        if response.result.is_error == "0" {
            Ok(())
        } else {
            Err(EtherscanError::ExecutionFailed(response.result.err_description))
        }
    }

    /// Returns the status of a transaction execution: `false` for failed and `true` for successful
    pub async fn check_transaction_receipt_status(
        &mut self,
        tx_hash: impl AsRef<str>,
    ) -> Result<()> {
        let query = self.create_query(
            "transaction",
            "gettxreceiptstatus",
            HashMap::from([("txhash", tx_hash.as_ref())]),
        );
        let response: Response<TransactionReceiptStatus> = self.get_json(&query).await?;

        match response.result.status.as_str() {
            "0" => Err(EtherscanError::TransactionReceiptFailed),
            "1" => Ok(()),
            err => Err(EtherscanError::BadStatusCode(err.to_string())),
        }
    }
}
