//! [`Cloud`] against real AWS: DynamoDB (the registry), SSM (guard state and
//! the claim credential) and IoT (the claim certificate's status).
//!
//! Credentials come from the default chain; the owner runs with
//! `AWS_PROFILE=...`. Nothing here is exercised by the tests.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use aws_config::Region;
use aws_sdk_dynamodb::config::ProvideCredentials;
use aws_sdk_dynamodb::error::DisplayErrorContext;
use aws_sdk_dynamodb::operation::delete_item::DeleteItemError;
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValuesOnConditionCheckFailure};
use aws_sdk_iot::types::CertificateStatus;

use crate::cloud::short_id;
use crate::cloud::{
    ClaimCredential, Cloud, Delete, Put, Secret, CLAIM_CERT_PARAMETER, CLAIM_KEY_PARAMETER,
    CLAIM_POLICY, GUARD_STATE_PARAMETER,
};
use crate::record::Record;

pub struct Aws {
    table: String,
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
    iot: aws_sdk_iot::Client,
}

impl Aws {
    /// Loads the configuration and checks up front that credentials resolve:
    /// otherwise the SDK fails later with a dispatch error that does not say
    /// what is actually missing.
    pub async fn connect(region: &str, table: &str) -> Result<Self> {
        let config = aws_config::from_env()
            .region(Region::new(region.to_string()))
            .load()
            .await;
        let provider = config
            .credentials_provider()
            .ok_or_else(|| anyhow!("no AWS credentials provider is configured"))?;
        provider.provide_credentials().await.map_err(|e| {
            anyhow!(
                "AWS credentials not found ({e}). Set AWS_PROFILE to a configured profile \
                 (and `aws sso login` if it is an SSO profile)."
            )
        })?;
        Ok(Self {
            table: table.to_string(),
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            ssm: aws_sdk_ssm::Client::new(&config),
            iot: aws_sdk_iot::Client::new(&config),
        })
    }

    async fn parameter(&self, name: &str, decrypt: bool) -> Result<String> {
        let out = self
            .ssm
            .get_parameter()
            .name(name)
            .with_decryption(decrypt)
            .send()
            .await
            .map_err(|e| anyhow!("{}", DisplayErrorContext(e)))
            .with_context(|| format!("SSM GetParameter {name}"))?;
        out.parameter()
            .and_then(|p| p.value())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("SSM parameter {name} has no value"))
    }

    fn key(mac: &str) -> HashMap<String, AttributeValue> {
        HashMap::from([("mac_address".to_string(), AttributeValue::S(mac.into()))])
    }
}

fn provisioned(item: &HashMap<String, AttributeValue>) -> bool {
    matches!(item.get("provisioned"), Some(AttributeValue::Bool(true)))
}

impl Cloud for Aws {
    async fn guard_state(&self) -> Result<String> {
        self.parameter(GUARD_STATE_PARAMETER, false).await
    }

    async fn put_record(&self, record: &Record, overwrite: bool) -> Result<Put> {
        let mut put = self
            .dynamodb
            .put_item()
            .table_name(&self.table)
            .set_item(Some(record.item()));
        if !overwrite {
            put = put.condition_expression("attribute_not_exists(mac_address)");
        }
        match put.send().await {
            Ok(_) => Ok(Put::Written),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(Put::AlreadyRegistered)
            }
            Err(e) => Err(anyhow!("{}", DisplayErrorContext(e)))
                .with_context(|| format!("DynamoDB PutItem into {}", self.table)),
        }
    }

    async fn get_provisioned(&self, mac: &str) -> Result<Option<bool>> {
        let out = self
            .dynamodb
            .get_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(mac)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| anyhow!("{}", DisplayErrorContext(e)))
            .with_context(|| format!("DynamoDB GetItem {mac} from {}", self.table))?;
        Ok(out.item().map(provisioned))
    }

    async fn delete_record_if_unprovisioned(&self, mac: &str) -> Result<Delete> {
        let result = self
            .dynamodb
            .delete_item()
            .table_name(&self.table)
            .set_key(Some(Self::key(mac)))
            .condition_expression("attribute_exists(mac_address) AND provisioned = :f")
            .expression_attribute_values(":f", AttributeValue::Bool(false))
            .return_values_on_condition_check_failure(ReturnValuesOnConditionCheckFailure::AllOld)
            .send()
            .await;
        match result {
            Ok(_) => Ok(Delete::Deleted),
            Err(e) => match e.as_service_error() {
                Some(DeleteItemError::ConditionalCheckFailedException(failed)) => {
                    // The record exists, so provisioned is true (or unreadable,
                    // which keeps it too); no item means there is no record.
                    Ok(if failed.item().is_some() {
                        Delete::Provisioned
                    } else {
                        Delete::Missing
                    })
                }
                _ => Err(anyhow!("{}", DisplayErrorContext(e)))
                    .with_context(|| format!("DynamoDB DeleteItem {mac} from {}", self.table)),
            },
        }
    }

    async fn claim_credential(&self) -> Result<ClaimCredential> {
        Ok(ClaimCredential {
            certificate_pem: self.parameter(CLAIM_CERT_PARAMETER, true).await?,
            private_key: Secret::new(self.parameter(CLAIM_KEY_PARAMETER, true).await?),
        })
    }

    async fn claim_policy_targets(&self) -> Result<Vec<String>> {
        let mut targets = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let out = self
                .iot
                .list_targets_for_policy()
                .policy_name(CLAIM_POLICY)
                .set_marker(marker.take())
                .send()
                .await
                .map_err(|e| anyhow!("{}", DisplayErrorContext(e)))
                .with_context(|| format!("IoT ListTargetsForPolicy {CLAIM_POLICY}"))?;
            targets.extend(out.targets().iter().cloned());
            match out.next_marker() {
                Some(next) if !next.is_empty() => marker = Some(next.to_string()),
                _ => return Ok(targets),
            }
        }
    }

    async fn set_claim_active(&self, cert_id: &str, active: bool) -> Result<()> {
        let status = if active {
            CertificateStatus::Active
        } else {
            CertificateStatus::Inactive
        };
        self.iot
            .update_certificate()
            .certificate_id(cert_id)
            .new_status(status.clone())
            .send()
            .await
            .map_err(|e| anyhow!("{}", DisplayErrorContext(e)))
            .with_context(|| format!("IoT UpdateCertificate {} {status:?}", short_id(cert_id)))?;
        Ok(())
    }
}
