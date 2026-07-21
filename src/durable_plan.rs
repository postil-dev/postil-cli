use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::header::HeaderValue;
use serde::Serialize;

const ENDPOINT_ENV: &str = "POSTIL_LARGE_REVIEW_PLAN_ENDPOINT";
const TOKEN_ENV: &str = "POSTIL_LARGE_REVIEW_PLAN_TOKEN";
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DurableReviewPlan {
    version: u8,
    pub plan_sha256: String,
    pub direct_hunks: u32,
    pub semantic_hunks: u32,
    pub unreviewed_hunks: u32,
    pub selected_batches: u32,
    pub total_batches: u32,
    pub concurrency: u32,
    pub request_timeout_seconds: u32,
    pub review_budget_seconds: u32,
}

impl DurableReviewPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        plan_sha256: String,
        direct_hunks: u32,
        semantic_hunks: u32,
        unreviewed_hunks: u32,
        selected_batches: u32,
        total_batches: u32,
        concurrency: u32,
        request_timeout_seconds: u32,
        review_budget_seconds: u32,
    ) -> Result<Self> {
        if plan_sha256.len() != 64
            || !plan_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(anyhow!(
                "durable review plan has an invalid SHA-256 identity"
            ));
        }
        if selected_batches == 0
            || selected_batches > total_batches
            || concurrency == 0
            || request_timeout_seconds == 0
            || review_budget_seconds == 0
        {
            return Err(anyhow!("durable review plan metadata is invalid"));
        }
        Ok(Self {
            version: 1,
            plan_sha256,
            direct_hunks,
            semantic_hunks,
            unreviewed_hunks,
            selected_batches,
            total_batches,
            concurrency,
            request_timeout_seconds,
            review_budget_seconds,
        })
    }
}

pub(crate) struct DurablePlanRegistrar {
    endpoint: reqwest::Url,
    authorization: HeaderValue,
}

impl DurablePlanRegistrar {
    pub(crate) fn from_env() -> Result<Option<Self>> {
        let configured = |name| -> Result<Option<String>> {
            std::env::var_os(name)
                .map(|value| {
                    value
                        .into_string()
                        .map_err(|_| anyhow!("{name} must contain valid UTF-8"))
                })
                .transpose()
        };
        let endpoint = configured(ENDPOINT_ENV)?;
        let token = configured(TOKEN_ENV)?;
        let (endpoint, token) = match (endpoint, token) {
            (None, None) => return Ok(None),
            (Some(endpoint), Some(token))
                if !endpoint.trim().is_empty() && !token.is_empty() && token.trim() == token =>
            {
                (endpoint, token)
            }
            _ => {
                return Err(anyhow!(
                    "{ENDPOINT_ENV} and {TOKEN_ENV} must be set together"
                ));
            }
        };
        let endpoint = reqwest::Url::parse(&endpoint)
            .map_err(|_| anyhow!("{ENDPOINT_ENV} must be an absolute loopback HTTP URL"))?;
        let loopback = endpoint
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if endpoint.scheme() != "http"
            || !loopback
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(anyhow!(
                "{ENDPOINT_ENV} must be an absolute loopback HTTP URL without credentials, query, or fragment"
            ));
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| anyhow!("{TOKEN_ENV} is not a valid bearer credential"))?;
        authorization.set_sensitive(true);
        Ok(Some(Self {
            endpoint,
            authorization,
        }))
    }

    pub(crate) async fn register(&self, plan: &DurableReviewPlan) -> Result<()> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(REGISTRATION_TIMEOUT)
            .build()
            .map_err(|_| anyhow!("could not prepare durable review plan registration"))?;
        let response = client
            .post(self.endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .json(plan)
            .send()
            .await
            .map_err(|_| anyhow!("durable review plan registration request failed"))?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(anyhow!(
                "durable review plan registration returned HTTP {}",
                response.status().as_u16()
            ));
        }
        Ok(())
    }
}
