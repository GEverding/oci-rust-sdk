use crate::auth::{AuthError, AuthProvider};
use crate::base_client::{encode_body, sign_request};
use crate::config::AuthConfig;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use reqwest::header::HeaderMap;
use reqwest::Response;
use serde_json::json;

pub struct QueryDetails {
    pub compartment_id: String,
    pub statement: String,
}

pub struct Nosql {
    auth_provider: Arc<dyn AuthProvider>,
    service_endpoint: String,
}

// Legacy struct for backward compatibility
#[deprecated(since = "0.3.0", note = "Use Nosql with AuthProvider instead")]
#[allow(dead_code)]
pub struct LegacyNosql {
    config: AuthConfig,
    service_endpoint: String,
}

pub struct TableLimits {
    pub max_read_units: u16,
    pub max_write_units: u16,
    pub max_storage_in_g_bs: u16,
}

pub struct CreateTableDetails {
    pub name: String,
    pub compartment_id: String,
    pub ddl_statement: String,
    pub table_limits: TableLimits,
}

impl Nosql {
    ///Creates a new `Nosql` which is the client necessary to interact with this type of object on OCI.
    ///
    ///## Example 1
    ///```no_run
    ///use oci_sdk::{
    ///    auth::ConfigFileAuth,
    ///    nosql::{Nosql},
    ///};
    ///use std::sync::Arc;
    ///
    ///let auth_provider = Arc::new(ConfigFileAuth::from_file(None, None).unwrap());
    ///let nosql = Nosql::new(auth_provider, None).await.unwrap();
    ///```
    ///
    /// ## Example 2
    ///
    ///```rust,no_run
    ///use oci_sdk::{
    ///    auth::InstancePrincipalAuth,
    ///    nosql::{Nosql},
    ///};
    ///use std::sync::Arc;
    ///
    ///let auth_provider = Arc::new(InstancePrincipalAuth::new(None));
    ///let nosql = Nosql::new(auth_provider, None).await.unwrap();
    ///```
    ///Returns the Nosql client.
    pub async fn new(
        auth_provider: Arc<dyn AuthProvider>,
        service_endpoint: Option<String>,
    ) -> Result<Nosql, AuthError> {
        let region = auth_provider.get_region().await?;
        let se = service_endpoint.unwrap_or(format!(
            "https://nosql.{}.oci.oraclecloud.com",
            region
        ));
        
        Ok(Nosql {
            auth_provider,
            service_endpoint: se,
        })
    }

    pub async fn create_table(
        &self,
        create_table_detais: CreateTableDetails,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let body_json = json!({
          "name": &create_table_detais.name,
          "compartmentId": &create_table_detais.compartment_id,
          "ddlStatement": &create_table_detais.ddl_statement,
          "tableLimits": {
            "maxReadUnits": create_table_detais.table_limits.max_read_units,
            "maxWriteUnits": create_table_detais.table_limits.max_write_units,
            "maxStorageInGBs": create_table_detais.table_limits.max_storage_in_g_bs
          }
        });

        let body = body_json.to_string();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );
        headers.insert("x-content-sha256", encode_body(&body).parse().unwrap());
        headers.insert("content-length", body.len().to_string().parse().unwrap());
        headers.insert(
            "content-type",
            String::from("application/json").parse().unwrap(),
        );

        let path = format!("/20190828/tables");

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "post",
            &path,
            &self.service_endpoint,
        )
        .await?;

        let response = client
            .post(format!("{}{}", self.service_endpoint, path))
            .body(body)
            .headers(headers)
            .send()
            .await?;

        return Ok(response);
    }

    pub async fn query(
        &self,
        query_details: QueryDetails,
        limit: u16,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();

        let body_json = json!({
          "compartmentId": &query_details.compartment_id,
          "statement": &query_details.statement,
        });

        let body = body_json.to_string();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.to_rfc2822().replace("+0000", "GMT").parse().unwrap(),
        );
        headers.insert("x-content-sha256", encode_body(&body).parse().unwrap());
        headers.insert("content-length", body.len().to_string().parse().unwrap());
        headers.insert(
            "content-type",
            String::from("application/json").parse().unwrap(),
        );

        let path = format!("/20190828/query?limit={}", limit);

        sign_request(
            self.auth_provider.as_ref(),
            &mut headers,
            "post",
            &path,
            &self.service_endpoint,
        )
        .await?;

        let response = client
            .post(format!("{}{}", self.service_endpoint, path))
            .body(body)
            .headers(headers)
            .send()
            .await?;

        return Ok(response);
    }
}

// Legacy implementation for backward compatibility
#[allow(deprecated)]
impl LegacyNosql {
    pub fn new(config: AuthConfig, service_endpoint: Option<String>) -> LegacyNosql {
        let se = service_endpoint.unwrap_or(format!(
            "https://nosql.{}.oci.oraclecloud.com",
            config.region
        ));
        LegacyNosql {
            config,
            service_endpoint: se,
        }
    }

    // Note: Legacy methods are not implemented as they require OpenSSL
    // Users should migrate to the new Nosql struct with AuthProvider
}
