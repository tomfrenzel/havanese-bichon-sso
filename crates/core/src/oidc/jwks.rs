//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::raise_error;
use serde::Deserialize;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);
const JWKS_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

struct CachedJwks {
    set: JwkSet,
    fetched_at: Instant,
    jwks_uri: String,
    last_forced_refresh: Option<Instant>,
}

static JWKS_CACHE: RwLock<Option<CachedJwks>> = RwLock::new(None);

pub async fn get_jwks(jwks_uri: &str, force_refresh: bool) -> BichonResult<JwkSet> {
    if let Ok(guard) = JWKS_CACHE.read() {
        if let Some(cached) = guard.as_ref() {
            if cached.jwks_uri == jwks_uri {
                let fresh = cached.fetched_at.elapsed() < JWKS_CACHE_TTL;
                let forced_refresh_allowed = cached
                    .last_forced_refresh
                    .map(|last| last.elapsed() >= FORCED_REFRESH_INTERVAL)
                    .unwrap_or(true);
                if fresh && (!force_refresh || !forced_refresh_allowed) {
                    return Ok(cached.set.clone());
                }
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(JWKS_HTTP_TIMEOUT)
        .build()
        .map_err(|e| {
            raise_error!(
                format!("Failed to build HTTP client for OIDC JWKS: {}", e),
                ErrorCode::InternalError
            )
        })?;

    let response = client.get(jwks_uri).send().await.map_err(|e| {
        raise_error!(
            format!("OIDC JWKS request to {} failed: {}", jwks_uri, e),
            ErrorCode::HttpResponseError
        )
    })?;

    if !response.status().is_success() {
        return Err(raise_error!(
            format!(
                "OIDC JWKS returned non-success status {} for {}",
                response.status(),
                jwks_uri
            ),
            ErrorCode::HttpResponseError
        ));
    }

    let set: JwkSet = response.json().await.map_err(|e| {
        raise_error!(
            format!("Failed to parse OIDC JWKS: {}", e),
            ErrorCode::HttpResponseError
        )
    })?;

    if let Ok(mut guard) = JWKS_CACHE.write() {
        *guard = Some(CachedJwks {
            set: set.clone(),
            fetched_at: Instant::now(),
            jwks_uri: jwks_uri.to_string(),
            last_forced_refresh: force_refresh.then(Instant::now),
        });
    }

    Ok(set)
}
