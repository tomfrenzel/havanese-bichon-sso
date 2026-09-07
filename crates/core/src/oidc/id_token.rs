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
use crate::oidc::jwks::{get_jwks, Jwk, JwkSet};
use crate::raise_error;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::{digest, hmac, signature};
use serde::Deserialize;
use serde_json::Value;

/// Constant-time byte-slice equality. Used for comparing security-sensitive
/// values (nonces, tokens) where a variable-time compare would leak the
/// value one byte at a time through timing side-channels.
fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Claims we care about for user identification. Extra claims are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    #[serde(default)]
    pub aud: Value,
    pub sub: String,
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    typ: Option<String>,
}

pub struct VerifyParams<'a> {
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub expected_nonce: &'a str,
    /// Client secret bytes, required for HS256 verification. Ignored for other algs.
    pub client_secret: &'a [u8],
    pub jwks_uri: &'a str,
    pub supported_algorithms: &'a [String],
    /// Clock skew tolerance in seconds.
    pub clock_skew_secs: i64,
    /// Current unix time in seconds.
    pub now_secs: i64,
}

fn split_jwt(token: &str) -> BichonResult<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    match (header, payload, signature, parts.next()) {
        (Some(h), Some(p), Some(s), None) => Ok((h, p, s)),
        _ => Err(raise_error!(
            "ID token is not a well-formed JWT (expected 3 segments)".into(),
            ErrorCode::InvalidParameter
        )),
    }
}

fn b64url_decode(s: &str) -> BichonResult<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| {
        raise_error!(
            format!("Failed to base64url-decode ID token segment: {}", e),
            ErrorCode::InvalidParameter
        )
    })
}

fn audience_matches(claim: &Value, expected: &str) -> bool {
    match claim {
        Value::String(s) => s == expected,
        Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn matching_key<'a>(set: &'a JwkSet, header: &Header) -> BichonResult<&'a Jwk> {
    let expected_kty = match header.alg.as_str() {
        "RS256" => "RSA",
        "ES256" => "EC",
        _ => unreachable!(),
    };
    let candidates: Vec<&Jwk> = set
        .keys
        .iter()
        .filter(|key| {
            key.kty == expected_kty
                && key.key_use.as_deref() != Some("enc")
                && key
                    .alg
                    .as_deref()
                    .map(|alg| alg == header.alg)
                    .unwrap_or(true)
                && header
                    .kid
                    .as_deref()
                    .map(|kid| key.kid.as_deref() == Some(kid))
                    .unwrap_or(true)
        })
        .collect();

    if candidates.len() != 1 {
        return Err(raise_error!(
            format!(
                "OIDC JWKS contains {} matching keys for alg '{}' and kid {:?}",
                candidates.len(),
                header.alg,
                header.kid
            ),
            ErrorCode::PermissionDenied
        ));
    }
    Ok(candidates[0])
}

fn required_jwk_member<'a>(
    key: &'a Jwk,
    value: &'a Option<String>,
    name: &str,
) -> BichonResult<&'a str> {
    value.as_deref().ok_or_else(|| {
        raise_error!(
            format!("OIDC {} key {:?} is missing '{}'", key.kty, key.kid, name),
            ErrorCode::InvalidParameter
        )
    })
}

fn verify_asymmetric(
    header: &Header,
    key: &Jwk,
    signing_input: &[u8],
    signature_bytes: &[u8],
) -> BichonResult<()> {
    let verification = match header.alg.as_str() {
        "RS256" => {
            let n = b64url_decode(required_jwk_member(key, &key.n, "n")?)?;
            let e = b64url_decode(required_jwk_member(key, &key.e, "e")?)?;
            signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                signing_input,
                signature_bytes,
            )
        }
        "ES256" => {
            if key.crv.as_deref() != Some("P-256") {
                return Err(raise_error!(
                    format!("OIDC EC key {:?} does not use P-256", key.kid),
                    ErrorCode::InvalidParameter
                ));
            }
            let x = b64url_decode(required_jwk_member(key, &key.x, "x")?)?;
            let y = b64url_decode(required_jwk_member(key, &key.y, "y")?)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(raise_error!(
                    format!("OIDC EC key {:?} has invalid P-256 coordinates", key.kid),
                    ErrorCode::InvalidParameter
                ));
            }
            let mut public_key = Vec::with_capacity(65);
            public_key.push(4);
            public_key.extend_from_slice(&x);
            public_key.extend_from_slice(&y);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key)
                .verify(signing_input, signature_bytes)
        }
        _ => unreachable!(),
    };

    verification.map_err(|_| {
        raise_error!(
            format!("ID token {} signature verification failed", header.alg),
            ErrorCode::PermissionDenied
        )
    })
}

/// Verify and parse the ID token.
///
/// The signature is verified for `HS256` using the OAuth client secret shared
/// with the IdP, or for `RS256` and `ES256` using the provider's JWKS.
///
/// After the signature check all standard OIDC claims are validated: `iss`,
/// `aud`, `exp` (with configurable skew), and `nonce` (constant-time compare
/// to defeat timing attacks).
pub async fn verify_and_parse(
    token: &str,
    params: &VerifyParams<'_>,
) -> BichonResult<IdTokenClaims> {
    let (h_b64, p_b64, s_b64) = split_jwt(token)?;

    let header_bytes = b64url_decode(h_b64)?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|e| {
        raise_error!(
            format!("Failed to parse ID token header: {}", e),
            ErrorCode::InvalidParameter
        )
    })?;

    if !params.supported_algorithms.is_empty()
        && !params
            .supported_algorithms
            .iter()
            .any(|alg| alg == &header.alg)
    {
        return Err(raise_error!(
            format!(
                "OIDC provider does not advertise ID token algorithm '{}'",
                header.alg
            ),
            ErrorCode::PermissionDenied
        ));
    }

    let signature_bytes = b64url_decode(s_b64)?;
    let signing_input = format!("{}.{}", h_b64, p_b64);
    match header.alg.as_str() {
        "HS256" => {
            // Authelia/ORY-Fosite behavior has varied across versions:
            // some sign HS256 ID tokens with the raw client_secret bytes
            // (OIDC Core 1.0 sec. 10.1), others with SHA-256(client_secret)
            // as the HMAC key. Accept either — both require knowledge of
            // the same shared secret, so forgery is infeasible either way.
            let raw_key = hmac::Key::new(hmac::HMAC_SHA256, params.client_secret);
            if hmac::verify(&raw_key, signing_input.as_bytes(), &signature_bytes).is_err() {
                let derived = digest::digest(&digest::SHA256, params.client_secret);
                let derived_key = hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref());
                hmac::verify(&derived_key, signing_input.as_bytes(), &signature_bytes).map_err(|_| {
                    raise_error!(
                        "ID token HS256 signature verification failed".into(),
                        ErrorCode::PermissionDenied
                    )
                })?;
            }
        }
        "RS256" | "ES256" => {
            let mut set = get_jwks(params.jwks_uri, false).await?;
            let key = match matching_key(&set, &header) {
                Ok(key) => key,
                Err(_) if header.kid.is_some() => {
                    set = get_jwks(params.jwks_uri, true).await?;
                    matching_key(&set, &header)?
                }
                Err(error) => return Err(error),
            };
            verify_asymmetric(&header, key, signing_input.as_bytes(), &signature_bytes)?;
        }
        other => {
            return Err(raise_error!(
                format!(
                    "Unsupported ID token signing algorithm '{}'. Supported algorithms \
                     are HS256, RS256, and ES256.",
                    other
                ),
                ErrorCode::PermissionDenied
            ));
        }
    }

    let payload_bytes = b64url_decode(p_b64)?;
    let claims: IdTokenClaims = serde_json::from_slice(&payload_bytes).map_err(|e| {
        raise_error!(
            format!("Failed to parse ID token claims: {}", e),
            ErrorCode::InvalidParameter
        )
    })?;

    if claims.iss.trim_end_matches('/') != params.expected_issuer.trim_end_matches('/') {
        return Err(raise_error!(
            format!(
                "ID token issuer mismatch: expected '{}', got '{}'",
                params.expected_issuer, claims.iss
            ),
            ErrorCode::PermissionDenied
        ));
    }

    if !audience_matches(&claims.aud, params.expected_audience) {
        return Err(raise_error!(
            "ID token audience does not include this client".into(),
            ErrorCode::PermissionDenied
        ));
    }

    if params.now_secs > claims.exp + params.clock_skew_secs {
        return Err(raise_error!(
            "ID token has expired".into(),
            ErrorCode::PermissionDenied
        ));
    }

    let nonce_ok = claims
        .nonce
        .as_deref()
        .map(|n| eq_ct(n.as_bytes(), params.expected_nonce.as_bytes()))
        .unwrap_or(false);
    if !nonce_ok {
        return Err(raise_error!(
            "ID token nonce mismatch — possible replay attack".into(),
            ErrorCode::PermissionDenied
        ));
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::hmac;

    fn make_token(secret_key: &[u8], nonce: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"iss":"https://authelia.example.com","aud":"bichon","sub":"user1","exp":2000000000,"nonce":"{}","email":"user1@example.com"}}"#,
                nonce
            )
            .as_str(),
        );
        let signing_input = format!("{}.{}", header, payload);
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
        let sig = hmac::sign(&key, signing_input.as_bytes());
        format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        )
    }

    fn params(secret: &[u8]) -> VerifyParams<'_> {
        VerifyParams {
            expected_issuer: "https://authelia.example.com",
            expected_audience: "bichon",
            expected_nonce: "test-nonce",
            client_secret: secret,
            clock_skew_secs: 60,
            now_secs: 1900000000,
        }
    }

    #[tokio::test]
    async fn verifies_raw_secret_signed_token() {
        let secret = b"test-client-secret-with-enough-length-123";
        let token = make_token(secret, "test-nonce");
        let claims = verify_and_parse(&token, &params(secret))
            .await
            .expect("raw-signed token must verify");
        assert_eq!(claims.sub, "user1");
    }

    #[tokio::test]
    async fn verifies_derived_key_signed_token() {
        let secret = b"test-client-secret-with-enough-length-123";
        let derived = digest::digest(&digest::SHA256, secret);
        let token = make_token(derived.as_ref(), "test-nonce");
        let claims = verify_and_parse(&token, &params(secret))
            .await
            .expect("derived-key token must verify");
        assert_eq!(claims.sub, "user1");
    }

    #[tokio::test]
    async fn rejects_wrong_secret() {
        let secret = b"test-client-secret-with-enough-length-123";
        let token = make_token(b"attacker-controlled-key-00000000000000", "test-nonce");
        assert!(verify_and_parse(&token, &params(secret)).await.is_err());
    }

    const PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

    fn jwk(kty: &str, alg: &str, kid: &str) -> Jwk {
        Jwk {
            kty: kty.to_string(),
            kid: Some(kid.to_string()),
            alg: Some(alg.to_string()),
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        }
    }

    #[test]
    fn selects_key_by_algorithm_and_kid() {
        let set = JwkSet {
            keys: vec![jwk("RSA", "RS256", "old"), jwk("RSA", "RS256", "current")],
        };
        let header = Header {
            alg: "RS256".to_string(),
            kid: Some("current".to_string()),
            typ: None,
        };

        assert_eq!(
            matching_key(&set, &header).unwrap().kid.as_deref(),
            Some("current")
        );
    }

    #[test]
    fn rejects_ambiguous_key_without_kid() {
        let set = JwkSet {
            keys: vec![jwk("RSA", "RS256", "one"), jwk("RSA", "RS256", "two")],
        };
        let header = Header {
            alg: "RS256".to_string(),
            kid: None,
            typ: None,
        };

        assert!(matching_key(&set, &header).is_err());
    }

    #[test]
    fn verifies_rs256_rfc7515_vector() {
        let header = Header {
            alg: "RS256".to_string(),
            kid: None,
            typ: None,
        };
        let mut key = jwk("RSA", "RS256", "rfc7515");
        key.n = Some(
            concat!(
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-",
                "Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6",
                "b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-",
                "KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_",
                "I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9",
                "gb54h4FRWyuXpoQ"
            )
            .to_string(),
        );
        key.e = Some("AQAB".to_string());
        let input = format!("eyJhbGciOiJSUzI1NiJ9.{}", PAYLOAD);
        let signature_bytes = b64url_decode(concat!(
            "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
            "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
            "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
            "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
            "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
            "p0igcN_IoypGlUPQGe77Rw"
        ))
        .unwrap();

        assert!(verify_asymmetric(&header, &key, input.as_bytes(), &signature_bytes).is_ok());
        assert!(verify_asymmetric(&header, &key, b"tampered", &signature_bytes).is_err());
    }

    #[test]
    fn verifies_es256_rfc7515_vector() {
        let header = Header {
            alg: "ES256".to_string(),
            kid: None,
            typ: None,
        };
        let mut key = jwk("EC", "ES256", "rfc7515");
        key.crv = Some("P-256".to_string());
        key.x = Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string());
        key.y = Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string());
        let input = format!("eyJhbGciOiJFUzI1NiJ9.{}", PAYLOAD);
        let signature_bytes = b64url_decode(concat!(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
            "pmWQxfKTUJqPP3-Kg6NU1Q"
        ))
        .unwrap();

        assert!(verify_asymmetric(&header, &key, input.as_bytes(), &signature_bytes).is_ok());
        assert!(verify_asymmetric(&header, &key, b"tampered", &signature_bytes).is_err());
    }
}
