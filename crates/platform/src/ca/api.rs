//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! CA service functions — library-only, no HTTP coupling.
//!
//! Status: Library-only. Contains plain async service functions for CA operations.
//! These functions accept typed parameters directly and return typed results.
//! When CA routes are wired into the HTTP layer, thin Axum handler shims will wrap these functions.

use super::{error::CAError, models::*, service::CertificateAuthorityService};
use serde::Deserialize;

/// Get the CA certificate PEM string.
pub fn get_ca_certificate(ca_service: &CertificateAuthorityService) -> String {
    ca_service.get_ca_certificate().to_string()
}

/// Issue a new certificate.
pub async fn issue_certificate(
    ca_service: &CertificateAuthorityService,
    request: &IssueCertificateRequest,
) -> Result<IssueCertificateResponse, CAError> {
    // Validate the certificate request
    validate_certificate_request(&request.certificate_request)?;

    // Future: Extract tenant ID from JWT auth instead of creating a new one
    let tenant_id = TenantId::new();

    tracing::info!(
        "Issuing certificate for subject: {}",
        request.certificate_request.subject.common_name
    );

    let certificate = ca_service
        .issue_certificate(&tenant_id, &request.certificate_request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to issue certificate: {}", e);
            e
        })?;

    tracing::info!(
        "Certificate issued successfully: serial={}, subject={}",
        certificate.serial_number,
        certificate.subject
    );

    Ok(IssueCertificateResponse { certificate })
}

/// Revoke a certificate by serial number.
pub async fn revoke_certificate(
    ca_service: &CertificateAuthorityService,
    serial: &str,
    request: &RevokeCertificateRequest,
) -> Result<(), CAError> {
    // Validate the revocation request
    validate_revocation_request(serial, request)?;

    // Future: Extract tenant ID from JWT auth instead of creating a new one
    let tenant_id = TenantId::new();

    tracing::info!(
        "Revoking certificate: serial={}, reason={}",
        serial,
        request.reason
    );

    ca_service
        .revoke_certificate(&tenant_id, serial, &request.reason)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke certificate: {}", e);
            e
        })?;

    tracing::info!("Certificate revoked successfully: serial={}", serial);

    Ok(())
}

/// List certificates with optional filtering and pagination.
pub fn list_certificates(
    query: &ListCertificatesQuery,
) -> Result<ListCertificatesResponse, String> {
    // Validate query parameters
    validate_list_query(query)?;

    // Listing is not yet backed by the certificate store. Return an honest empty
    // result rather than fabricated demo certificates — the production CA path must
    // never emit mock certificates. (Future: query the store for this tenant.)
    let response = ListCertificatesResponse {
        certificates: Vec::new(),
        total: 0,
        limit: query.limit.unwrap_or(50),
        offset: query.offset.unwrap_or(0),
    };

    tracing::info!(
        "Listed certificates: returned={} results",
        response.certificates.len()
    );

    Ok(response)
}

/// Query parameters for listing certificates.
#[derive(Debug, Deserialize)]
pub struct ListCertificatesQuery {
    /// Filter by certificate status
    pub status: Option<String>,
    /// Filter by subject (partial match)
    pub subject: Option<String>,
    /// Filter by serial number (exact match)
    pub serial: Option<String>,
    /// Filter by common name (partial match)
    pub common_name: Option<String>,
    /// Filter by organization (partial match)
    pub organization: Option<String>,
    /// Filter certificates expiring before this date (ISO 8601)
    pub expires_before: Option<String>,
    /// Filter certificates created after this date (ISO 8601)
    pub created_after: Option<String>,
    /// Maximum number of results to return
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination)
    pub offset: Option<u32>,
    /// Sort field (serial, subject, created_at, expires_at)
    pub sort_by: Option<String>,
    /// Sort order (asc, desc)
    pub sort_order: Option<String>,
}

/// Validate certificate request parameters.
pub fn validate_certificate_request(request: &CertificateRequest) -> Result<(), CAError> {
    // Validate common name
    if request.subject.common_name.is_empty() {
        return Err(CAError::InvalidRequest(
            "Common name cannot be empty".to_string(),
        ));
    }

    if request.subject.common_name.len() > 64 {
        return Err(CAError::InvalidRequest(
            "Common name cannot exceed 64 characters".to_string(),
        ));
    }

    // Basic DNS name validation for common name
    if request.subject.common_name.contains(' ') {
        return Err(CAError::InvalidRequest(
            "Common name cannot contain spaces".to_string(),
        ));
    }

    // Validate organization if provided
    if let Some(org) = &request.subject.organization {
        if org.is_empty() {
            return Err(CAError::InvalidRequest(
                "Organization cannot be empty if provided".to_string(),
            ));
        }
        if org.len() > 64 {
            return Err(CAError::InvalidRequest(
                "Organization cannot exceed 64 characters".to_string(),
            ));
        }
    }

    // Validate country if provided
    if let Some(country) = &request.subject.country {
        if country.len() != 2 {
            return Err(CAError::InvalidRequest(
                "Country code must be exactly 2 characters (ISO 3166-1 alpha-2)".to_string(),
            ));
        }
        if !country
            .chars()
            .all(|c| c.is_ascii_alphabetic() && c.is_uppercase())
        {
            return Err(CAError::InvalidRequest(
                "Country code must be uppercase letters only".to_string(),
            ));
        }
    }

    // Validate validity period
    if let Some(days) = request.validity_days {
        if days == 0 {
            return Err(CAError::InvalidRequest(
                "Validity period must be at least 1 day".to_string(),
            ));
        }
        if days > 3650 {
            // 10 years max
            return Err(CAError::InvalidRequest(
                "Validity period cannot exceed 10 years (3650 days)".to_string(),
            ));
        }
    }

    // Validate key usage - must have at least one
    if request.key_usage.is_empty() {
        return Err(CAError::InvalidRequest(
            "At least one key usage must be specified".to_string(),
        ));
    }

    // Validate extended key usage - must have at least one
    if request.extended_key_usage.is_empty() {
        return Err(CAError::InvalidRequest(
            "At least one extended key usage must be specified".to_string(),
        ));
    }

    // Validate SAN entries
    if request.san_entries.is_empty() {
        return Err(CAError::InvalidRequest(
            "At least one Subject Alternative Name must be specified".to_string(),
        ));
    }

    for san in &request.san_entries {
        match san {
            SubjectAlternativeName::DnsName(name) => {
                if name.is_empty() {
                    return Err(CAError::InvalidRequest(
                        "DNS name in SAN cannot be empty".to_string(),
                    ));
                }
                if name.len() > 253 {
                    return Err(CAError::InvalidRequest(
                        "DNS name in SAN cannot exceed 253 characters".to_string(),
                    ));
                }
                // Basic DNS validation
                if name.starts_with('.') || name.ends_with('.') {
                    return Err(CAError::InvalidRequest(
                        "DNS name cannot start or end with a dot".to_string(),
                    ));
                }
                if name.contains("..") {
                    return Err(CAError::InvalidRequest(
                        "DNS name cannot contain consecutive dots".to_string(),
                    ));
                }
            }
            SubjectAlternativeName::Email(email) => {
                if email.is_empty() {
                    return Err(CAError::InvalidRequest(
                        "Email in SAN cannot be empty".to_string(),
                    ));
                }
                if !email.contains('@') || email.matches('@').count() != 1 {
                    return Err(CAError::InvalidRequest(
                        "Invalid email format in SAN".to_string(),
                    ));
                }
                if email.len() > 254 {
                    return Err(CAError::InvalidRequest(
                        "Email in SAN cannot exceed 254 characters".to_string(),
                    ));
                }
            }
            SubjectAlternativeName::IpAddress(ip) => {
                if ip.parse::<std::net::IpAddr>().is_err() {
                    return Err(CAError::InvalidRequest(
                        "Invalid IP address format in SAN".to_string(),
                    ));
                }
            }
            SubjectAlternativeName::Uri(uri) => {
                if uri.is_empty() {
                    return Err(CAError::InvalidRequest(
                        "URI in SAN cannot be empty".to_string(),
                    ));
                }
                if uri.len() > 2048 {
                    return Err(CAError::InvalidRequest(
                        "URI in SAN cannot exceed 2048 characters".to_string(),
                    ));
                }
                // Basic URI validation
                if !uri.starts_with("http://") && !uri.starts_with("https://") {
                    return Err(CAError::InvalidRequest(
                        "URI in SAN must start with http:// or https://".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Validate certificate revocation request.
pub fn validate_revocation_request(
    serial: &str,
    request: &RevokeCertificateRequest,
) -> Result<(), CAError> {
    // Validate serial number format
    if serial.is_empty() {
        return Err(CAError::InvalidRequest(
            "Serial number cannot be empty".to_string(),
        ));
    }

    if serial.len() > 64 {
        return Err(CAError::InvalidRequest(
            "Serial number cannot exceed 64 characters".to_string(),
        ));
    }

    // Validate hex format
    if !serial.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CAError::InvalidRequest(
            "Serial number must contain only hexadecimal characters".to_string(),
        ));
    }

    // Validate revocation reason
    if request.reason.is_empty() {
        return Err(CAError::InvalidRequest(
            "Revocation reason cannot be empty".to_string(),
        ));
    }

    if request.reason.len() > 255 {
        return Err(CAError::InvalidRequest(
            "Revocation reason cannot exceed 255 characters".to_string(),
        ));
    }

    // Validate reason is one of the standard RFC 5280 reasons
    let valid_reasons = [
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "removeFromCRL",
        "privilegeWithdrawn",
        "aACompromise",
    ];

    if !valid_reasons.contains(&request.reason.as_str()) {
        return Err(CAError::InvalidRequest(format!(
            "Invalid revocation reason. Must be one of: {}",
            valid_reasons.join(", ")
        )));
    }

    Ok(())
}

/// Validate list certificates query parameters.
pub fn validate_list_query(query: &ListCertificatesQuery) -> Result<(), String> {
    // Validate status filter
    if let Some(status) = &query.status {
        match status.as_str() {
            "Pending" | "Issued" | "Revoked" | "Expired" => {}
            _ => {
                return Err(
                    "Invalid status filter. Must be one of: Pending, Issued, Revoked, Expired"
                        .to_string(),
                )
            }
        }
    }

    // Validate search strings
    if let Some(subject) = &query.subject {
        if subject.len() > 200 {
            return Err("Subject filter cannot exceed 200 characters".to_string());
        }
    }

    if let Some(serial) = &query.serial {
        if serial.is_empty() {
            return Err("Serial number filter cannot be empty".to_string());
        }
        if serial.len() > 64 {
            return Err("Serial number filter cannot exceed 64 characters".to_string());
        }
        // Validate hex format
        if !serial.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Serial number must contain only hexadecimal characters".to_string());
        }
    }

    if let Some(common_name) = &query.common_name {
        if common_name.is_empty() {
            return Err("Common name filter cannot be empty".to_string());
        }
        if common_name.len() > 64 {
            return Err("Common name filter cannot exceed 64 characters".to_string());
        }
    }

    if let Some(organization) = &query.organization {
        if organization.is_empty() {
            return Err("Organization filter cannot be empty".to_string());
        }
        if organization.len() > 64 {
            return Err("Organization filter cannot exceed 64 characters".to_string());
        }
    }

    // Validate limit
    if let Some(limit) = query.limit {
        if limit == 0 {
            return Err("Limit must be at least 1".to_string());
        }
        if limit > 1000 {
            return Err("Limit cannot exceed 1000".to_string());
        }
    }

    // Validate offset
    if let Some(offset) = query.offset {
        if offset > 1_000_000 {
            return Err("Offset cannot exceed 1,000,000".to_string());
        }
    }

    // Validate sort_by
    if let Some(sort_by) = &query.sort_by {
        match sort_by.as_str() {
            "serial" | "subject" | "created_at" | "expires_at" => {}
            _ => return Err(
                "Invalid sort_by field. Must be one of: serial, subject, created_at, expires_at"
                    .to_string(),
            ),
        }
    }

    // Validate sort_order
    if let Some(sort_order) = &query.sort_order {
        match sort_order.as_str() {
            "asc" | "desc" => {}
            _ => return Err("Invalid sort_order. Must be 'asc' or 'desc'".to_string()),
        }
    }

    // Validate date formats
    if let Some(expires_before) = &query.expires_before {
        if chrono::DateTime::parse_from_rfc3339(expires_before).is_err() {
            return Err("Invalid expires_before date format. Use ISO 8601 format (e.g., 2025-12-31T23:59:59Z)".to_string());
        }
    }

    if let Some(created_after) = &query.created_after {
        if chrono::DateTime::parse_from_rfc3339(created_after).is_err() {
            return Err("Invalid created_after date format. Use ISO 8601 format (e.g., 2025-01-01T00:00:00Z)".to_string());
        }
    }

    // Validate date logic
    if let (Some(created_after), Some(expires_before)) =
        (&query.created_after, &query.expires_before)
    {
        let created = chrono::DateTime::parse_from_rfc3339(created_after).unwrap();
        let expires = chrono::DateTime::parse_from_rfc3339(expires_before).unwrap();

        if created >= expires {
            return Err("created_after date must be before expires_before date".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_certificate_request_valid() {
        let request = CertificateRequest {
            subject: CertificateSubject {
                common_name: "test.example.com".to_string(),
                organization: Some("Test Org".to_string()),
                organizational_unit: None,
                country: Some("US".to_string()),
                state: None,
                locality: None,
                email: None,
            },
            validity_days: Some(30),
            key_usage: vec![KeyUsage::DigitalSignature],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
            san_entries: vec![SubjectAlternativeName::DnsName(
                "test.example.com".to_string(),
            )],
        };

        assert!(validate_certificate_request(&request).is_ok());
    }

    #[test]
    fn test_validate_certificate_request_empty_common_name() {
        let request = CertificateRequest {
            subject: CertificateSubject {
                common_name: "".to_string(),
                organization: None,
                organizational_unit: None,
                country: None,
                state: None,
                locality: None,
                email: None,
            },
            validity_days: Some(30),
            key_usage: vec![KeyUsage::DigitalSignature],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
            san_entries: vec![SubjectAlternativeName::DnsName(
                "test.example.com".to_string(),
            )],
        };

        let result = validate_certificate_request(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Common name cannot be empty"));
    }

    #[test]
    fn test_validate_certificate_request_invalid_country() {
        let request = CertificateRequest {
            subject: CertificateSubject {
                common_name: "test.example.com".to_string(),
                organization: None,
                organizational_unit: None,
                country: Some("USA".to_string()), // Invalid: 3 letters
                state: None,
                locality: None,
                email: None,
            },
            validity_days: Some(30),
            key_usage: vec![KeyUsage::DigitalSignature],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
            san_entries: vec![SubjectAlternativeName::DnsName(
                "test.example.com".to_string(),
            )],
        };

        let result = validate_certificate_request(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Country code must be exactly 2 characters"));
    }

    #[test]
    fn test_validate_list_query_valid() {
        let query = ListCertificatesQuery {
            status: Some("Issued".to_string()),
            subject: None,
            serial: None,
            common_name: None,
            organization: None,
            expires_before: None,
            created_after: None,
            limit: Some(10),
            offset: Some(0),
            sort_by: Some("created_at".to_string()),
            sort_order: Some("desc".to_string()),
        };

        assert!(validate_list_query(&query).is_ok());
    }

    #[test]
    fn test_validate_list_query_invalid_status() {
        let query = ListCertificatesQuery {
            status: Some("InvalidStatus".to_string()),
            subject: None,
            serial: None,
            common_name: None,
            organization: None,
            expires_before: None,
            created_after: None,
            limit: None,
            offset: None,
            sort_by: None,
            sort_order: None,
        };

        let result = validate_list_query(&query);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid status filter"));
    }

    #[test]
    fn test_validate_revocation_request_valid() {
        let request = RevokeCertificateRequest {
            reason: "keyCompromise".to_string(),
        };

        assert!(validate_revocation_request("3701e7c1d6134032917ece67be150e25", &request).is_ok());
    }

    #[test]
    fn test_validate_revocation_request_empty_serial() {
        let request = RevokeCertificateRequest {
            reason: "keyCompromise".to_string(),
        };

        let result = validate_revocation_request("", &request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Serial number cannot be empty"));
    }

    #[test]
    fn test_validate_revocation_request_invalid_serial_format() {
        let request = RevokeCertificateRequest {
            reason: "keyCompromise".to_string(),
        };

        let result = validate_revocation_request("invalid-serial-123", &request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Serial number must contain only hexadecimal characters"));
    }

    #[test]
    fn test_validate_revocation_request_empty_reason() {
        let request = RevokeCertificateRequest {
            reason: "".to_string(),
        };

        let result = validate_revocation_request("3701e7c1d6134032917ece67be150e25", &request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Revocation reason cannot be empty"));
    }

    #[test]
    fn test_validate_revocation_request_invalid_reason() {
        let request = RevokeCertificateRequest {
            reason: "invalidReason".to_string(),
        };

        let result = validate_revocation_request("3701e7c1d6134032917ece67be150e25", &request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid revocation reason"));
    }

    #[test]
    fn test_validate_revocation_request_long_reason() {
        let request = RevokeCertificateRequest {
            reason: "a".repeat(256), // Exceeds 255 character limit
        };

        let result = validate_revocation_request("3701e7c1d6134032917ece67be150e25", &request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Revocation reason cannot exceed 255 characters"));
    }

    #[test]
    fn test_validate_revocation_request_all_valid_reasons() {
        let valid_reasons = [
            "unspecified",
            "keyCompromise",
            "cACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
            "removeFromCRL",
            "privilegeWithdrawn",
            "aACompromise",
        ];

        for reason in &valid_reasons {
            let request = RevokeCertificateRequest {
                reason: reason.to_string(),
            };
            assert!(
                validate_revocation_request("3701e7c1d6134032917ece67be150e25", &request).is_ok(),
                "Reason '{}' should be valid",
                reason
            );
        }
    }
}
