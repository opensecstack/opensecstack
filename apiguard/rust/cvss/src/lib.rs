use serde::{Deserialize, Serialize};

/// CVSS 3.1 metric values.
#[derive(Debug, Clone, Deserialize)]
pub struct CvssMetrics {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: Impact,
    pub integrity: Impact,
    pub availability: Impact,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum AttackVector {
    Network,
    AdjacentNetwork,
    Local,
    Physical,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Impact {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct CvssScore {
    pub base_score: f64,
    pub severity: String,
    pub vector_string: String,
}

/// Roundup: round to 1 decimal place, always rounding up (ceiling at 1dp).
fn roundup(x: f64) -> f64 {
    let shifted = (x * 10.0).ceil();
    shifted / 10.0
}

/// Convert metrics to a CVSS 3.1 vector string.
pub fn to_vector_string(metrics: &CvssMetrics) -> String {
    let av = match metrics.attack_vector {
        AttackVector::Network => "N",
        AttackVector::AdjacentNetwork => "A",
        AttackVector::Local => "L",
        AttackVector::Physical => "P",
    };
    let ac = match metrics.attack_complexity {
        AttackComplexity::Low => "L",
        AttackComplexity::High => "H",
    };
    let pr = match metrics.privileges_required {
        PrivilegesRequired::None => "N",
        PrivilegesRequired::Low => "L",
        PrivilegesRequired::High => "H",
    };
    let ui = match metrics.user_interaction {
        UserInteraction::None => "N",
        UserInteraction::Required => "R",
    };
    let sc = match metrics.scope {
        Scope::Unchanged => "U",
        Scope::Changed => "C",
    };
    let c = match metrics.confidentiality {
        Impact::None => "N",
        Impact::Low => "L",
        Impact::High => "H",
    };
    let i = match metrics.integrity {
        Impact::None => "N",
        Impact::Low => "L",
        Impact::High => "H",
    };
    let a = match metrics.availability {
        Impact::None => "N",
        Impact::Low => "L",
        Impact::High => "H",
    };
    format!(
        "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
        av, ac, pr, ui, sc, c, i, a
    )
}

/// Calculate the CVSS 3.1 base score from metrics.
pub fn calculate(metrics: &CvssMetrics) -> CvssScore {
    // Numeric values per CVSS 3.1 specification
    let av = match metrics.attack_vector {
        AttackVector::Network => 0.85,
        AttackVector::AdjacentNetwork => 0.62,
        AttackVector::Local => 0.55,
        AttackVector::Physical => 0.20,
    };

    let ac = match metrics.attack_complexity {
        AttackComplexity::Low => 0.77,
        AttackComplexity::High => 0.44,
    };

    // PR values depend on Scope
    let pr = match (&metrics.privileges_required, &metrics.scope) {
        (PrivilegesRequired::None, _) => 0.85,
        (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
        (PrivilegesRequired::Low, Scope::Changed) => 0.68,
        (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
        (PrivilegesRequired::High, Scope::Changed) => 0.50,
    };

    let ui = match metrics.user_interaction {
        UserInteraction::None => 0.85,
        UserInteraction::Required => 0.62,
    };

    let c_val = match metrics.confidentiality {
        Impact::None => 0.0,
        Impact::Low => 0.22,
        Impact::High => 0.56,
    };
    let i_val = match metrics.integrity {
        Impact::None => 0.0,
        Impact::Low => 0.22,
        Impact::High => 0.56,
    };
    let a_val = match metrics.availability {
        Impact::None => 0.0,
        Impact::Low => 0.22,
        Impact::High => 0.56,
    };

    let isc_base = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val);

    let isc = match metrics.scope {
        Scope::Unchanged => 6.42 * isc_base,
        Scope::Changed => 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02_f64).powi(15),
    };

    let base_score = if isc <= 0.0 {
        0.0
    } else {
        let exploitability = 8.22 * av * ac * pr * ui;
        match metrics.scope {
            Scope::Unchanged => roundup(f64::min(isc + exploitability, 10.0)),
            Scope::Changed => roundup(f64::min(1.08 * (isc + exploitability), 10.0)),
        }
    };

    let severity = severity_label(base_score);
    let vector_string = to_vector_string(metrics);

    CvssScore {
        base_score,
        severity,
        vector_string,
    }
}

fn severity_label(score: f64) -> String {
    match score {
        0.0 => "None",
        s if s < 4.0 => "Low",
        s if s < 7.0 => "Medium",
        s if s < 9.0 => "High",
        _ => "Critical",
    }
    .to_string()
}

/// Parse a CVSS 3.1 vector string and return the computed score.
///
/// Example: `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"`
pub fn from_vector_string(vector: &str) -> Result<CvssScore, String> {
    if !vector.starts_with("CVSS:3.1/") {
        return Err(format!(
            "Vector string must start with 'CVSS:3.1/', got: {}",
            vector
        ));
    }

    let parts: Vec<&str> = vector["CVSS:3.1/".len()..].split('/').collect();
    let mut map = std::collections::HashMap::new();
    for part in &parts {
        let kv: Vec<&str> = part.splitn(2, ':').collect();
        if kv.len() != 2 {
            return Err(format!("Invalid metric component: '{}'", part));
        }
        map.insert(kv[0], kv[1]);
    }

    let get = |key: &str| -> Result<&str, String> {
        map.get(key)
            .copied()
            .ok_or_else(|| format!("Missing metric: {}", key))
    };

    let attack_vector = match get("AV")? {
        "N" => AttackVector::Network,
        "A" => AttackVector::AdjacentNetwork,
        "L" => AttackVector::Local,
        "P" => AttackVector::Physical,
        v => return Err(format!("Invalid AV value: '{}'", v)),
    };

    let attack_complexity = match get("AC")? {
        "L" => AttackComplexity::Low,
        "H" => AttackComplexity::High,
        v => return Err(format!("Invalid AC value: '{}'", v)),
    };

    let scope_raw = get("S")?;
    let scope = match scope_raw {
        "U" => Scope::Unchanged,
        "C" => Scope::Changed,
        v => return Err(format!("Invalid S value: '{}'", v)),
    };

    let privileges_required = match get("PR")? {
        "N" => PrivilegesRequired::None,
        "L" => PrivilegesRequired::Low,
        "H" => PrivilegesRequired::High,
        v => return Err(format!("Invalid PR value: '{}'", v)),
    };

    let user_interaction = match get("UI")? {
        "N" => UserInteraction::None,
        "R" => UserInteraction::Required,
        v => return Err(format!("Invalid UI value: '{}'", v)),
    };

    let parse_impact = |key: &str| -> Result<Impact, String> {
        match get(key)? {
            "N" => Ok(Impact::None),
            "L" => Ok(Impact::Low),
            "H" => Ok(Impact::High),
            v => Err(format!("Invalid {} value: '{}'", key, v)),
        }
    };

    let confidentiality = parse_impact("C")?;
    let integrity = parse_impact("I")?;
    let availability = parse_impact("A")?;

    let metrics = CvssMetrics {
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope,
        confidentiality,
        integrity,
        availability,
    };

    Ok(calculate(&metrics))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_critical_network_no_auth() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N => expected 9.1
        let result = from_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N").unwrap();
        assert_eq!(result.base_score, 9.1);
        assert_eq!(result.severity, "Critical");
    }

    #[test]
    fn test_cvss_zero_no_impact() {
        // All impacts None => score 0
        let result = from_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").unwrap();
        assert_eq!(result.base_score, 0.0);
        assert_eq!(result.severity, "None");
    }

    #[test]
    #[allow(clippy::approx_constant)] // 3.14 is an arbitrary rounding fixture, not an approximation of PI
    fn test_roundup() {
        assert_eq!(roundup(9.05), 9.1);
        assert_eq!(roundup(4.0), 4.0);
        assert_eq!(roundup(3.14), 3.2);
    }
}
