/// Serde helpers for MISP's inconsistent JSON wire format.
///
/// MISP often sends numeric fields as strings (e.g., `"1"` instead of `1`)
/// and booleans as `0`/`1` or `true`/`false`. These modules handle both forms.
use serde::{self, Deserialize, Deserializer, Serializer};

/// Deserialize a value that may be a string or number into an `Option<i64>`.
/// Handles: `null`, `"123"`, `123`, `""`.
pub mod string_or_i64_opt {
    use super::*;

    pub fn serialize<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_str(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| serde::de::Error::custom("number out of i64 range"))
                .map(Some),
            Some(serde_json::Value::String(s)) if s.is_empty() => Ok(None),
            Some(serde_json::Value::String(s)) => {
                s.parse::<i64>().map(Some).map_err(serde::de::Error::custom)
            }
            Some(other) => Err(serde::de::Error::custom(format!(
                "expected string or number, got {other}"
            ))),
        }
    }
}

/// Deserialize a value that may be a string or number into an `i64`.
/// Handles: `"123"`, `123`.
pub mod string_or_i64 {
    use super::*;

    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::Number(n) => n
                .as_i64()
                .ok_or_else(|| serde::de::Error::custom("number out of i64 range")),
            serde_json::Value::String(s) => s.parse::<i64>().map_err(serde::de::Error::custom),
            other => Err(serde::de::Error::custom(format!(
                "expected string or number, got {other}"
            ))),
        }
    }
}

/// Deserialize a boolean that may be `true`/`false`, `0`/`1`, `"0"`/`"1"`, or `"true"`/`"false"`.
pub mod flexible_bool {
    use super::*;

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(*value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::Bool(b) => Ok(b),
            serde_json::Value::Number(n) => Ok(n.as_i64() != Some(0)),
            serde_json::Value::String(s) => match s.as_str() {
                "0" | "false" | "" => Ok(false),
                _ => Ok(true),
            },
            serde_json::Value::Null => Ok(false),
            other => Err(serde::de::Error::custom(format!(
                "expected bool-like value, got {other}"
            ))),
        }
    }
}

/// Same as `flexible_bool` but for `Option<bool>`.
pub mod flexible_bool_opt {
    use super::*;

    pub fn serialize<S>(value: &Option<bool>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_bool(*v),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
        match opt {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
            Some(serde_json::Value::Number(n)) => Ok(Some(n.as_i64() != Some(0))),
            Some(serde_json::Value::String(s)) => match s.as_str() {
                "0" | "false" | "" => Ok(Some(false)),
                _ => Ok(Some(true)),
            },
            Some(other) => Err(serde::de::Error::custom(format!(
                "expected bool-like value, got {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(with = "super::string_or_i64")]
        num: i64,
        #[serde(
            default,
            with = "super::string_or_i64_opt",
            skip_serializing_if = "Option::is_none"
        )]
        opt_num: Option<i64>,
        #[serde(with = "super::flexible_bool")]
        flag: bool,
    }

    #[test]
    fn deserialize_string_numbers() {
        let json = r#"{"num": "42", "flag": true}"#;
        let v: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(v.num, 42);
        assert_eq!(v.opt_num, None);
    }

    #[test]
    fn deserialize_real_numbers() {
        let json = r#"{"num": 42, "opt_num": 7, "flag": false}"#;
        let v: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(v.num, 42);
        assert_eq!(v.opt_num, Some(7));
    }

    #[test]
    fn deserialize_flexible_bool_variants() {
        for (input, expected) in [
            ("true", true),
            ("false", false),
            ("1", true),
            ("0", false),
            ("\"1\"", true),
            ("\"0\"", false),
            ("\"true\"", true),
            ("\"false\"", false),
        ] {
            let json = format!(r#"{{"num": "1", "flag": {input}}}"#);
            let v: TestStruct = serde_json::from_str(&json).unwrap();
            assert_eq!(v.flag, expected, "input: {input}");
        }
    }

    #[test]
    fn roundtrip_serialization() {
        let original = TestStruct {
            num: 99,
            opt_num: Some(5),
            flag: true,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }
}
