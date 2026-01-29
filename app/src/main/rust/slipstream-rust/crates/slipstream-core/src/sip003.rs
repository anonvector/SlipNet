use crate::ConfigError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sip003Option {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Sip003Env {
    pub local_host: Option<String>,
    pub local_port: Option<String>,
    pub remote_host: Option<String>,
    pub remote_port: Option<String>,
    pub plugin_options: Vec<Sip003Option>,
}

impl Sip003Env {
    pub fn is_present(&self) -> bool {
        self.local_host.is_some()
            || self.local_port.is_some()
            || self.remote_host.is_some()
            || self.remote_port.is_some()
            || !self.plugin_options.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Sip003Endpoint {
    pub host: String,
    pub port: u16,
}

pub fn read_sip003_env() -> Result<Sip003Env, ConfigError> {
    let local_host = read_env_value("SS_LOCAL_HOST");
    let local_port = read_env_value("SS_LOCAL_PORT");
    let remote_host = read_env_value("SS_REMOTE_HOST");
    let remote_port = read_env_value("SS_REMOTE_PORT");
    let plugin_options = match read_env_value("SS_PLUGIN_OPTIONS") {
        Some(value) => parse_plugin_options(&value)?,
        None => Vec::new(),
    };

    Ok(Sip003Env {
        local_host,
        local_port,
        remote_host,
        remote_port,
        plugin_options,
    })
}

pub fn parse_plugin_options(input: &str) -> Result<Vec<Sip003Option>, ConfigError> {
    let mut options = Vec::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_key = true;
    let mut escape = false;
    let mut saw_any = false;

    for ch in input.chars() {
        if escape {
            if in_key {
                key.push(ch);
            } else {
                value.push(ch);
            }
            escape = false;
            saw_any = true;
            continue;
        }

        match ch {
            '\\' => {
                escape = true;
            }
            ';' => {
                if in_key {
                    if !saw_any && key.is_empty() {
                        continue;
                    }
                    if allows_empty_value_key(&key) {
                        push_option(&mut options, &mut key, &mut value)?;
                        in_key = true;
                        saw_any = false;
                        continue;
                    }
                    return Err(ConfigError::new(
                        "Invalid SS_PLUGIN_OPTIONS entry (missing '=')",
                    ));
                }
                push_option(&mut options, &mut key, &mut value)?;
                in_key = true;
                saw_any = false;
            }
            '=' => {
                if in_key {
                    in_key = false;
                    saw_any = true;
                } else {
                    value.push('=');
                    saw_any = true;
                }
            }
            _ => {
                if in_key {
                    key.push(ch);
                } else {
                    value.push(ch);
                }
                saw_any = true;
            }
        }
    }

    if escape {
        return Err(ConfigError::new(
            "Invalid SS_PLUGIN_OPTIONS entry (dangling escape)",
        ));
    }

    if saw_any || !key.is_empty() || !value.is_empty() {
        if in_key {
            if allows_empty_value_key(&key) {
                push_option(&mut options, &mut key, &mut value)?;
            } else {
                return Err(ConfigError::new(
                    "Invalid SS_PLUGIN_OPTIONS entry (missing '=')",
                ));
            }
        } else {
            push_option(&mut options, &mut key, &mut value)?;
        }
    }

    Ok(options)
}

pub fn parse_endpoint(
    host: Option<&str>,
    port: Option<&str>,
    label: &str,
) -> Result<Option<Sip003Endpoint>, ConfigError> {
    match (host, port) {
        (None, None) => Ok(None),
        (Some(host), Some(port)) => {
            let host = host.trim();
            if host.is_empty() {
                return Err(ConfigError::new(format!(
                    "{}_HOST must not be empty",
                    label
                )));
            }
            let port = parse_port(port, label)?;
            Ok(Some(Sip003Endpoint {
                host: host.to_string(),
                port,
            }))
        }
        _ => Err(ConfigError::new(format!(
            "Both {}_HOST and {}_PORT must be set",
            label, label
        ))),
    }
}

pub fn select_host_port(
    cli_host: &str,
    cli_port: u16,
    cli_host_provided: bool,
    cli_port_provided: bool,
    env_host: Option<&str>,
    env_port: Option<&str>,
    label: &str,
) -> Result<(String, u16), ConfigError> {
    if cli_host_provided || cli_port_provided {
        return Ok((cli_host.to_string(), cli_port));
    }

    match parse_endpoint(env_host, env_port, label)? {
        Some(endpoint) => Ok((endpoint.host, endpoint.port)),
        None => Ok((cli_host.to_string(), cli_port)),
    }
}

pub fn split_list(value: &str) -> Result<Vec<String>, ConfigError> {
    let mut entries = Vec::new();
    for raw in value.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::new(
                "Invalid SS_PLUGIN_OPTIONS list entry (empty value)",
            ));
        }
        entries.push(trimmed.to_string());
    }
    Ok(entries)
}

pub fn last_option_value(options: &[Sip003Option], key: &str) -> Option<String> {
    let mut last = None;
    for option in options {
        if option.key == key {
            last = Some(option.value.trim().to_string());
        }
    }
    last
}

fn read_env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_port(value: &str, label: &str) -> Result<u16, ConfigError> {
    let trimmed = value.trim();
    let port = trimmed
        .parse::<u16>()
        .map_err(|_| ConfigError::new(format!("Invalid {}_PORT value: {}", label, trimmed)))?;
    if port == 0 {
        return Err(ConfigError::new(format!(
            "Invalid {}_PORT value: {}",
            label, trimmed
        )));
    }
    Ok(port)
}

fn push_option(
    options: &mut Vec<Sip003Option>,
    key: &mut String,
    value: &mut String,
) -> Result<(), ConfigError> {
    let trimmed_key = key.trim();
    if trimmed_key.is_empty() {
        return Err(ConfigError::new(
            "Invalid SS_PLUGIN_OPTIONS entry (empty key)",
        ));
    }
    options.push(Sip003Option {
        key: trimmed_key.to_ascii_lowercase(),
        value: value.clone(),
    });
    key.clear();
    value.clear();
    Ok(())
}

fn allows_empty_value_key(key: &str) -> bool {
    key.trim().eq_ignore_ascii_case("authoritative")
}

#[cfg(test)]
mod tests {
    use super::{parse_endpoint, parse_plugin_options, split_list, Sip003Option};

    #[test]
    fn parses_plugin_options_with_escapes() {
        let options = parse_plugin_options(r"mode=http\;tcp;path=dir\\file\=a").unwrap();
        assert_eq!(
            options,
            vec![
                Sip003Option {
                    key: "mode".to_string(),
                    value: "http;tcp".to_string(),
                },
                Sip003Option {
                    key: "path".to_string(),
                    value: r"dir\file=a".to_string(),
                }
            ]
        );
    }

    #[test]
    fn allows_authoritative_without_value() {
        let options = parse_plugin_options("authoritative;mode=test").unwrap();
        assert_eq!(
            options,
            vec![
                Sip003Option {
                    key: "authoritative".to_string(),
                    value: "".to_string(),
                },
                Sip003Option {
                    key: "mode".to_string(),
                    value: "test".to_string(),
                },
            ]
        );
    }

    #[test]
    fn splits_list_values() {
        let values = split_list("a,b, c").unwrap();
        assert_eq!(
            values,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn rejects_empty_list_entry() {
        assert!(split_list("a,,b").is_err());
    }

    #[test]
    fn parses_endpoint_pair() {
        let endpoint = parse_endpoint(Some("127.0.0.1"), Some("8080"), "SS_LOCAL").unwrap();
        let endpoint = endpoint.expect("endpoint");
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 8080);
    }

    #[test]
    fn rejects_zero_port_in_endpoint() {
        assert!(parse_endpoint(Some("127.0.0.1"), Some("0"), "SS_LOCAL").is_err());
    }
}
