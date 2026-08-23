//! Proxy bypass ("exception") rules: hosts a profile connects to directly
//! instead of through its assigned proxy or VPN.
//!
//! A rule is one of:
//!
//! | Form | Matches |
//! | --- | --- |
//! | `example.com` | `example.com` and every subdomain of it |
//! | `*.example.com` / `.example.com` | subdomains only, not the apex |
//! | `*.corp.*` | glob over the whole host (`*` any run, `?` one character) |
//! | `192.168.1.5` / `fd00::1` | that exact address |
//! | `10.0.0.0/8` / `fd00::/8` | any address in the range |
//! | `example.com:8080` | the host, but only on that port |
//! | `https://example.com` | the host, but only over that scheme |
//! | `<local>` | any host with no dot in it, plus loopback |
//! | `<loopback>` | loopback addresses and `localhost` |
//! | `/regex/` | a regular expression, anchored to the whole host |
//!
//! Every pattern is anchored: `example.com` never matches
//! `example.com.attacker.net`. That matters more here than elsewhere, because a
//! rule that matches too much sends traffic around the proxy and exposes the
//! real IP.

use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use url::Url;

/// Why a rule could not be parsed. `code()` is what the frontend translates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassRuleError {
  Empty,
  InvalidHost,
  InvalidPort,
  InvalidCidr,
  InvalidScheme,
  InvalidRegex,
}

impl BypassRuleError {
  pub fn code(self) -> &'static str {
    match self {
      Self::Empty => "BYPASS_RULE_EMPTY",
      Self::InvalidHost => "BYPASS_RULE_INVALID_HOST",
      Self::InvalidPort => "BYPASS_RULE_INVALID_PORT",
      Self::InvalidCidr => "BYPASS_RULE_INVALID_CIDR",
      Self::InvalidScheme => "BYPASS_RULE_INVALID_SCHEME",
      Self::InvalidRegex => "BYPASS_RULE_INVALID_REGEX",
    }
  }
}

impl std::fmt::Display for BypassRuleError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.code())
  }
}

impl std::error::Error for BypassRuleError {}

#[derive(Debug)]
enum RuleKind {
  /// Hosts with no dot (plus loopback) — the intranet shorthand.
  Local,
  /// Loopback addresses and `localhost`.
  Loopback,
  /// One exact address.
  Ip(IpAddr),
  /// An address range.
  Cidr { network: IpAddr, prefix: u8 },
  /// A domain and all of its subdomains.
  Domain(String),
  /// Subdomains of a domain, but not the domain itself.
  Subdomains(String),
  /// A `*`/`?` glob over the whole host.
  Wildcard(String),
  /// A user-supplied regex, anchored and case-insensitive.
  Regex { source: String, compiled: Regex },
}

impl RuleKind {
  fn name(&self) -> &'static str {
    match self {
      Self::Local => "local",
      Self::Loopback => "loopback",
      Self::Ip(_) => "ip",
      Self::Cidr { .. } => "cidr",
      Self::Domain(_) => "domain",
      Self::Subdomains(_) => "subdomains",
      Self::Wildcard(_) => "wildcard",
      Self::Regex { .. } => "regex",
    }
  }
}

#[derive(Debug)]
pub struct BypassRule {
  kind: RuleKind,
  port: Option<u16>,
  scheme: Option<String>,
}

impl BypassRule {
  /// Stable identifier for the rule's shape, used by the UI to label it.
  pub fn kind_name(&self) -> &'static str {
    self.kind.name()
  }

  /// The rule rewritten in canonical form: lowercased, pasted URL paths
  /// dropped, `.example.com` normalized to `*.example.com`. This is what gets
  /// stored, so two spellings of the same rule dedupe against each other.
  pub fn canonical(&self) -> String {
    let host = match &self.kind {
      RuleKind::Local => "<local>".to_string(),
      RuleKind::Loopback => "<loopback>".to_string(),
      RuleKind::Ip(ip) => bracketed(&ip.to_string(), self.port.is_some() && ip.is_ipv6()),
      RuleKind::Cidr { network, prefix } => format!("{network}/{prefix}"),
      RuleKind::Domain(d) => d.clone(),
      RuleKind::Subdomains(d) => format!("*.{d}"),
      RuleKind::Wildcard(p) => p.clone(),
      RuleKind::Regex { source, .. } => format!("/{source}/"),
    };

    let mut out = String::new();
    if let Some(scheme) = &self.scheme {
      out.push_str(scheme);
      out.push_str("://");
    }
    out.push_str(&host);
    if let Some(port) = self.port {
      out.push(':');
      out.push_str(&port.to_string());
    }
    out
  }

  /// `host` must already be normalized by [`normalize_host`]; `ip` is the same
  /// host pre-parsed, so a long rule list doesn't re-parse it per rule.
  fn matches(
    &self,
    host: &str,
    ip: Option<IpAddr>,
    port: Option<u16>,
    scheme: Option<&str>,
  ) -> bool {
    // A narrowed rule only fires when we actually know the port/scheme.
    // Unknown means "not this rule": staying on the proxy is the safe answer.
    if let Some(want) = self.port {
      if port != Some(want) {
        return false;
      }
    }
    if let Some(want) = &self.scheme {
      match scheme {
        Some(got) if got.eq_ignore_ascii_case(want) => {}
        _ => return false,
      }
    }

    match &self.kind {
      RuleKind::Local => is_loopback(host, ip) || (ip.is_none() && !host.contains('.')),
      RuleKind::Loopback => is_loopback(host, ip),
      RuleKind::Ip(want) => ip == Some(*want),
      RuleKind::Cidr { network, prefix } => ip.is_some_and(|a| cidr_contains(*network, *prefix, a)),
      RuleKind::Domain(d) => host == d || host.ends_with(&format!(".{d}")),
      RuleKind::Subdomains(d) => host.ends_with(&format!(".{d}")),
      RuleKind::Wildcard(p) => glob_match(p, host),
      RuleKind::Regex { compiled, .. } => compiled.is_match(host),
    }
  }
}

/// A compiled bypass list. Cloning is cheap — workers hand one to every
/// connection task.
#[derive(Clone, Default)]
pub struct BypassMatcher {
  rules: Arc<Vec<(String, BypassRule)>>,
}

impl BypassMatcher {
  /// Invalid rules are logged and dropped rather than failing the launch: a
  /// browser that starts with one bad rule beats a browser that won't start.
  /// The UI rejects them at entry, so reaching this is already unusual.
  pub fn new(rules: &[String]) -> Self {
    let mut parsed = Vec::with_capacity(rules.len());
    for raw in rules {
      match parse_rule(raw) {
        Ok(rule) => parsed.push((raw.trim().to_string(), rule)),
        Err(e) => log::warn!("[bypass] Ignoring unparsable rule {raw:?}: {}", e.code()),
      }
    }
    if !parsed.is_empty() {
      log::info!("[bypass] Loaded {} bypass rule(s)", parsed.len());
    }
    Self {
      rules: Arc::new(parsed),
    }
  }

  pub fn is_empty(&self) -> bool {
    self.rules.is_empty()
  }

  /// The first rule that sends this request direct, if any. `port`/`scheme` are
  /// `None` when the caller genuinely cannot know them.
  pub fn matching_rule(&self, host: &str, port: Option<u16>, scheme: Option<&str>) -> Option<&str> {
    if self.rules.is_empty() {
      return None;
    }
    let host = normalize_host(host);
    if host.is_empty() {
      return None;
    }
    let ip = host.parse::<IpAddr>().ok().map(normalize_ip);
    self
      .rules
      .iter()
      .find(|(_, rule)| rule.matches(&host, ip, port, scheme))
      .map(|(source, _)| source.as_str())
  }

  pub fn should_bypass(&self, host: &str, port: Option<u16>, scheme: Option<&str>) -> bool {
    self.matching_rule(host, port, scheme).is_some()
  }
}

/// One rule as the UI sees it: whether it parsed, what shape it is, and — when
/// a test host was supplied — whether it would send that host direct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRuleReport {
  pub rule: String,
  pub canonical: Option<String>,
  pub kind: Option<String>,
  pub error_code: Option<String>,
  pub matches_target: Option<bool>,
}

/// Parse `rules`, and if `target` is given, report which of them would bypass
/// it. `target` may be a bare host, a `host:port`, or a full URL.
pub fn report_rules(rules: &[String], target: Option<&str>) -> Vec<BypassRuleReport> {
  let parsed_target = target.and_then(parse_target);
  rules
    .iter()
    .map(|raw| match parse_rule(raw) {
      Ok(rule) => {
        let matches_target = parsed_target.as_ref().map(|(host, port, scheme)| {
          let ip = host.parse::<IpAddr>().ok().map(normalize_ip);
          rule.matches(host, ip, *port, scheme.as_deref())
        });
        BypassRuleReport {
          rule: raw.trim().to_string(),
          canonical: Some(rule.canonical()),
          kind: Some(rule.kind_name().to_string()),
          error_code: None,
          matches_target,
        }
      }
      Err(e) => BypassRuleReport {
        rule: raw.trim().to_string(),
        canonical: None,
        kind: None,
        error_code: Some(e.code().to_string()),
        matches_target: None,
      },
    })
    .collect()
}

/// Reject a list outright if any rule in it is unparsable, naming the first
/// offender. Used on every write path so a bad rule can never be stored.
pub fn validate_rules(rules: &[String]) -> Result<Vec<String>, (String, BypassRuleError)> {
  let mut canonical = Vec::with_capacity(rules.len());
  for raw in rules {
    match parse_rule(raw) {
      Ok(rule) => {
        let value = rule.canonical();
        if !canonical.contains(&value) {
          canonical.push(value);
        }
      }
      Err(e) => return Err((raw.trim().to_string(), e)),
    }
  }
  Ok(canonical)
}

/// Backs the bypass-list editor: tells it whether each rule parses, what shape
/// it is, and — when the user types a host to try — which rules would send it
/// direct. Read-only; it never touches stored state.
#[tauri::command]
pub fn check_proxy_bypass_rules(
  rules: Vec<String>,
  target: Option<String>,
) -> Vec<BypassRuleReport> {
  report_rules(&rules, target.as_deref())
}

/// Split a user-typed test target into host, port and scheme.
fn parse_target(target: &str) -> Option<(String, Option<u16>, Option<String>)> {
  let trimmed = target.trim();
  if trimmed.is_empty() {
    return None;
  }

  let (scheme, rest) = match trimmed.split_once("://") {
    Some((s, r)) => (Some(s.to_lowercase()), r.to_string()),
    None => (None, trimmed.to_string()),
  };
  let rest = rest
    .split(['/', '?', '#'])
    .next()
    .unwrap_or_default()
    .to_string();
  // Credentials in a pasted URL are not part of the host.
  let rest = rest
    .rsplit_once('@')
    .map_or(rest.clone(), |(_, h)| h.to_string());
  let (host, port) = split_host_port(&rest).ok()?;
  let host = normalize_host(&host);
  if host.is_empty() {
    return None;
  }
  let port = port.or(match scheme.as_deref() {
    Some("http") => Some(80),
    Some("https") => Some(443),
    _ => None,
  });
  Some((host, port, scheme))
}

pub fn parse_rule(raw: &str) -> Result<BypassRule, BypassRuleError> {
  let trimmed = raw.trim();
  if trimmed.is_empty() || trimmed.starts_with('#') {
    return Err(BypassRuleError::Empty);
  }

  // Explicit regex form, kept verbatim so patterns can be case-sensitive
  // about nothing else the parser would lowercase.
  if trimmed.len() >= 2 && trimmed.starts_with('/') && trimmed.ends_with('/') {
    return Ok(BypassRule {
      kind: compile_regex(&trimmed[1..trimmed.len() - 1])?,
      port: None,
      scheme: None,
    });
  }

  let lowered = trimmed.to_lowercase();
  if lowered == "<local>" {
    return Ok(plain(RuleKind::Local));
  }
  if lowered == "<loopback>" {
    return Ok(plain(RuleKind::Loopback));
  }

  let (scheme, rest) = match lowered.split_once("://") {
    Some((s, r)) => {
      if s.is_empty()
        || !s
          .chars()
          .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
      {
        return Err(BypassRuleError::InvalidScheme);
      }
      (Some(s.to_string()), r.to_string())
    }
    None => (None, lowered.clone()),
  };
  if rest.is_empty() {
    return Err(BypassRuleError::InvalidHost);
  }

  // CIDR is the only meaning a `/` can have here; anything else after a slash
  // is a pasted URL path and is dropped.
  if let Some((addr, prefix)) = rest.split_once('/') {
    if let Ok(network) = addr.parse::<IpAddr>() {
      let prefix: u8 = prefix.parse().map_err(|_| BypassRuleError::InvalidCidr)?;
      let max = if network.is_ipv4() { 32 } else { 128 };
      if prefix > max {
        return Err(BypassRuleError::InvalidCidr);
      }
      return Ok(BypassRule {
        kind: RuleKind::Cidr {
          network: normalize_ip(network),
          prefix,
        },
        port: None,
        scheme,
      });
    }
  }
  // Drop the path and fragment of a pasted URL. `?` only ends the host when a
  // scheme proves this is a URL — bare, it is the single-character glob, and
  // stripping it turned `10.0.0.?` into the invalid `10.0.0.`.
  let cutset: &[char] = if scheme.is_some() {
    &['/', '?', '#']
  } else {
    &['/', '#']
  };
  let rest = rest.split(cutset).next().unwrap_or_default();
  if rest.is_empty() {
    return Err(BypassRuleError::InvalidHost);
  }

  let (host, port) = split_host_port(rest)?;
  if host.is_empty() {
    return Err(BypassRuleError::InvalidHost);
  }

  let kind = if let Ok(ip) = host.parse::<IpAddr>() {
    RuleKind::Ip(normalize_ip(ip))
  } else if host.contains(is_regex_only_meta) {
    // Rules written before this parser existed were compiled as bare regexes.
    // Keep honouring them, but anchored, so `.*\.local` no longer also matches
    // `foo.local.attacker.net`.
    compile_regex(&host)?
  } else if let Some(base) = subdomain_base(&host) {
    let base = to_ascii_domain(base)?;
    check_host(&base)?;
    RuleKind::Subdomains(base)
  } else if host.contains(['*', '?']) {
    RuleKind::Wildcard(host.clone())
  } else {
    let host = to_ascii_domain(&host)?;
    check_host(&host)?;
    RuleKind::Domain(host)
  };

  Ok(BypassRule { kind, port, scheme })
}

fn plain(kind: RuleKind) -> BypassRule {
  BypassRule {
    kind,
    port: None,
    scheme: None,
  }
}

fn compile_regex(body: &str) -> Result<RuleKind, BypassRuleError> {
  if body.is_empty() {
    return Err(BypassRuleError::InvalidRegex);
  }
  let compiled =
    Regex::new(&format!("(?i)^(?:{body})$")).map_err(|_| BypassRuleError::InvalidRegex)?;
  Ok(RuleKind::Regex {
    source: body.to_string(),
    compiled,
  })
}

/// `*.example.com` and `.example.com` mean "subdomains of this domain" — but
/// only when a plain domain follows. `*.corp.*` is a general glob instead.
fn subdomain_base(host: &str) -> Option<&str> {
  let base = host.strip_prefix("*.").or_else(|| host.strip_prefix('.'))?;
  if base.is_empty() || base.contains(['*', '?']) {
    return None;
  }
  Some(base)
}

fn is_regex_only_meta(c: char) -> bool {
  matches!(
    c,
    '\\' | '^' | '$' | '[' | ']' | '(' | ')' | '+' | '|' | '{' | '}'
  )
}

/// Browsers put punycode on the wire, so `例え.jp` typed as-is would match
/// nothing. Convert an internationalized domain once, at parse time.
fn to_ascii_domain(host: &str) -> Result<String, BypassRuleError> {
  if host.is_ascii() {
    return Ok(host.to_string());
  }
  Url::parse(&format!("http://{host}"))
    .ok()
    .and_then(|url| url.host_str().map(str::to_string))
    .ok_or(BypassRuleError::InvalidHost)
}

fn check_host(host: &str) -> Result<(), BypassRuleError> {
  if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
    return Err(BypassRuleError::InvalidHost);
  }
  if host
    .chars()
    .all(|c| c.is_alphanumeric() || matches!(c, '-' | '.' | '_'))
  {
    Ok(())
  } else {
    Err(BypassRuleError::InvalidHost)
  }
}

/// Split `host:port`, leaving bare IPv6 literals (many colons, no brackets)
/// alone and unwrapping bracketed ones.
fn split_host_port(input: &str) -> Result<(String, Option<u16>), BypassRuleError> {
  if let Some(inner) = input.strip_prefix('[') {
    let close = inner.find(']').ok_or(BypassRuleError::InvalidHost)?;
    let host = inner[..close].to_string();
    let tail = &inner[close + 1..];
    if tail.is_empty() {
      return Ok((host, None));
    }
    let port = tail
      .strip_prefix(':')
      .ok_or(BypassRuleError::InvalidHost)?
      .parse::<u16>()
      .map_err(|_| BypassRuleError::InvalidPort)?;
    if port == 0 {
      return Err(BypassRuleError::InvalidPort);
    }
    return Ok((host, Some(port)));
  }

  match input.rsplit_once(':') {
    Some((head, tail)) if !head.contains(':') => {
      let port = tail
        .parse::<u16>()
        .map_err(|_| BypassRuleError::InvalidPort)?;
      if port == 0 {
        return Err(BypassRuleError::InvalidPort);
      }
      Ok((head.to_string(), Some(port)))
    }
    _ => Ok((input.to_string(), None)),
  }
}

/// Lowercase, unbracket, and drop the FQDN root dot so `Example.COM.` and
/// `example.com` are the same host.
fn normalize_host(host: &str) -> String {
  let host = host.trim().trim_end_matches('.').to_lowercase();
  host
    .strip_prefix('[')
    .and_then(|h| h.strip_suffix(']'))
    .map_or(host.clone(), str::to_string)
}

/// `::ffff:192.0.2.1` and `192.0.2.1` are the same address; store and compare
/// them as one so an IPv4 rule still covers a v4-mapped connection.
fn normalize_ip(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
    v4 => v4,
  }
}

fn is_loopback(host: &str, ip: Option<IpAddr>) -> bool {
  ip.is_some_and(|a| a.is_loopback()) || host == "localhost" || host.ends_with(".localhost")
}

fn bracketed(host: &str, wrap: bool) -> String {
  if wrap {
    format!("[{host}]")
  } else {
    host.to_string()
  }
}

fn cidr_contains(network: IpAddr, prefix: u8, addr: IpAddr) -> bool {
  match (network, addr) {
    (IpAddr::V4(n), IpAddr::V4(a)) => prefix_eq(&n.octets(), &a.octets(), prefix),
    (IpAddr::V6(n), IpAddr::V6(a)) => prefix_eq(&n.octets(), &a.octets(), prefix),
    _ => false,
  }
}

fn prefix_eq(network: &[u8], addr: &[u8], prefix: u8) -> bool {
  let whole = (prefix / 8) as usize;
  if network[..whole] != addr[..whole] {
    return false;
  }
  let remainder = prefix % 8;
  if remainder == 0 {
    return true;
  }
  let mask = 0xffu8 << (8 - remainder);
  network[whole] & mask == addr[whole] & mask
}

/// `*` matches any run of characters (dots included), `?` exactly one.
fn glob_match(pattern: &str, value: &str) -> bool {
  let p: Vec<char> = pattern.chars().collect();
  let v: Vec<char> = value.chars().collect();
  let (mut pi, mut vi) = (0usize, 0usize);
  let mut star: Option<usize> = None;
  let mut resume = 0usize;

  while vi < v.len() {
    if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
      pi += 1;
      vi += 1;
    } else if pi < p.len() && p[pi] == '*' {
      star = Some(pi);
      resume = vi;
      pi += 1;
    } else if let Some(s) = star {
      pi = s + 1;
      resume += 1;
      vi = resume;
    } else {
      return false;
    }
  }
  p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
  use super::*;

  fn matcher(rules: &[&str]) -> BypassMatcher {
    BypassMatcher::new(&rules.iter().map(|r| (*r).to_string()).collect::<Vec<_>>())
  }

  fn bypasses(rules: &[&str], host: &str) -> bool {
    matcher(rules).should_bypass(host, None, None)
  }

  #[test]
  fn bare_domain_covers_the_apex_and_its_subdomains() {
    assert!(bypasses(&["example.com"], "example.com"));
    assert!(bypasses(&["example.com"], "www.example.com"));
    assert!(bypasses(&["example.com"], "a.b.example.com"));
  }

  #[test]
  fn bare_domain_does_not_leak_to_lookalike_hosts() {
    // The old matcher compiled rules as unanchored regexes, so every one of
    // these went direct — around the proxy — for an attacker-chosen host.
    assert!(!bypasses(&["example.com"], "example.com.attacker.net"));
    assert!(!bypasses(&["example.com"], "notexample.com"));
    assert!(!bypasses(&["example.com"], "example-com"));
    assert!(!bypasses(&["example.com"], "myexample.community"));
  }

  #[test]
  fn subdomain_only_forms_skip_the_apex() {
    for rule in ["*.example.com", ".example.com"] {
      assert!(bypasses(&[rule], "www.example.com"), "{rule}");
      assert!(!bypasses(&[rule], "example.com"), "{rule}");
      assert!(!bypasses(&[rule], "example.com.attacker.net"), "{rule}");
    }
  }

  #[test]
  fn host_normalization_ignores_case_and_the_root_dot() {
    assert!(bypasses(&["Example.COM"], "WWW.example.com."));
    assert!(bypasses(&["example.com"], "WWW.EXAMPLE.COM"));
  }

  #[test]
  fn wildcards_match_anywhere_in_the_host() {
    assert!(bypasses(&["*.corp.*"], "mail.corp.internal"));
    assert!(bypasses(
      &["staging-*.example.com"],
      "staging-7.example.com"
    ));
    assert!(!bypasses(&["staging-*.example.com"], "prod.example.com"));
    assert!(bypasses(&["10.0.0.?"], "10.0.0.7"));
    assert!(!bypasses(&["10.0.0.?"], "10.0.0.42"));
    // `?` is the glob here, not a query separator.
    assert_eq!(parse_rule("10.0.0.?").unwrap().kind_name(), "wildcard");
    // With a scheme it is a pasted URL, so the query goes.
    assert_eq!(
      parse_rule("https://example.com?q=1").unwrap().canonical(),
      "https://example.com"
    );
  }

  #[test]
  fn ip_literals_match_exactly() {
    assert!(bypasses(&["192.168.1.5"], "192.168.1.5"));
    assert!(!bypasses(&["192.168.1.5"], "192.168.1.50"));
    assert!(bypasses(&["fd00::1"], "fd00::1"));
    assert!(bypasses(&["fd00::1"], "[fd00::1]"));
  }

  #[test]
  fn cidr_rules_cover_their_range_only() {
    assert!(bypasses(&["10.0.0.0/8"], "10.255.1.1"));
    assert!(!bypasses(&["10.0.0.0/8"], "11.0.0.1"));
    assert!(bypasses(&["192.168.1.0/24"], "192.168.1.200"));
    assert!(!bypasses(&["192.168.1.0/24"], "192.168.2.1"));
    assert!(bypasses(&["172.16.0.0/12"], "172.31.255.254"));
    assert!(!bypasses(&["172.16.0.0/12"], "172.32.0.1"));
    assert!(bypasses(&["fd00::/8"], "fd12:3456::1"));
    assert!(!bypasses(&["fd00::/8"], "2001:db8::1"));
  }

  #[test]
  fn a_v4_rule_still_covers_the_v4_mapped_form_of_the_same_address() {
    assert!(bypasses(&["192.0.2.1"], "::ffff:192.0.2.1"));
    assert!(bypasses(&["192.0.2.0/24"], "::ffff:192.0.2.9"));
  }

  #[test]
  fn a_cidr_never_matches_a_hostname() {
    assert!(!bypasses(&["10.0.0.0/8"], "example.com"));
  }

  #[test]
  fn port_narrowed_rules_need_that_port() {
    let m = matcher(&["example.com:8080"]);
    assert!(m.should_bypass("example.com", Some(8080), None));
    assert!(!m.should_bypass("example.com", Some(443), None));
    // Unknown port keeps the request on the proxy rather than guessing.
    assert!(!m.should_bypass("example.com", None, None));
  }

  #[test]
  fn scheme_narrowed_rules_need_that_scheme() {
    let m = matcher(&["http://example.com"]);
    assert!(m.should_bypass("example.com", None, Some("http")));
    assert!(!m.should_bypass("example.com", None, Some("https")));
    assert!(!m.should_bypass("example.com", None, None));
  }

  #[test]
  fn an_unnarrowed_rule_matches_whatever_the_port_and_scheme_are() {
    let m = matcher(&["example.com"]);
    assert!(m.should_bypass("example.com", Some(8443), Some("https")));
    assert!(m.should_bypass("example.com", None, None));
  }

  #[test]
  fn local_covers_dotless_hosts_and_loopback() {
    assert!(bypasses(&["<local>"], "intranet"));
    assert!(bypasses(&["<local>"], "localhost"));
    assert!(bypasses(&["<local>"], "127.0.0.1"));
    assert!(!bypasses(&["<local>"], "example.com"));
    assert!(!bypasses(&["<local>"], "10.0.0.1"));
  }

  #[test]
  fn loopback_covers_both_families_and_the_name() {
    assert!(bypasses(&["<loopback>"], "127.0.0.1"));
    assert!(bypasses(&["<loopback>"], "127.5.5.5"));
    assert!(bypasses(&["<loopback>"], "::1"));
    assert!(bypasses(&["<loopback>"], "localhost"));
    assert!(!bypasses(&["<loopback>"], "192.168.0.1"));
  }

  #[test]
  fn legacy_regex_rules_keep_working_but_anchored() {
    // Written against the old regex-per-rule matcher; still honoured.
    assert!(bypasses(&[r".*\.local"], "printer.local"));
    assert!(!bypasses(&[r".*\.local"], "printer.local.attacker.net"));
    assert!(bypasses(&[r"^10\.0\.0\.\d+$"], "10.0.0.9"));
  }

  #[test]
  fn explicit_regex_form_is_anchored_and_case_insensitive() {
    assert!(bypasses(&["/example\\.(com|net)/"], "EXAMPLE.NET"));
    assert!(!bypasses(&["/example\\.(com|net)/"], "example.net.evil.io"));
  }

  #[test]
  fn internationalized_domains_are_stored_as_punycode() {
    let rule = parse_rule("例え.jp").unwrap();
    assert_eq!(rule.canonical(), "xn--r8jz45g.jp");
    // The browser asks for the punycode form, which is what has to match.
    assert!(bypasses(&["例え.jp"], "www.xn--r8jz45g.jp"));
    assert!(bypasses(&[".例え.jp"], "www.xn--r8jz45g.jp"));
  }

  #[test]
  fn a_pasted_url_is_reduced_to_its_host() {
    let m = matcher(&["https://example.com/some/path?q=1"]);
    assert!(m.should_bypass("www.example.com", Some(443), Some("https")));
    let rule = parse_rule("https://example.com/some/path?q=1").unwrap();
    assert_eq!(rule.canonical(), "https://example.com");
  }

  #[test]
  fn canonical_form_normalizes_equivalent_spellings() {
    for (input, expected) in [
      (" Example.COM ", "example.com"),
      (".example.com", "*.example.com"),
      ("*.example.com", "*.example.com"),
      ("HTTPS://Example.com:8443", "https://example.com:8443"),
      ("10.0.0.0/8", "10.0.0.0/8"),
      ("<LOCAL>", "<local>"),
      ("[fd00::1]:443", "[fd00::1]:443"),
      ("fd00::1", "fd00::1"),
    ] {
      assert_eq!(parse_rule(input).unwrap().canonical(), expected, "{input}");
    }
  }

  #[test]
  fn validate_rules_canonicalizes_and_dedupes() {
    let rules = vec![
      "Example.com".to_string(),
      "example.com".to_string(),
      ".corp.internal".to_string(),
    ];
    assert_eq!(
      validate_rules(&rules).unwrap(),
      vec!["example.com".to_string(), "*.corp.internal".to_string()]
    );
  }

  #[test]
  fn validate_rules_names_the_first_bad_rule() {
    let rules = vec!["example.com".to_string(), "10.0.0.0/99".to_string()];
    let (offender, error) = validate_rules(&rules).unwrap_err();
    assert_eq!(offender, "10.0.0.0/99");
    assert_eq!(error, BypassRuleError::InvalidCidr);
  }

  #[test]
  fn malformed_rules_are_rejected_with_a_reason() {
    for (rule, expected) in [
      ("", BypassRuleError::Empty),
      ("   ", BypassRuleError::Empty),
      ("# a comment", BypassRuleError::Empty),
      ("example.com:0", BypassRuleError::InvalidPort),
      ("example.com:99999", BypassRuleError::InvalidPort),
      ("example.com:https", BypassRuleError::InvalidPort),
      ("10.0.0.0/33", BypassRuleError::InvalidCidr),
      ("fd00::/129", BypassRuleError::InvalidCidr),
      ("ht tp://example.com", BypassRuleError::InvalidScheme),
      ("/(unclosed/", BypassRuleError::InvalidRegex),
      ("exa mple.com", BypassRuleError::InvalidHost),
      ("exam!ple.com", BypassRuleError::InvalidHost),
      ("..example.com", BypassRuleError::InvalidHost),
    ] {
      assert_eq!(parse_rule(rule).unwrap_err(), expected, "{rule:?}");
    }
  }

  #[test]
  fn an_invalid_rule_never_disables_the_valid_ones() {
    let m = matcher(&["exam ple.com", "example.com"]);
    assert!(m.should_bypass("example.com", None, None));
    assert!(!m.should_bypass("other.com", None, None));
  }

  #[test]
  fn an_empty_list_bypasses_nothing() {
    let m = matcher(&[]);
    assert!(m.is_empty());
    assert!(!m.should_bypass("example.com", None, None));
  }

  #[test]
  fn matching_rule_reports_the_rule_as_the_user_typed_it() {
    let m = matcher(&["other.com", "*.example.com"]);
    assert_eq!(
      m.matching_rule("www.example.com", None, None),
      Some("*.example.com")
    );
    assert_eq!(m.matching_rule("example.com", None, None), None);
  }

  #[test]
  fn kind_names_describe_the_parsed_shape() {
    for (rule, kind) in [
      ("example.com", "domain"),
      ("*.example.com", "subdomains"),
      ("sta*.example.com", "wildcard"),
      ("10.0.0.1", "ip"),
      ("10.0.0.0/8", "cidr"),
      ("<local>", "local"),
      ("<loopback>", "loopback"),
      ("/foo.*/", "regex"),
    ] {
      assert_eq!(parse_rule(rule).unwrap().kind_name(), kind, "{rule}");
    }
  }

  #[test]
  fn report_rules_answers_would_this_host_go_direct() {
    let rules = vec![
      "*.example.com".to_string(),
      "10.0.0.0/8".to_string(),
      "nope!!".to_string(),
    ];

    let report = report_rules(&rules, Some("https://www.example.com/dashboard"));
    assert_eq!(report[0].matches_target, Some(true));
    assert_eq!(report[1].matches_target, Some(false));
    assert_eq!(report[2].matches_target, None);
    assert_eq!(
      report[2].error_code.as_deref(),
      Some("BYPASS_RULE_INVALID_HOST")
    );

    // No target: shape and validity only.
    let report = report_rules(&rules, None);
    assert!(report.iter().all(|r| r.matches_target.is_none()));
    assert_eq!(report[0].kind.as_deref(), Some("subdomains"));
  }

  #[test]
  fn report_rules_applies_the_targets_port_and_scheme() {
    let rules = vec![
      "example.com:8080".to_string(),
      "https://example.com".to_string(),
    ];

    let report = report_rules(&rules, Some("example.com:8080"));
    assert_eq!(report[0].matches_target, Some(true));
    assert_eq!(report[1].matches_target, Some(false));

    // A scheme with no explicit port still implies the default port.
    let report = report_rules(&rules, Some("https://example.com"));
    assert_eq!(report[0].matches_target, Some(false));
    assert_eq!(report[1].matches_target, Some(true));
  }

  #[test]
  fn glob_matching_handles_backtracking() {
    assert!(glob_match("*.com", "a.b.com"));
    assert!(glob_match("*a*b*", "xxaxxbxx"));
    assert!(!glob_match("*a*b*c", "xxaxxbxx"));
    assert!(glob_match("**", "anything"));
    assert!(glob_match("*", ""));
    assert!(!glob_match("?", ""));
  }
}
