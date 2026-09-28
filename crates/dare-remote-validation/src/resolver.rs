//! The pinned resolver (BLUEPRINT AD-04).
//!
//! The first lookup of the planned host resolves it once, classifies every
//! address, and refuses the whole host if any address is not permitted: a
//! mixed answer (one public record, one private) is exactly what a rebinding
//! attack looks like. A permitted answer is pinned for the rest of the run, so
//! a later answer that changes is never seen. Any other host name is refused:
//! the gateway only ever builds URLs for the planned origin.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::address::{classify, permitted, NetworkScope};
use crate::error::EgressRefusal;

type Lookup = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

struct Inner {
    host: String,
    scope: NetworkScope,
    pinned: Mutex<BTreeMap<String, Vec<IpAddr>>>,
    refusal: Mutex<Option<EgressRefusal>>,
    injected: Option<Lookup>,
}

/// Cheap to clone; clones share the pin.
#[derive(Clone)]
pub struct PinnedResolver {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Refused(EgressRefusal);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Refused {}

impl PinnedResolver {
    /// A resolver for exactly `host` (lowercase), permitting `scope`.
    pub fn new(host: &str, scope: NetworkScope) -> PinnedResolver {
        Self::build(host, scope, None)
    }

    /// Test seam: answers come from `lookup` instead of the system resolver.
    #[cfg(any(test, feature = "lab"))]
    pub fn with_lookup(
        host: &str,
        scope: NetworkScope,
        lookup: impl Fn(&str) -> Vec<IpAddr> + Send + Sync + 'static,
    ) -> PinnedResolver {
        Self::build(host, scope, Some(Arc::new(lookup)))
    }

    fn build(host: &str, scope: NetworkScope, injected: Option<Lookup>) -> PinnedResolver {
        PinnedResolver {
            inner: Arc::new(Inner {
                host: host.to_ascii_lowercase(),
                scope,
                pinned: Mutex::new(BTreeMap::new()),
                refusal: Mutex::new(None),
                injected,
            }),
        }
    }

    /// The addresses pinned so far, for the capture.
    pub fn pinned(&self) -> Vec<IpAddr> {
        self.inner
            .pinned
            .lock()
            .map(|map| map.values().flatten().copied().collect())
            .unwrap_or_default()
    }

    /// Why the last lookup was refused, if one was.
    pub fn last_refusal(&self) -> Option<EgressRefusal> {
        self.inner.refusal.lock().ok().and_then(|slot| *slot)
    }

    /// Resolve and pin, or refuse.
    pub async fn resolve_host(&self, name: &str) -> Result<Vec<IpAddr>, EgressRefusal> {
        let inner = &self.inner;
        let name = name.to_ascii_lowercase();
        let outcome = async {
            if name != inner.host {
                return Err(EgressRefusal::AddressNotPermitted);
            }
            if let Some(pinned) = inner
                .pinned
                .lock()
                .ok()
                .and_then(|map| map.get(&name).cloned())
            {
                return Ok(pinned);
            }
            let answers: Vec<IpAddr> = match &inner.injected {
                Some(lookup) => lookup(&name),
                None => tokio::net::lookup_host((name.as_str(), 0))
                    .await
                    .map_err(|_| EgressRefusal::Resolution)?
                    .map(|addr| addr.ip())
                    .collect(),
            };
            if answers.is_empty() {
                return Err(EgressRefusal::Resolution);
            }
            if !answers
                .iter()
                .all(|ip| permitted(classify(*ip), inner.scope))
            {
                return Err(EgressRefusal::AddressNotPermitted);
            }
            let mut answers = answers;
            answers.sort();
            answers.dedup();
            if let Ok(mut map) = inner.pinned.lock() {
                map.insert(name.clone(), answers.clone());
            }
            Ok(answers)
        }
        .await;
        if let Err(refusal) = outcome {
            if let Ok(mut slot) = inner.refusal.lock() {
                *slot = Some(refusal);
            }
        }
        outcome
    }
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            match this.resolve_host(&host).await {
                Ok(ips) => {
                    let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
                    Ok(addrs)
                }
                Err(refusal) => {
                    Err(Box::new(Refused(refusal)) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn a_permitted_answer_is_pinned_and_a_changed_answer_is_never_seen() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let resolver =
            PinnedResolver::with_lookup("agent.example.test", NetworkScope::Public, move |_| {
                // First answer public, every later one loopback: a rebinding.
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    vec![ip("93.184.216.34")]
                } else {
                    vec![ip("127.0.0.1")]
                }
            });
        for _ in 0..3 {
            assert_eq!(
                resolver.resolve_host("agent.example.test").await.unwrap(),
                vec![ip("93.184.216.34")]
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "resolved once");
        assert_eq!(resolver.pinned(), vec![ip("93.184.216.34")]);
    }

    #[tokio::test]
    async fn a_rebinding_to_loopback_on_first_answer_is_refused() {
        let resolver =
            PinnedResolver::with_lookup("agent.example.test", NetworkScope::Public, |_| {
                vec![ip("127.0.0.1")]
            });
        assert_eq!(
            resolver.resolve_host("agent.example.test").await,
            Err(EgressRefusal::AddressNotPermitted)
        );
        assert_eq!(
            resolver.last_refusal(),
            Some(EgressRefusal::AddressNotPermitted)
        );
        assert!(resolver.pinned().is_empty());
    }

    #[tokio::test]
    async fn a_mixed_answer_refuses_the_whole_host() {
        for private in ["10.0.0.5", "169.254.169.254", "::1", "::ffff:192.168.0.1"] {
            let p = ip(private);
            let resolver = PinnedResolver::with_lookup(
                "agent.example.test",
                NetworkScope::Public,
                move |_| vec![ip("93.184.216.34"), p],
            );
            assert_eq!(
                resolver.resolve_host("agent.example.test").await,
                Err(EgressRefusal::AddressNotPermitted),
                "{private}"
            );
        }
    }

    #[tokio::test]
    async fn another_host_name_is_refused_without_a_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let resolver =
            PinnedResolver::with_lookup("agent.example.test", NetworkScope::Public, move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                vec![ip("93.184.216.34")]
            });
        assert_eq!(
            resolver.resolve_host("other.example.test").await,
            Err(EgressRefusal::AddressNotPermitted)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_empty_answer_is_a_resolution_failure() {
        let resolver =
            PinnedResolver::with_lookup("agent.example.test", NetworkScope::Public, |_| vec![]);
        assert_eq!(
            resolver.resolve_host("agent.example.test").await,
            Err(EgressRefusal::Resolution)
        );
    }

    #[tokio::test]
    async fn scope_decides_private_and_loopback() {
        let private =
            PinnedResolver::with_lookup("svc.internal.test", NetworkScope::Private, |_| {
                vec![ip("10.2.3.4")]
            });
        assert!(private.resolve_host("svc.internal.test").await.is_ok());
        let lab = PinnedResolver::with_lookup("localhost", NetworkScope::LoopbackLab, |_| {
            vec![ip("127.0.0.1"), ip("::1")]
        });
        assert_eq!(lab.resolve_host("LOCALHOST").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_reqwest_trait_carries_the_refusal() {
        let resolver =
            PinnedResolver::with_lookup("agent.example.test", NetworkScope::Public, |_| {
                vec![ip("169.254.169.254")]
            });
        let name: Name = "agent.example.test".parse().unwrap();
        let error = match Resolve::resolve(&resolver, name).await {
            Err(error) => error,
            Ok(_) => panic!("resolved a metadata address"),
        };
        assert!(error.to_string().contains("not permitted"));
    }
}
