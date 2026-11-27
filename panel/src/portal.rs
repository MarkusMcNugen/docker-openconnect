//! What the helper keeps in memory for the VPN user portal: portal sessions
//! and failed sign-ins per VPN user, apart from the admin panel's, so that
//! no admin request accepts a portal token and the two lockouts never mix.
//! Tokens are kept only as their SHA-256 digests.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::secret;
use crate::sessions::Issued;

/// What a portal session may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalScope {
    /// Everything the portal offers a VPN user.
    Full,
    /// Only enrolling the user's first authenticator key: a user without a
    /// key, signed in with the password alone while the VPN asks for codes.
    EnrollKey,
}

/// A VPN user signed in to the portal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSession {
    pub user: String,
    pub scope: PortalScope,
    pub from: IpAddr,
    /// The token every change made in this session must carry.
    pub csrf: String,
    pub created: u64,
    pub last_seen: u64,
    /// When the user last proved who they are.
    pub authenticated: u64,
}

/// Live portal sessions with an idle limit and an absolute limit, in
/// seconds.
pub struct PortalSessions {
    by_digest: HashMap<[u8; 32], PortalSession>,
    idle: u64,
    max: u64,
}

impl PortalSessions {
    pub fn new(idle: u64, max: u64) -> PortalSessions {
        PortalSessions {
            by_digest: HashMap::new(),
            idle,
            max,
        }
    }

    /// When `session` ends unless it is used again.
    pub fn expires(&self, session: &PortalSession) -> u64 {
        (session.last_seen + self.idle).min(session.created + self.max)
    }

    /// Starts a session for `user` and returns its tokens.
    pub fn create(
        &mut self,
        user: &str,
        scope: PortalScope,
        from: IpAddr,
        now: u64,
    ) -> Result<Issued, String> {
        self.by_digest.retain(|_digest, session| {
            now < (session.last_seen + self.idle).min(session.created + self.max)
        });
        let token = secret::token()?;
        let csrf = secret::token()?;
        let session = PortalSession {
            user: user.to_owned(),
            scope,
            from,
            csrf: csrf.clone(),
            created: now,
            last_seen: now,
            authenticated: now,
        };
        let expires = self.expires(&session);
        self.by_digest.insert(secret::digest(&token), session);
        Ok(Issued {
            token,
            csrf,
            expires,
        })
    }

    /// The live session for `token`, with its idle timer restarted. An
    /// expired session is removed and not returned.
    pub fn touch(&mut self, token: &str, now: u64) -> Option<PortalSession> {
        let key = secret::digest(token);
        let live = self
            .by_digest
            .get(&key)
            .is_some_and(|session| now < self.expires(session));
        if !live {
            self.by_digest.remove(&key);
            return None;
        }
        let session = self.by_digest.get_mut(&key)?;
        session.last_seen = now;
        Some(session.clone())
    }

    /// Gives the session for `token` the full scope, once its user has
    /// enrolled a key.
    pub fn widen(&mut self, token: &str) -> bool {
        match self.by_digest.get_mut(&secret::digest(token)) {
            Some(session) => {
                session.scope = PortalScope::Full;
                true
            }
            None => false,
        }
    }

    pub fn end(&mut self, token: &str) -> bool {
        self.by_digest.remove(&secret::digest(token)).is_some()
    }

    /// Ends every session of `user` but the one for `keep`; how many ended.
    pub fn end_user(&mut self, user: &str, keep: Option<&str>) -> usize {
        let kept = keep.map(secret::digest);
        let before = self.by_digest.len();
        self.by_digest
            .retain(|digest, session| session.user != user || kept.as_ref() == Some(digest));
        before - self.by_digest.len()
    }
}

/// Failed portal sign-ins in a row per VPN user: `max` of them lock the user
/// out of the portal for `window` seconds after the last one.
pub struct UserLockout {
    failures: HashMap<String, (u32, u64)>,
    max: u32,
    window: u64,
}

impl UserLockout {
    pub fn new(max: u32, window: u64) -> UserLockout {
        UserLockout {
            failures: HashMap::new(),
            max,
            window,
        }
    }

    /// Seconds left of `user`'s lockout, if they are locked out.
    pub fn locked(&self, user: &str, now: u64) -> Option<u64> {
        let (count, last) = self.failures.get(user)?;
        let until = last + self.window;
        (*count >= self.max && now < until).then_some(until - now)
    }

    /// Counts a failure; true when it locks the user out.
    pub fn failure(&mut self, user: &str, now: u64) -> bool {
        let window = self.window;
        self.failures
            .retain(|_user, (_count, last)| now < *last + window);
        let entry = self.failures.entry(user.to_owned()).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        entry.0 >= self.max
    }

    pub fn success(&mut self, user: &str) {
        self.failures.remove(user);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));

    #[test]
    fn a_session_lives_until_idle_or_old_and_can_be_widened_and_ended() {
        let mut sessions = PortalSessions::new(60, 300);
        let issued = sessions
            .create("sam", PortalScope::EnrollKey, FROM, 0)
            .unwrap();
        let session = sessions.touch(&issued.token, 50).unwrap();
        assert_eq!(
            (session.user.as_str(), session.scope),
            ("sam", PortalScope::EnrollKey)
        );
        assert!(sessions.widen(&issued.token));
        assert_eq!(
            sessions.touch(&issued.token, 100).unwrap().scope,
            PortalScope::Full
        );
        assert!(sessions.touch(&issued.token, 161).is_none());
        let long = sessions.create("sam", PortalScope::Full, FROM, 0).unwrap();
        for now in [50, 100, 150, 200, 250] {
            assert!(sessions.touch(&long.token, now).is_some());
        }
        assert!(sessions.touch(&long.token, 300).is_none());
        let first = sessions
            .create("sam", PortalScope::Full, FROM, 400)
            .unwrap();
        let second = sessions
            .create("sam", PortalScope::Full, FROM, 400)
            .unwrap();
        let other = sessions
            .create("riley", PortalScope::Full, FROM, 400)
            .unwrap();
        assert_eq!(sessions.end_user("sam", Some(&first.token)), 1);
        assert!(sessions.touch(&first.token, 401).is_some());
        assert!(sessions.touch(&second.token, 401).is_none());
        assert!(sessions.end(&other.token));
        assert!(!sessions.end(&other.token));
    }

    #[test]
    fn failures_in_a_row_lock_a_user_out_for_the_window() {
        let mut lockout = UserLockout::new(3, 900);
        assert!(!lockout.failure("sam", 10));
        assert!(!lockout.failure("sam", 11));
        assert_eq!(lockout.locked("sam", 12), None);
        assert!(lockout.failure("sam", 12));
        assert_eq!(lockout.locked("sam", 12), Some(900));
        assert_eq!(lockout.locked("riley", 12), None);
        assert_eq!(lockout.locked("sam", 912), None);
        lockout.success("sam");
        assert_eq!(lockout.locked("sam", 13), None);
    }
}
