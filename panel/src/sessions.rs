//! What the helper keeps in memory between requests: signed-in sessions,
//! sign-ins waiting for their second factor, and failed sign-ins per
//! address. Tokens are kept only as their SHA-256 digests, and a restart of
//! the helper ends every session.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::secret;
use crate::store::Role;

/// What a session may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Everything the admin's role allows.
    Full,
    /// Only replacing the password and enrolling a second factor: a new
    /// account signing in from outside the LAN before it has a factor.
    Enrollment,
}

/// A signed-in admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub admin: String,
    pub role: Role,
    pub scope: Scope,
    pub from: IpAddr,
    /// The token every change made in this session must carry.
    pub csrf: String,
    pub created: u64,
    pub last_seen: u64,
    /// When the admin last proved who they are: signing in, or entering the
    /// password again for a sensitive action.
    pub authenticated: u64,
}

/// The tokens handed out when a session is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub token: String,
    pub csrf: String,
    pub expires: u64,
}

/// Live sessions with an idle limit and an absolute limit, in seconds.
pub struct Sessions {
    by_digest: HashMap<[u8; 32], Session>,
    idle: u64,
    max: u64,
}

impl Sessions {
    pub fn new(idle: u64, max: u64) -> Sessions {
        Sessions {
            by_digest: HashMap::new(),
            idle,
            max,
        }
    }

    /// The idle limit and the absolute limit, in seconds.
    pub fn limits(&self) -> (u64, u64) {
        (self.idle, self.max)
    }

    /// Starts a session and returns its tokens.
    pub fn create(
        &mut self,
        admin: &str,
        role: Role,
        scope: Scope,
        from: IpAddr,
        now: u64,
    ) -> Result<Issued, String> {
        self.purge(now);
        let token = secret::token()?;
        let csrf = secret::token()?;
        let session = Session {
            admin: admin.to_owned(),
            role,
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
    pub fn touch(&mut self, token: &str, now: u64) -> Option<Session> {
        let key = secret::digest(token);
        let live = self
            .by_digest
            .get(&key)
            .map(|session| self.is_live(session, now))?;
        if !live {
            self.by_digest.remove(&key);
            return None;
        }
        let session = self.by_digest.get_mut(&key)?;
        session.last_seen = now;
        Some(session.clone())
    }

    /// Changes the scope of the session for `token`.
    pub fn set_scope(&mut self, token: &str, scope: Scope) -> bool {
        match self.by_digest.get_mut(&secret::digest(token)) {
            Some(session) => {
                session.scope = scope;
                true
            }
            None => false,
        }
    }

    /// Records that the admin of the session for `token` proved who they are.
    pub fn reauthenticated(&mut self, token: &str, now: u64) -> bool {
        match self.by_digest.get_mut(&secret::digest(token)) {
            Some(session) => {
                session.authenticated = now;
                true
            }
            None => false,
        }
    }

    /// Ends the session for `token`; false when there was none.
    pub fn end(&mut self, token: &str) -> bool {
        self.by_digest.remove(&secret::digest(token)).is_some()
    }

    /// Ends every session of `admin` except the one for `keep`, and returns
    /// how many ended.
    pub fn end_admin(&mut self, admin: &str, keep: Option<&str>) -> usize {
        let kept = keep.map(secret::digest);
        let before = self.by_digest.len();
        self.by_digest
            .retain(|digest, session| session.admin != admin || Some(*digest) == kept);
        before - self.by_digest.len()
    }

    /// How many live sessions `admin` has besides the one for `except`.
    pub fn others_of(&self, admin: &str, except: &str, now: u64) -> usize {
        let skipped = secret::digest(except);
        self.by_digest
            .iter()
            .filter(|(digest, session)| {
                session.admin == admin && **digest != skipped && self.is_live(session, now)
            })
            .count()
    }

    /// Where `admin`'s live sessions were signed in from.
    pub fn addresses_of(&self, admin: &str, now: u64) -> Vec<IpAddr> {
        self.by_digest
            .values()
            .filter(|session| session.admin == admin && self.is_live(session, now))
            .map(|session| session.from)
            .collect()
    }

    /// When a session ends if it stays idle.
    pub fn expires(&self, session: &Session) -> u64 {
        (session.last_seen + self.idle).min(session.created + self.max)
    }

    fn is_live(&self, session: &Session, now: u64) -> bool {
        now < self.expires(session)
    }

    fn purge(&mut self, now: u64) {
        let (idle, max) = (self.idle, self.max);
        self.by_digest
            .retain(|_digest, session| now < (session.last_seen + idle).min(session.created + max));
    }
}

/// A sign-in whose password was accepted and whose second factor is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignIn {
    pub admin: String,
    pub from: IpAddr,
    pub created: u64,
}

/// Sign-ins waiting for their second factor, each usable once, for a
/// window in seconds.
pub struct Pending {
    by_digest: HashMap<[u8; 32], PendingSignIn>,
    window: u64,
}

impl Pending {
    pub fn new(window: u64) -> Pending {
        Pending {
            by_digest: HashMap::new(),
            window,
        }
    }

    /// Records a pending sign-in and returns its token.
    pub fn create(&mut self, admin: &str, from: IpAddr, now: u64) -> Result<String, String> {
        let window = self.window;
        self.by_digest
            .retain(|_digest, pending| now < pending.created + window);
        let token = secret::token()?;
        self.by_digest.insert(
            secret::digest(&token),
            PendingSignIn {
                admin: admin.to_owned(),
                from,
                created: now,
            },
        );
        Ok(token)
    }

    /// Removes and returns the pending sign-in for `token`, if it is still
    /// inside its window.
    pub fn take(&mut self, token: &str, now: u64) -> Option<PendingSignIn> {
        let pending = self.by_digest.remove(&secret::digest(token))?;
        (now < pending.created + self.window).then_some(pending)
    }

    /// The pending sign-in for `token`, if it is still inside its window,
    /// left in place for the step that completes it.
    pub fn get(&self, token: &str, now: u64) -> Option<PendingSignIn> {
        self.by_digest
            .get(&secret::digest(token))
            .filter(|pending| now < pending.created + self.window)
            .cloned()
    }
}

/// Failed sign-ins per address: after `max` failures, each within `window`
/// seconds of the one before, the address is refused until `window` seconds
/// after its last failure.
pub struct Limiter {
    failures: HashMap<IpAddr, Failures>,
    max: u32,
    window: u64,
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    count: u32,
    last: u64,
}

impl Limiter {
    pub fn new(max: u32, window: u64) -> Limiter {
        Limiter {
            failures: HashMap::new(),
            max,
            window,
        }
    }

    /// Seconds until `from` may try again, or `None` when it may now.
    pub fn blocked(&self, from: IpAddr, now: u64) -> Option<u64> {
        let failures = self.failures.get(&from.to_canonical())?;
        let until = failures.last + self.window;
        (failures.count >= self.max && now < until).then_some(until.saturating_sub(now))
    }

    /// Counts a failed sign-in from `from`.
    pub fn failure(&mut self, from: IpAddr, now: u64) {
        let window = self.window;
        self.failures
            .retain(|_address, failures| now < failures.last + window);
        let failures = self
            .failures
            .entry(from.to_canonical())
            .or_insert(Failures {
                count: 0,
                last: now,
            });
        failures.count += 1;
        failures.last = now;
    }

    /// Forgets the failures of `from` after a successful sign-in.
    pub fn success(&mut self, from: IpAddr) {
        self.failures.remove(&from.to_canonical());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: u64 = 1800;
    const MAX: u64 = 43_200;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn sessions() -> Sessions {
        Sessions::new(IDLE, MAX)
    }

    #[test]
    fn a_session_lives_while_it_is_used() {
        let mut sessions = sessions();
        let issued = sessions
            .create("alex", Role::Owner, Scope::Full, ip("192.168.1.20"), 1000)
            .unwrap();
        assert_eq!(issued.expires, 1000 + IDLE);
        assert_eq!(
            sessions
                .touch(&issued.token, 1000 + IDLE - 1)
                .unwrap()
                .admin,
            "alex"
        );
        assert!(sessions.touch(&issued.token, 1000 + 2 * IDLE - 2).is_some());
    }

    #[test]
    fn idle_sessions_end() {
        let mut sessions = sessions();
        let issued = sessions
            .create("alex", Role::Owner, Scope::Full, ip("192.168.1.20"), 1000)
            .unwrap();
        assert!(sessions.touch(&issued.token, 1000 + IDLE).is_none());
        assert!(sessions.touch(&issued.token, 1000).is_none());
    }

    #[test]
    fn sessions_end_at_the_absolute_limit_however_busy() {
        let mut sessions = sessions();
        let issued = sessions
            .create("alex", Role::Owner, Scope::Full, ip("192.168.1.20"), 0)
            .unwrap();
        let mut now = 0;
        while now + IDLE / 2 < MAX {
            now += IDLE / 2;
            assert!(sessions.touch(&issued.token, now).is_some(), "at {now}");
        }
        assert!(sessions.touch(&issued.token, MAX).is_none());
    }

    #[test]
    fn unknown_tokens_have_no_session() {
        let mut sessions = sessions();
        assert!(sessions.touch("nope", 0).is_none());
        assert!(!sessions.end("nope"));
    }

    #[test]
    fn ending_sessions() {
        let mut sessions = sessions();
        let from = ip("192.168.1.20");
        let one = sessions
            .create("alex", Role::Owner, Scope::Full, from, 0)
            .unwrap();
        let two = sessions
            .create("alex", Role::Owner, Scope::Full, from, 0)
            .unwrap();
        let other = sessions
            .create("kai", Role::Viewer, Scope::Full, from, 0)
            .unwrap();
        assert_eq!(sessions.end_admin("alex", Some(&one.token)), 1);
        assert!(sessions.touch(&one.token, 1).is_some());
        assert!(sessions.touch(&two.token, 1).is_none());
        assert!(sessions.touch(&other.token, 1).is_some());
        assert!(sessions.end(&one.token));
        assert!(sessions.touch(&one.token, 1).is_none());
    }

    #[test]
    fn scope_and_reauthentication() {
        let mut sessions = sessions();
        let issued = sessions
            .create("alex", Role::Owner, Scope::Enrollment, ip("10.0.0.1"), 0)
            .unwrap();
        assert!(sessions.set_scope(&issued.token, Scope::Full));
        assert!(sessions.reauthenticated(&issued.token, 50));
        let session = sessions.touch(&issued.token, 60).unwrap();
        assert_eq!(session.scope, Scope::Full);
        assert_eq!(session.authenticated, 50);
        assert!(!sessions.set_scope("nope", Scope::Full));
    }

    #[test]
    fn pending_sign_ins_are_single_use_and_expire() {
        let mut pending = Pending::new(300);
        let from = ip("192.168.255.40");
        let token = pending.create("alex", from, 1000).unwrap();
        assert_eq!(pending.take(&token, 1299).unwrap().admin, "alex");
        assert!(pending.take(&token, 1299).is_none());
        let late = pending.create("alex", from, 1000).unwrap();
        assert!(pending.take(&late, 1300).is_none());
    }

    #[test]
    fn addresses_are_blocked_after_repeated_failures() {
        let mut limiter = Limiter::new(3, 900);
        let from = ip("203.0.113.9");
        for now in [0, 10, 20] {
            assert_eq!(limiter.blocked(from, now), None);
            limiter.failure(from, now);
        }
        assert_eq!(limiter.blocked(from, 21), Some(899));
        assert_eq!(limiter.blocked(ip("::ffff:203.0.113.9"), 21), Some(899));
        assert_eq!(limiter.blocked(ip("203.0.113.10"), 21), None);
        assert_eq!(limiter.blocked(from, 920), None);
    }

    #[test]
    fn spaced_out_failures_do_not_add_up() {
        let mut limiter = Limiter::new(3, 900);
        let from = ip("203.0.113.9");
        for now in [0, 1000, 2000, 3000] {
            limiter.failure(from, now);
            assert_eq!(limiter.blocked(from, now), None, "at {now}");
        }
    }

    #[test]
    fn success_clears_an_address() {
        let mut limiter = Limiter::new(2, 900);
        let from = ip("192.168.1.20");
        limiter.failure(from, 0);
        limiter.failure(from, 1);
        assert!(limiter.blocked(from, 2).is_some());
        limiter.success(from);
        assert_eq!(limiter.blocked(from, 2), None);
    }
}
