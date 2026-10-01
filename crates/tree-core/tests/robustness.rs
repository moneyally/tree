//! Property-based robustness tests (proptest).
//!
//! Random and mutated bytes go into every entry point that takes bytes from
//! the network. The properties: no panic, never accepted, and a failed input
//! never damages state (the genuine input still works afterwards).
//!
//! Case counts are kept moderate because post-quantum crypto is slow in debug
//! builds; raise them with `PROPTEST_CASES=<n>`.

mod common;

#[allow(unused_imports)]
use common::Now;

use std::cell::RefCell;

use common::{chat_with_insider, two_person_chat, TAG_LEN};
use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, TestRunner},
};
use tree_core::{
    features::{standard_features, Caller, Feature, FeatureError, Lock, LockReason, Plan, Registry, Scope, State, Status},
    Client, Incoming,
};

fn runner(default_cases: u32) -> TestRunner {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default_cases);
    TestRunner::new(Config { cases, failure_persistence: None, ..Config::default() })
}

/// One way of damaging a byte string.
#[derive(Debug, Clone)]
enum Mutation {
    Flip { at: usize, xor: u8 },
    Truncate { keep: usize },
    Extend { tail: Vec<u8> },
    Insert { at: usize, byte: u8 },
    Delete { at: usize },
    Overwrite { at: usize, bytes: Vec<u8> },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        3 => (any::<usize>(), 1u8..=255).prop_map(|(at, xor)| Mutation::Flip { at, xor }),
        1 => any::<usize>().prop_map(|keep| Mutation::Truncate { keep }),
        1 => vec(any::<u8>(), 1..64).prop_map(|tail| Mutation::Extend { tail }),
        1 => (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Insert { at, byte }),
        1 => any::<usize>().prop_map(|at| Mutation::Delete { at }),
        1 => (any::<usize>(), vec(any::<u8>(), 1..16)).prop_map(|(at, bytes)| Mutation::Overwrite { at, bytes }),
    ]
}

/// Applies `m`; returns None if the result equals the input.
fn mutate(input: &[u8], m: &Mutation) -> Option<Vec<u8>> {
    let mut v = input.to_vec();
    let n = v.len();
    if n == 0 {
        return match m {
            Mutation::Extend { tail } => Some(tail.clone()),
            Mutation::Insert { byte, .. } => Some(vec![*byte]),
            _ => None,
        };
    }
    match m {
        Mutation::Flip { at, xor } => v[at % n] ^= xor,
        Mutation::Truncate { keep } => v.truncate(keep % n),
        Mutation::Extend { tail } => v.extend_from_slice(tail),
        Mutation::Insert { at, byte } => v.insert(at % (n + 1), *byte),
        Mutation::Delete { at } => {
            v.remove(at % n);
        }
        Mutation::Overwrite { at, bytes } => {
            let start = at % n;
            for (i, b) in bytes.iter().enumerate() {
                if start + i < n {
                    v[start + i] = *b;
                }
            }
        }
    }
    (v != input).then_some(v)
}

/// Bytes that look a little like an envelope more often than pure noise.
fn noise() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..2048),
        vec(any::<u8>(), 0..64).prop_map(|mut v| {
            v.insert(0, 1);
            v
        }),
        (vec(any::<u8>(), 0..1500)).prop_map(|body| {
            let mut v = vec![1u8];
            v.extend_from_slice(&[0u8; TAG_LEN]);
            v.extend_from_slice(&body);
            v
        }),
    ]
}

// ---------------------------------------------------------------- receive

#[test]
fn receive_random_bytes_never_accepted() {
    let (alice, bob, mut a, b) = two_person_chat();
    let genuine = a.send(&alice, b"genuine").unwrap();
    let b = RefCell::new(b);
    runner(512)
        .run(&noise(), |bytes| {
            let r = b.borrow_mut().receive(&bob, &bytes);
            prop_assert!(r.is_err(), "random input accepted: {:?}", r);
            Ok(())
        })
        .unwrap();
    let r = b.borrow_mut().receive(&bob, &genuine);
    assert!(matches!(r, Ok(Incoming::Message { .. })), "{r:?}");
}

#[test]
fn receive_mutated_message_never_accepted() {
    let (alice, bob, mut a, b) = two_person_chat();
    let genuine = a.send(&alice, b"genuine message body").unwrap();
    let b = RefCell::new(b);
    runner(512)
        .run(&vec(mutation(), 1..4), |ms| {
            let mut v = genuine.clone();
            for m in &ms {
                v = mutate(&v, m).unwrap_or(v);
            }
            if v == genuine {
                return Ok(());
            }
            let r = b.borrow_mut().receive(&bob, &v);
            prop_assert!(r.is_err(), "mutated message accepted: {:?}", r);
            Ok(())
        })
        .unwrap();
    let r = b.borrow_mut().receive(&bob, &genuine);
    assert!(matches!(r, Ok(Incoming::Message { .. })), "genuine message lost: {r:?}");
}

#[test]
fn receive_mutated_commit_never_accepted() {
    let (alice, bob, mut a, b) = two_person_chat();
    let carol = Client::new("carol").unwrap();
    let commit = a.add_now(&alice, &carol.key_package().unwrap()).unwrap().commit;
    let b = RefCell::new(b);
    runner(256)
        .run(&mutation(), |m| {
            let Some(v) = mutate(&commit, &m) else { return Ok(()) };
            let r = b.borrow_mut().receive(&bob, &v);
            prop_assert!(r.is_err(), "mutated commit accepted: {:?}", r);
            prop_assert_eq!(b.borrow().epoch(), 1);
            Ok(())
        })
        .unwrap();
    assert!(matches!(b.borrow_mut().receive(&bob, &commit), Ok(Incoming::GroupChanged { epoch: 2, .. })));
}

/// Behind the seal: a member wraps random bytes in a VALID envelope, so they
/// reach the MLS parser. Must not panic, must not be accepted.
#[test]
fn insider_sealed_random_bytes_never_accepted() {
    let (_alice, bob, _a, b, m) = chat_with_insider("mallory");
    let (b, m) = (RefCell::new(b), RefCell::new(m));
    runner(512)
        .run(&vec(any::<u8>(), 0..2048), |body| {
            let sealed = m.borrow_mut().seal(&body);
            let r = b.borrow_mut().receive(&bob, &sealed);
            prop_assert!(r.is_err(), "sealed garbage accepted: {:?}", r);
            Ok(())
        })
        .unwrap();
    let ok = m.borrow_mut().send(b"still works");
    assert!(matches!(b.borrow_mut().receive(&bob, &ok), Ok(Incoming::Message { .. })));
}

/// Behind the seal: a member mutates a genuine MLS message and re-seals it.
#[test]
fn insider_sealed_mutated_mls_never_accepted() {
    let (_alice, bob, _a, b, m) = chat_with_insider("mallory");
    let (b, m) = (RefCell::new(b), RefCell::new(m));
    runner(256)
        .run(&vec(mutation(), 1..3), |ms| {
            let raw = m.borrow_mut().raw_message(b"insider text");
            let mut v = raw.clone();
            for x in &ms {
                v = mutate(&v, x).unwrap_or(v);
            }
            if v == raw {
                return Ok(());
            }
            let sealed = m.borrow_mut().seal(&v);
            let r = b.borrow_mut().receive(&bob, &sealed);
            prop_assert!(r.is_err(), "mutated MLS accepted: {:?}", r);
            Ok(())
        })
        .unwrap();
    let ok = m.borrow_mut().send(b"after fuzzing");
    assert!(matches!(b.borrow_mut().receive(&bob, &ok), Ok(Incoming::Message { .. })));
}

// ---------------------------------------------------------------- join

#[test]
fn join_random_bytes_never_accepted() {
    let bob = Client::new("bob").unwrap();
    let _kp = bob.key_package().unwrap();
    runner(512)
        .run(&vec(any::<u8>(), 0..4096), |bytes| {
            prop_assert!(bob.join(&bytes).is_err());
            Ok(())
        })
        .unwrap();
}

/// Mutated welcomes are refused, and (F-006 regression) do not destroy the
/// key package: the genuine welcome still works afterwards.
#[test]
fn join_mutated_welcome_never_accepted() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let mut a = alice.create_group().unwrap();
    let welcome = a.add_now(&alice, &bob.key_package().unwrap()).unwrap().welcome;
    runner(256)
        .run(&vec(mutation(), 1..3), |ms| {
            let mut v = welcome.clone();
            for x in &ms {
                v = mutate(&v, x).unwrap_or(v);
            }
            if v == welcome {
                return Ok(());
            }
            let r = bob.join(&v);
            prop_assert!(r.is_err(), "mutated welcome accepted");
            Ok(())
        })
        .unwrap();
    let mut b = bob.join(&welcome).expect("genuine welcome refused after mutated copies");
    let m = a.send(&alice, b"welcome").unwrap();
    assert!(matches!(b.receive(&bob, &m), Ok(Incoming::Message { .. })));
}

// ---------------------------------------------------------------- add

#[test]
fn add_random_or_mutated_key_package_never_accepted() {
    let alice = Client::new("alice").unwrap();
    let bob = Client::new("bob").unwrap();
    let kp = bob.key_package().unwrap();
    let a = RefCell::new(alice.create_group().unwrap());
    let input = prop_oneof![
        vec(any::<u8>(), 0..3000).prop_map(Some),
        vec(mutation(), 1..3).prop_map(|ms| {
            let mut v = kp.clone();
            for x in &ms {
                v = mutate(&v, x).unwrap_or(v);
            }
            (v != kp).then_some(v)
        }),
    ];
    runner(256)
        .run(&input, |bytes| {
            let Some(bytes) = bytes else { return Ok(()) };
            let r = a.borrow_mut().add_now(&alice, &bytes);
            prop_assert!(r.is_err(), "bad key package accepted");
            let g = a.borrow();
            prop_assert_eq!(g.epoch(), 0);
            prop_assert_eq!(common::names(&g), vec!["alice".to_string()]);
            Ok(())
        })
        .unwrap();
    a.borrow_mut().add_now(&alice, &kp).expect("genuine key package refused");
    assert_eq!(common::names(&a.borrow()), vec!["alice", "bob"]);
}

// ---------------------------------------------------------------- features

#[derive(Debug, Clone)]
enum Op {
    Apply { key: usize, option: Option<u8>, who: usize },
    Release { key: usize, who: usize },
    ServerFlag { key: usize, applied: bool },
}

const CALLERS: [Caller; 4] = [
    Caller { plan: Plan::Free, is_admin: false },
    Caller { plan: Plan::Free, is_admin: true },
    Caller { plan: Plan::Pro, is_admin: false },
    Caller { plan: Plan::Pro, is_admin: true },
];

fn all_features() -> Vec<Feature> {
    let mut v = standard_features();
    v.push(Feature { key: "user.pro_x", scope: Scope::User, default: State::Released, lock: Lock::None, plan: Plan::Pro, stage: 2 });
    v.push(Feature { key: "chat.pro_y", scope: Scope::Chat, default: State::Applied, lock: Lock::None, plan: Plan::Pro, stage: 2 });
    v
}

/// Independent model of the documented rules.
struct Model {
    defs: Vec<Feature>,
    state: std::collections::BTreeMap<(Scope, &'static str), (State, Option<String>)>,
}

impl Model {
    fn status(&self, f: &Feature) -> Status {
        match f.lock {
            Lock::AlwaysOn(r) => return Status { key: f.key, state: State::Applied, option: None, locked_by: Some(LockReason::Always(r)) },
            Lock::AlwaysOff(r) => return Status { key: f.key, state: State::Released, option: None, locked_by: Some(LockReason::Always(r)) },
            Lock::None => {}
        }
        let (state, option) = self.state.get(&(f.scope, f.key)).cloned().unwrap_or((f.default, None));
        if self.server_locked(f) {
            Status { key: f.key, state: State::Released, option, locked_by: Some(LockReason::Server) }
        } else {
            Status { key: f.key, state, option, locked_by: None }
        }
    }
    fn server_locked(&self, f: &Feature) -> bool {
        f.scope != Scope::Server && matches!(self.state.get(&(Scope::Server, f.key)), Some((State::Released, _)))
    }
    fn change(&mut self, f: &Feature, apply: bool, option: Option<String>, who: Caller) -> Result<Status, FeatureError> {
        match (apply, f.lock) {
            (true, Lock::AlwaysOff(r)) => return Err(FeatureError::ReleasedAlways(r)),
            (false, Lock::AlwaysOn(r)) => return Err(FeatureError::LockedAlways(r)),
            _ => {}
        }
        if matches!(f.scope, Scope::Chat | Scope::Server) && !who.is_admin {
            return Err(FeatureError::NotAdmin);
        }
        if self.server_locked(f) {
            return Err(FeatureError::LockedByServer);
        }
        if apply && f.plan == Plan::Pro && who.plan != Plan::Pro {
            return Err(FeatureError::PlanRequired);
        }
        if f.lock == Lock::None {
            let v = if apply { (State::Applied, option) } else { (State::Released, None) };
            self.state.insert((f.scope, f.key), v);
        }
        Ok(self.status(f))
    }
}

fn op(n_keys: usize) -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..n_keys, proptest::option::of(any::<u8>()), 0..4usize)
            .prop_map(|(key, option, who)| Op::Apply { key, option, who }),
        4 => (0..n_keys, 0..4usize).prop_map(|(key, who)| Op::Release { key, who }),
        1 => (0..n_keys, any::<bool>()).prop_map(|(key, applied)| Op::ServerFlag { key, applied }),
    ]
}

#[test]
fn feature_registry_random_sequences() {
    let defs = all_features();
    let n = defs.len();
    runner(512)
        .run(&vec(op(n), 1..60), |ops| {
            let mut r = Registry::standard();
            for f in &defs[n - 2..] {
                r.define(f.clone()).unwrap();
            }
            let mut model = Model { defs: defs.clone(), state: Default::default() };
            for o in &ops {
                let snapshot: Vec<Status> = model.defs.iter().map(|f| r.status(f.key).unwrap()).collect();
                let (got, want, touched) = match *o {
                    Op::Apply { key, option, who } => {
                        let f = &model.defs[key].clone();
                        let opt = option.map(|b| b.to_string());
                        let got = r.apply(f.key, opt.clone(), CALLERS[who]);
                        let want = model.change(f, true, opt.clone(), CALLERS[who]);
                        // Idempotency: the same call again gives the same answer.
                        prop_assert_eq!(&r.apply(f.key, opt.clone(), CALLERS[who]), &got);
                        (Some(got), Some(want), f.key)
                    }
                    Op::Release { key, who } => {
                        let f = &model.defs[key].clone();
                        let got = r.release(f.key, CALLERS[who]);
                        let want = model.change(f, false, None, CALLERS[who]);
                        prop_assert_eq!(&r.release(f.key, CALLERS[who]), &got);
                        (Some(got), Some(want), f.key)
                    }
                    Op::ServerFlag { key, applied } => {
                        let k = model.defs[key].key;
                        let st = if applied { State::Applied } else { State::Released };
                        r.set_server_flag(k, st);
                        model.state.insert((Scope::Server, k), (st, None));
                        (None, None, k)
                    }
                };
                prop_assert_eq!(&got, &want, "op {:?}", o);
                if let Some(Ok(s)) = &got {
                    prop_assert_eq!(s, &r.status(s.key).unwrap());
                }
                for (f, before) in model.defs.iter().zip(&snapshot) {
                    let now = r.status(f.key).unwrap();
                    prop_assert_eq!(&now, &model.status(f), "{} after {:?}", f.key, o);
                    // Invariants that must hold whatever the model says.
                    match f.lock {
                        Lock::AlwaysOn(_) => prop_assert_eq!(now.state, State::Applied),
                        Lock::AlwaysOff(_) => prop_assert_eq!(now.state, State::Released),
                        Lock::None => {}
                    }
                    // A failed call changes nothing; a call on another key
                    // changes nothing here.
                    let failed = matches!(got, Some(Err(_)));
                    if failed || f.key != touched {
                        prop_assert_eq!(&now, before, "{} changed by {:?}", f.key, o);
                    }
                    // Non-admins never change Chat/Server features.
                    if let Op::Apply { who, .. } | Op::Release { who, .. } = *o {
                        if !CALLERS[who].is_admin && matches!(f.scope, Scope::Chat | Scope::Server) {
                            prop_assert_eq!(&now, before);
                        }
                    }
                }
            }
            Ok(())
        })
        .unwrap();
}
