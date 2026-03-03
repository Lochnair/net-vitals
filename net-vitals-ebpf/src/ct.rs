//! Conntrack (nf_conntrack) type definitions for eBPF kfuncs.
//!
//! These structs mirror kernel types. Their layout depends on kernel version,
//! config, and architecture. The definitions below assume:
//!   - aarch64
//!   - CONFIG_NF_CONNTRACK_ZONES=y
//!   - CONFIG_NF_NAT=y
//!   - CONFIG_NF_CONNTRACK_MARK=y
//!   - CONFIG_NET_NS=y
//!   - No lock debugging (LOCKDEP/LOCK_STAT off)

use core::ffi::c_void;

use aya_ebpf::bindings::{__sk_buff, bpf_sock_tuple};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const IP_CT_DIR_ORIGINAL: usize = 0;
pub const IP_CT_DIR_REPLY: usize = 1;
pub const IP_CT_DIR_MAX: usize = 2;

/// Connection status bits (from `linux/netfilter/nf_conntrack_common.h`)
pub const IPS_EXPECTED: u64 = 1 << 0;
pub const IPS_SEEN_REPLY: u64 = 1 << 1;
pub const IPS_ASSURED: u64 = 1 << 2;
pub const IPS_CONFIRMED: u64 = 1 << 3;
pub const IPS_SRC_NAT: u64 = 1 << 4;
pub const IPS_DST_NAT: u64 = 1 << 5;
pub const IPS_NAT_MASK: u64 = IPS_DST_NAT | IPS_SRC_NAT;

// ---------------------------------------------------------------------------
// Conntrack tuple types
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub union nf_inet_addr {
    pub all: [u32; 4],
    pub ip: u32,
    pub ip6: [u32; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union nf_conntrack_man_proto {
    /// Covers tcp.port, udp.port, icmp.id, dccp.port, sctp.port, gre.key
    pub all: u16,
}

/// Source half of a conntrack tuple.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct nf_conntrack_man {
    pub u3: nf_inet_addr,
    pub u: nf_conntrack_man_proto,
    pub l3num: u16,
}

/// Destination half of a conntrack tuple.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct nf_conntrack_tuple_dst {
    pub u3: nf_inet_addr,
    pub u: nf_conntrack_man_proto,
    pub protonum: u8,
    pub dir: u8,
}

/// Full conntrack 5-tuple (src + dst).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct nf_conntrack_tuple {
    pub src: nf_conntrack_man,
    pub dst: nf_conntrack_tuple_dst,
}

// ---------------------------------------------------------------------------
// Kernel linked-list node types
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct hlist_nulls_node {
    pub next: *mut hlist_nulls_node,
    pub pprev: *mut *mut hlist_nulls_node,
}

#[repr(C)]
pub struct hlist_node {
    pub next: *mut hlist_node,
    pub pprev: *mut *mut hlist_node,
}

// ---------------------------------------------------------------------------
// nf_conntrack_tuple_hash  (what tuplehash[] elements are)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct nf_conntrack_tuple_hash {
    pub hnnode: hlist_nulls_node,
    pub tuple: nf_conntrack_tuple,
}

// ---------------------------------------------------------------------------
// Small kernel helpers
// ---------------------------------------------------------------------------

/// `struct nf_conntrack` — just a refcount.
#[repr(C)]
pub struct nf_conntrack {
    pub use_: i32, // atomic_t
}

/// `struct nf_conntrack_zone` (CONFIG_NF_CONNTRACK_ZONES=y)
#[repr(C)]
pub struct nf_conntrack_zone {
    pub id: u16,
    pub flags: u8,
    pub dir: u8,
}

// ---------------------------------------------------------------------------
// nf_conn — the main conntrack entry
// ---------------------------------------------------------------------------

/// Kernel `struct nf_conn`.
///
/// **Layout is kernel-config dependent!**  See module-level docs for the
/// assumed config.  If your kernel differs (e.g. no ZONES, no NAT, or
/// SECMARK enabled) you will need to adjust the fields below.
#[repr(C)]
pub struct nf_conn {
    pub ct_general: nf_conntrack,

    /// `spinlock_t` — 4 bytes on aarch64 without lock debugging.
    pub lock: u32,

    /// jiffies32 when this ct is considered dead.
    pub timeout: u32,

    /// CONFIG_NF_CONNTRACK_ZONES
    pub zone: nf_conntrack_zone,

    /// Original (index 0) and reply (index 1) tuple hashes.
    pub tuplehash: [nf_conntrack_tuple_hash; IP_CT_DIR_MAX],

    /// Bitset — see `IPS_*` constants.
    pub status: u64, // unsigned long

    /// `possible_net_t` with CONFIG_NET_NS=y (wraps `struct net *`).
    pub ct_net: *mut c_void,

    /// CONFIG_NF_NAT — `struct hlist_node nat_bysource`
    pub nat_bysource: hlist_node,

    /* --- everything below is memset to 0 on alloc (__nfct_init_offset) --- */
    pub master: *mut nf_conn,

    /// CONFIG_NF_CONNTRACK_MARK
    pub mark: u32,

    // CONFIG_NF_CONNTRACK_SECMARK — uncomment if your kernel has it:
    // pub secmark: u32,
    pub ext: *mut c_void, // struct nf_ct_ext *

                          // `union nf_conntrack_proto proto` lives at the tail — variable size,
                          // omitted here.
}

// ---------------------------------------------------------------------------
// bpf_ct_opts — passed to ct kfuncs
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct bpf_ct_opts {
    pub netns_id: i32,
    pub error: i32,
    pub l4proto: u8,
    pub dir: u8,
    pub ct_zone_id: u16,
    pub ct_zone_dir: u8,
    pub reserved: [u8; 3],
}

// ---------------------------------------------------------------------------
// kfunc declarations
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// Look up a conntrack entry for the given tuple.  Acquires a reference
    /// that **must** be released with [`bpf_ct_release`].
    ///
    /// Returns a pointer to `nf_conn` on success, or null if not found.
    pub fn bpf_skb_ct_lookup(
        skb_ctx: *mut __sk_buff,
        bpf_tuple: *mut bpf_sock_tuple,
        tuple__sz: u32,
        opts: *mut bpf_ct_opts,
        opts__sz: u32,
    ) -> *mut nf_conn;

    /// Release a conntrack reference obtained from `bpf_skb_ct_lookup`
    /// (or similar).
    pub fn bpf_ct_release(nf_conn: *mut nf_conn);
}
