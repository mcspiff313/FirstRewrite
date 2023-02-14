#![no_std]
#![no_main]

use aya_bpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};
use aya_log_ebpf::info;
use first_rewrite_common::*;

#[map(name = "PORTS")] //
static mut PORTS: HashMap<u8, u16> = HashMap::<u8, u16>::with_max_entries(2, 0);

#[cgroup_sock_addr(connect4, name = "first_rewrite")]
pub fn first_rewrite(ctx: SockAddrContext) -> i32 {
    match try_first_rewrite(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
struct IpV4Addr(u32);

impl From<u32> for IpV4Addr {
    fn from(x: u32) -> IpV4Addr {
        IpV4Addr(x)
    }
}

impl From<(u8, u8, u8, u8)> for IpV4Addr {
    fn from(abcd: (u8, u8, u8, u8)) -> IpV4Addr {
        let (a, b, c, d) = abcd;
        fn w(u: u8, n: i32) -> u32 {
            (u as u32) << (8 * n)
        }
        let u = w(a, 3) | w(b, 2) | w(c, 1) | w(d, 0);
        u.into()
    }
}

impl From<IpV4Addr> for (u8, u8, u8, u8) {
    fn from(x: IpV4Addr) -> (u8, u8, u8, u8) {
        let IpV4Addr(x) = x;
        let e = |n: i32| ((x >> (8 * n)) as u8);
        (e(3), e(2), e(1), e(0))
    }
}

fn try_first_rewrite(ctx: SockAddrContext) -> Result<i32, i32> {
    let localhost: IpV4Addr = IpV4Addr::from((127, 0, 0, 1));
    let src = unsafe { PORTS.get(&SRC) };
    let Some(src) =  src else {
        return Ok(1)
    };

    let dst = unsafe { PORTS.get(&DST) };
    let Some(dst) = dst else {
        return Ok(1)
    };

    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    let addr: u32 = u32::from_be(addr);
    let port = unsafe { (*ctx.sock_addr).user_port } as u16;
    let port = u16::from_be(port);
    let addr = IpV4Addr(addr);
    if localhost.0 == addr.0 && port == *src {
        info!(&ctx, "Rewriting socket!");
        unsafe {
            (*ctx.sock_addr).user_port = u16::to_be(*dst) as u32;
        }
    }
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
