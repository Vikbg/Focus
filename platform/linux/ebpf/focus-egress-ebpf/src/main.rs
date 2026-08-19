#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

const AF_INET: u32 = 2;
const IPV4_MIN_HEADER_LENGTH: usize = 20;
const IPV4_MAX_HEADER_LENGTH: usize = 60;
const IPV4_PROTOCOL_OFFSET: usize = 9;
const IPV4_DESTINATION_OFFSET: usize = 16;
const DESTINATION_PORT_OFFSET: usize = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[map]
static ALLOWED_IPV4_ENDPOINTS: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

#[cgroup_skb(egress)]
pub fn focus_egress(ctx: SkBuffContext) -> i32 {
    evaluate_egress(&ctx).unwrap_or(0)
}

fn evaluate_egress(ctx: &SkBuffContext) -> Result<i32, ()> {
    if ctx.skb.family() != AF_INET {
        return Ok(0);
    }

    let version_ihl = ctx.load::<u8>(0).map_err(|_| ())?;
    if version_ihl >> 4 != 4 {
        return Ok(0);
    }

    let header_length = usize::from(version_ihl & 0x0f) * 4;
    if !(IPV4_MIN_HEADER_LENGTH..=IPV4_MAX_HEADER_LENGTH).contains(&header_length) {
        return Ok(0);
    }

    let protocol = ctx
        .load::<u8>(IPV4_PROTOCOL_OFFSET)
        .map_err(|_| ())?;
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(0);
    }

    let destination = u32::from_be(
        ctx.load::<u32>(IPV4_DESTINATION_OFFSET)
            .map_err(|_| ())?,
    );
    let destination_port = u16::from_be(
        ctx.load::<u16>(header_length + DESTINATION_PORT_OFFSET)
            .map_err(|_| ())?,
    );
    if destination_port == 0 {
        return Ok(0);
    }

    let key = (u64::from(destination) << 32)
        | (u64::from(destination_port) << 16)
        | u64::from(protocol);

    Ok(unsafe {
        ALLOWED_IPV4_ENDPOINTS
            .get(&key)
            .map(|_| 1)
            .unwrap_or(0)
    })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
