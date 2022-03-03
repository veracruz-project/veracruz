#![no_std]
#![no_main]

extern crate alloc;
use alloc::format;

use core::ops::Range;

use serde::{Deserialize, Serialize};

use icecap_start_generic::declare_generic_main;
use icecap_core::config::*;
use icecap_core::prelude::*;
use icecap_core::ring_buffer::{BufferedRingBuffer, RingBuffer};

use virtio_drivers::VirtIOConsole;
use virtio_drivers::VirtIOHeader;
use virtio_drivers::DeviceType;

declare_generic_main!(main);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    virtio_region: Range<usize>,
    virtio_irq_handlers: Vec<IRQHandler>,
    virtio_pool_region: Range<usize>,
    virtio_pool_pages: Vec<SmallPage>,

    event_nfn: Notification,
    client_ring_buffer: UnmanagedRingBufferConfig,
    badges: Badges,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Badges {
    irq: Badge,
    client: Badge,
}



// Pool to manage pages which are accessible by both the guest and the host
struct VirtioPool {
    pool: &'static mut [u8],
    paddr: usize,
    mark: usize,
}

impl VirtioPool {
    fn new(vaddr: usize, paddr: usize, len: usize) -> VirtioPool {
        VirtioPool {
            pool: unsafe {
                core::slice::from_raw_parts_mut(vaddr as *mut u8, len)
            },
            paddr: paddr,
            mark: 0,
        }
    }

    fn alloc<'a>(&'a mut self, size: usize) -> Fallible<&'a mut [u8]> {
        let count = (size+virtio_drivers::PAGE_SIZE-1) / virtio_drivers::PAGE_SIZE;
        let ppages = unsafe { virtio_dma_alloc(count) };
        if ppages == 0 {
            bail!("virtio_pool: out of pages");
        }

        Ok(unsafe {
            core::slice::from_raw_parts_mut(
                virtio_phys_to_virt(ppages) as *mut u8,
                count * virtio_drivers::PAGE_SIZE,
            )
        })
    }

    #[allow(unused)]
    fn dealloc(&mut self, pages: &mut [u8]) {
        unsafe {
            virtio_dma_dealloc(
                virtio_virt_to_phys(pages.as_ptr() as usize),
                pages.len() / virtio_drivers::PAGE_SIZE
            )
        };
    }
}

static mut VIRTIO_POOL: Option<VirtioPool> = None;

// virtio pool page mappings for virtio-drivers
#[no_mangle]
pub unsafe extern "C" fn virtio_dma_alloc(pages: usize) -> usize {
    debug_println!("virtio_pool: allocating {}x{} pages", pages, virtio_drivers::PAGE_SIZE);
    let pool = VIRTIO_POOL.as_mut().unwrap();
    if pool.mark + pages*virtio_drivers::PAGE_SIZE > pool.pool.len() {
        debug_println!("virtio_pool: out of pages ({}/{})!",
            pool.pool.len() / virtio_drivers::PAGE_SIZE,
            pool.pool.len() / virtio_drivers::PAGE_SIZE
        );
        return 0;
    }

    let old_mark = pool.mark;
    pool.mark += pages*virtio_drivers::PAGE_SIZE;
    let p = &mut pool.pool[old_mark] as *mut _ as usize;
    debug_println!("virtio_pool: allocating {}x{} pages -> {:012x}", pages, virtio_drivers::PAGE_SIZE, virtio_virt_to_phys(p as usize));
    virtio_virt_to_phys(p as usize)
}

#[no_mangle]
pub unsafe extern "C" fn virtio_dma_dealloc(paddr: usize, _pages: usize) -> i32 {
    debug_println!("virtio_pool: deallocating {:012x}", paddr);
    let pool = VIRTIO_POOL.as_mut().unwrap();
    debug_assert!(pool.pool.as_ptr_range().contains(&(virtio_phys_to_virt(paddr) as *const u8)));
    0
}

#[no_mangle]
pub unsafe extern "C" fn virtio_phys_to_virt(paddr: usize) -> usize {
    let pool = VIRTIO_POOL.as_mut().unwrap();
    debug_assert!(paddr >= pool.paddr && paddr < pool.paddr + pool.pool.len(),
        "virtio_pool: invalid paddr {:012x}", paddr);
    paddr - pool.paddr + (pool.pool.as_ptr() as usize)
}

#[no_mangle]
pub unsafe extern "C" fn virtio_virt_to_phys(vaddr: usize) -> usize {
    let pool = VIRTIO_POOL.as_mut().unwrap();
    debug_assert!(vaddr >= pool.pool.as_ptr() as usize && vaddr < pool.pool.as_ptr() as usize + pool.pool.len(),
        "virtio_pool: invalid vaddr {:012x}", vaddr);
    vaddr - (pool.pool.as_ptr() as usize) + pool.paddr
}


// entry point
fn main(config: Config) -> Fallible<()> {
    debug_println!("hello from virtio-console-server");

    // is the virtio region mapped correctly?
    for (i, v) in config.virtio_region.clone().step_by(512).enumerate() {
        debug_println!("virtio{}@{:012x}: {:08x} {:08x} {:08x} {:08x}",
            i,
            v,
            unsafe { core::ptr::read_volatile((v+ 0) as *const u32) },
            unsafe { core::ptr::read_volatile((v+ 4) as *const u32) },
            unsafe { core::ptr::read_volatile((v+ 8) as *const u32) },
            unsafe { core::ptr::read_volatile((v+12) as *const u32) },
        );
    }

    // is the virtio pool allocated correctly?
    for (_, (addr, page)) in
        config.virtio_pool_region.clone().step_by(4096)
            .zip(&config.virtio_pool_pages)
            .enumerate()
    {
        debug_println!("virtio_pool@{:012x} = {:012x}", addr, page.paddr().unwrap_or(0));
    }

    // setup the virtio pool
    unsafe {
        VIRTIO_POOL = Some(VirtioPool::new(
            config.virtio_pool_region.start,
            config.virtio_pool_pages[0].paddr()?,
            config.virtio_pool_region.end - config.virtio_pool_region.start,
        ));
    }

    // find a virtio driver that reports as a console device
    let (virtio_i, virtio_mmio, virtio_irq_handler) = match
        config.virtio_region.clone()
            .step_by(512)
            .zip(&config.virtio_irq_handlers)
            .enumerate()
            .find(|(_, (mmio, _))| {
                let id = unsafe { core::ptr::read_volatile((mmio+8) as *const u32) };
                id == DeviceType::Console as u32
            })
    {
        Some((i, (mmio, irq_handler))) => (i, mmio, irq_handler),
        None => {
            bail!("virtio-console-server: could not find a virtio-console");
        }
    };

    debug_println!("found virtio-console at virtio{}@{:012x}", virtio_i, virtio_mmio);
    debug_println!("virtio{}@{:012x}: initializing...", virtio_i, virtio_mmio);
    let header = unsafe { &mut *(virtio_mmio as *mut VirtIOHeader) };
    let mut console = VirtIOConsole::new(header)?;

    // we start off with all irqs registered, but we only need to listen to one,
    // disable the others
    for irq_handler in config.virtio_irq_handlers.iter() {
        if irq_handler.raw() != virtio_irq_handler.raw() {
            irq_handler.clear()?;
        }
    }

    //debug_println!("virtio{}@{:012x}: sending...", virtio_i, virtio_mmio);
    // we need to send over a frame, allocate one from the pool
    let send_page = unsafe { VIRTIO_POOL.as_mut() }.unwrap().alloc(virtio_drivers::PAGE_SIZE)?;
    //let formatted = format!("\nhello from virtio-console-server over virtio{}@{:012x}!\n\n", virtio_i, virtio_mmio);
    //send_page[..formatted.as_bytes().len()].copy_from_slice(&formatted.as_bytes());
    //console.send_slice(&send_page[..formatted.as_bytes().len()])?;

    // begin processing requests
    let mut rb = BufferedRingBuffer::new(RingBuffer::unmanaged_from_config(
        &config.client_ring_buffer,
    ));

    debug_println!("virtio{}@{:012x}: processing requests...", virtio_i, virtio_mmio);

    // we may have already recieved data to send, but lost the notification
    // during initialization, so there may already be data in our ring buffer
    // we need to write out
    rb.rx_callback();
    rb.tx_callback();
    if let Some(chars) = rb.rx() {
        for chunk in chars.chunks(virtio_drivers::PAGE_SIZE) {
            send_page[..chunk.len()].copy_from_slice(chunk);
            console.send_slice(&send_page[..chunk.len()])?;
        }
    }
    rb.ring_buffer().enable_notify_read();
    rb.ring_buffer().enable_notify_write();

    loop {
        let badge = config.event_nfn.wait();

        if badge & config.badges.irq != 0 {
            loop {
                console.ack_interrupt()?;
                let mut buffer = [0; 512];
                let recved = console.recv_slice(&mut buffer)?;
                if recved == 0 {
                    break;
                }
                rb.tx(&buffer[..recved]);
            }

            virtio_irq_handler.ack()?;
        }

        if badge & config.badges.client != 0 {
            rb.rx_callback();
            rb.tx_callback();
            if let Some(chars) = rb.rx() {
                for chunk in chars.chunks(virtio_drivers::PAGE_SIZE) {
                    send_page[..chunk.len()].copy_from_slice(chunk);
                    console.send_slice(&send_page[..chunk.len()])?;
                }
            }
            rb.ring_buffer().enable_notify_read();
            rb.ring_buffer().enable_notify_write();
        }
    }
}
