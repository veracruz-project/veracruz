from capdl import ObjectType, Cap, ARMIRQMode
from icecap_framework import GenericElfComponent
from icecap_framework.utils import align_up, align_down, PAGE_SIZE, PAGE_SIZE_BITS, BLOCK_SIZE_BITS
import itertools as it

BADGE_IRQ = 1 << 0
BADGE_TX = 1 << 1
BADGE_RX = 1 << 2

MMIO_BLOCK_SIZE = 512
NS_POOL_PADDR_start = 0xc0000000
VIRTIO_PARAMS = {
    "qemu": {
        "paddr": 0xa000000,
        "irq": 0x20 + 0x10,
        "count": 32,
        "poolsize": 32 * 4096,
    },
    "lkvm": {
        "paddr": 0x10000,
        "irq": 0x20 + 0x4,
        "count": 1,
        "poolsize": 32 * 4096,
    },
    "lkvm_realm": {
        "paddr": 0x10000,
        "irq": 0x20 + 0x4,
        "count": 1,
        "poolsize": 32 * 4096,
    }
}

class VirtioConsoleServer(GenericElfComponent):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        plat = args[0].plat
        if plat in VIRTIO_PARAMS:
            virtio = VIRTIO_PARAMS[plat]
        else:
            raise Exception("Unsupported platform '%s'" % (plat))

        virtio_region_start = align_down(virtio["paddr"], PAGE_SIZE)
        virtio_region_end = align_up(virtio["paddr"] + virtio["count"] * MMIO_BLOCK_SIZE, PAGE_SIZE)

        # first allocate vaddrs for the virtio region
        self.align(PAGE_SIZE)
        self.skip(PAGE_SIZE)
        virtio_vaddr = self.cur_vaddr
        virtio_size = virtio_region_end - virtio_region_start
        self.skip(virtio_size)

        # add some padding to catch out-of-bounds access
        self.skip(PAGE_SIZE)

        # allocate vaddrs for the virtio pool, these pages must be
        # shared with the host
        virtio_pool_vaddr = self.cur_vaddr
        self.skip(align_up(virtio["poolsize"], PAGE_SIZE))

        # more padding
        self.skip(PAGE_SIZE)

        # map in the virtio-mmio region
        # TODO do we need to do this a page at a time?
        for (vaddr, paddr) in zip(
                it.count(virtio_vaddr, PAGE_SIZE),
                range(virtio_region_start, virtio_region_end, PAGE_SIZE)):
            self.map_with_size(
                vaddr=vaddr, paddr=paddr, size=PAGE_SIZE,
                read=True, write=True)

        # allocate some pages to put at a fixed address for communication over virtio
        virtio_pool_pages = []
        if plat == "lkvm_realm":
            paddr = NS_POOL_PADDR_start
        for vaddr in range(
                virtio_pool_vaddr,
                align_up(virtio_pool_vaddr + virtio["poolsize"], PAGE_SIZE),
                PAGE_SIZE):
            # if we are inside a realm, virtio pages need to be inside the NS pool to be shared with the host
            if plat == "lkvm_realm":
                self.map_with_size(PAGE_SIZE, vaddr=vaddr, paddr=paddr, read=True, write=True, cached=True, virtio_pages=virtio_pool_pages)
                paddr += PAGE_SIZE
            elif plat == "lkvm":
                page = self.alloc(ObjectType.seL4_FrameObject,
                    name='virtio_page_{:#x}'.format(vaddr), size=4096)
                cap = self.cspace().alloc(page, read=True, write=True, cached=False)
                virtio_pool_pages.append(cap)
                self.addr_space().add_hack_page(vaddr, PAGE_SIZE,
                    Cap(page, read=True, write=True, cached=True))

        # create irq handler objects to catch all virtio IRQs
        self.event_nfn = self.alloc(ObjectType.seL4_NotificationObject, name='event_nfn')
        virtio_irq_handlers = []
        for irq in range(virtio["irq"], virtio["irq"] + virtio["count"]):
            irq_handler = self.alloc(ObjectType.seL4_IRQHandler,
                name='irq_{}_handler'.format(irq),
                number=irq, trigger=ARMIRQMode.seL4_ARM_IRQ_EDGE,
                notification=Cap(self.event_nfn, badge=BADGE_IRQ))
            cap = self.cspace().alloc(irq_handler)
            virtio_irq_handlers.append(cap)

        self._arg = {
            'virtio_region': (virtio_vaddr, virtio_vaddr + virtio_size),
            'virtio_irq_handlers': virtio_irq_handlers,
            'virtio_pool_region': (virtio_pool_vaddr,
                align_up(virtio_pool_vaddr + virtio["poolsize"], PAGE_SIZE)),
            'virtio_pool_pages': virtio_pool_pages,
            'event_nfn': self.cspace().alloc(self.event_nfn, read=True),
            'badges': {
                'irq': BADGE_IRQ,
                'tx': BADGE_TX,
                'rx': BADGE_RX,
                },
            }

    def register_client(self, client, kick_nfn, kick_tx_badge, kick_rx_badge):
        server_rb_objs, client_rb_objs = self.composition.alloc_ring_buffer(
            a_name=self.name, a_size_bits=BLOCK_SIZE_BITS,
            b_name=client.name, b_size_bits=BLOCK_SIZE_BITS,
            )
        kick_tx_cap = self.cspace().alloc(kick_nfn, badge=kick_tx_badge, write=True)
        kick_rx_cap = self.cspace().alloc(kick_nfn, badge=kick_rx_badge, write=True)
        self._arg['client_ring_buffer'] = {
            'ring_buffer': self.map_ring_buffer(server_rb_objs),
            'kicks': {
                'read': kick_tx_cap,
                'write': kick_rx_cap,
                },
            }
        return (
            client_rb_objs,
            client.cspace().alloc(self.event_nfn, badge=BADGE_TX, write=True),
            client.cspace().alloc(self.event_nfn, badge=BADGE_RX, write=True),
        )

    def arg_json(self):
        return self._arg
