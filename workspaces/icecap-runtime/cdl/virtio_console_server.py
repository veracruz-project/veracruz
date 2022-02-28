from capdl import ObjectType, Cap, ARMIRQMode
from icecap_framework import GenericElfComponent
from icecap_framework.utils import align_up, align_down, PAGE_SIZE, PAGE_SIZE_BITS
import itertools as it

BADGE_IRQ = 1 << 0
BADGE_CLIENT = 1 << 1

VIRTIO_PADDR = 0xa000000
VIRTIO_IRQ = 0x20 + 0x10
VIRTIO_COUNT = 32
VIRTIO_POOL_SIZE = 32*4096
VIRTIO_REGION = (VIRTIO_PADDR, VIRTIO_PADDR + VIRTIO_COUNT*512)


class VirtioConsoleServer(GenericElfComponent):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # first allocate vaddrs for the virtio region
        self.align(PAGE_SIZE)
        self.skip(PAGE_SIZE)
        virtio_vaddr = self.cur_vaddr
        virtio_size = (align_up(VIRTIO_REGION[1], PAGE_SIZE)
            - align_down(VIRTIO_REGION[0], PAGE_SIZE))
        self.skip(virtio_size)

        # add some padding to catch out-of-bounds access
        self.skip(PAGE_SIZE)

        # allocate vaddrs for the virtio pool, these pages must be
        # shared with the host
        virtio_pool_vaddr = self.cur_vaddr
        self.skip(align_up(VIRTIO_POOL_SIZE, PAGE_SIZE))

        # more padding
        self.skip(PAGE_SIZE)

        # map in the virtio-mmio region
        # TODO do we need to do this a page at a time?
        for (vaddr, paddr) in zip(
                it.count(virtio_vaddr, PAGE_SIZE),
                range(
                    align_down(VIRTIO_REGION[0], PAGE_SIZE),
                    align_up(VIRTIO_REGION[1], PAGE_SIZE),
                    PAGE_SIZE)):
            self.map_with_size(
                vaddr=vaddr, paddr=paddr, size=PAGE_SIZE,
                read=True, write=True)

        # allocate some pages to put at a fixed address for communication over virtio
        virtio_pool_pages = []
        for vaddr in range(
                virtio_pool_vaddr,
                align_up(virtio_pool_vaddr + VIRTIO_POOL_SIZE, PAGE_SIZE),
                PAGE_SIZE):
            page = self.alloc(ObjectType.seL4_FrameObject,
                name='virtio_page_{:#x}'.format(vaddr), size=4096)
            cap = self.cspace().alloc(page, read=True, write=True, cached=False)
            virtio_pool_pages.append(cap)
            self.addr_space().add_hack_page(vaddr, PAGE_SIZE,
                Cap(page, read=True, write=True, cached=False))

        # create irq handler objects to catch all virtio IRQs
        self.event_nfn = self.alloc(ObjectType.seL4_NotificationObject, name='event_nfn')
        virtio_irq_handlers = []
        for irq in range(VIRTIO_IRQ, VIRTIO_IRQ + VIRTIO_COUNT):
            irq_handler = self.alloc(ObjectType.seL4_IRQHandler,
                name='irq_{}_handler'.format(irq),
                number=irq, trigger=ARMIRQMode.seL4_ARM_IRQ_LEVEL,
                notification=Cap(self.event_nfn, badge=BADGE_IRQ))
            cap = self.cspace().alloc(irq_handler)
            virtio_irq_handlers.append(cap)

        self._arg = {
            'virtio_region': (virtio_vaddr, virtio_vaddr + virtio_size),
            'virtio_irq_handlers': virtio_irq_handlers,
            'virtio_pool_region': (virtio_pool_vaddr,
                align_up(virtio_pool_vaddr + VIRTIO_POOL_SIZE, PAGE_SIZE)),
            'virtio_pool_pages': virtio_pool_pages,
            'event_nfn': self.cspace().alloc(self.event_nfn, read=True),
            'badges': {
                'irq': BADGE_IRQ,
                'client': BADGE_CLIENT,
                },
            }

    def register_client(self, client, kick_nfn, kick_nfn_badge):
        server_rb_objs, client_rb_objs = self.composition.alloc_ring_buffer(
            a_name=self.name, a_size_bits=PAGE_SIZE_BITS,
            b_name=client.name, b_size_bits=PAGE_SIZE_BITS,
            )
        kick_cap = self.cspace().alloc(kick_nfn, badge=kick_nfn_badge, write=True)
        self._arg['client_ring_buffer'] = {
            'ring_buffer': self.map_ring_buffer(server_rb_objs),
            'kicks': {
                'read': kick_cap,
                'write': kick_cap,
                },
            }
        return client_rb_objs, client.cspace().alloc(self.event_nfn, badge=BADGE_CLIENT, write=True)

    def arg_json(self):
        return self._arg
