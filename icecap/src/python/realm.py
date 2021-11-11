# CapDL specification creation script for the Veracruz IceCap realm.
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

from capdl import ObjectType, Cap
from icedl.common import GenericElfComponent, DEFAULT_PRIO
from icedl.realm import BaseRealmComposition
from icedl.utils import PAGE_SIZE_BITS, BLOCK_SIZE_BITS, BLOCK_SIZE, block_at

REQUEST_BADGE = 1
FAULT_BADGE = 2

MMAP_BASE = block_at(0x10, 0, 0) << BLOCK_SIZE_BITS

class RuntimeManager(GenericElfComponent):

    def __init__(self, *args, runtime_manager_supervisor=None, **kwargs):
        super().__init__(*args, **kwargs, fault_handler=runtime_manager_supervisor)

        node_index = 0

        event = self.composition.extern(
            ObjectType.seL4_NotificationObject,
            'realm_{}_nfn_for_core_{}'.format(self.composition.realm_id(), node_index),
            )

        event_server_endpoint = self.composition.extern(
            ObjectType.seL4_EndpointObject,
            'realm_{}_event_server_client_endpoint_{}'.format(self.composition.realm_id(), self.composition.virt_to_phys_node_map(node_index)),
            )

        event_server_bitfield = self.composition.extern(
            ObjectType.seL4_FrameObject,
            'realm_{}_event_bitfield_for_core_{}'.format(self.composition.realm_id(), node_index),
            )

        channel = self.composition.extern_ring_buffer('realm_{}_channel_ring_buffer'.format(self.composition.realm_id()), size=BLOCK_SIZE)

        self._arg = {
            'event': self.cspace().alloc(event, read=True),
            'event_server_endpoint': self.cspace().alloc(event_server_endpoint, write=True, grantreply=True),
            'event_server_bitfield': self.map_region([(event_server_bitfield, PAGE_SIZE_BITS)], read=True, write=True),
            'channel': self.map_ring_buffer(channel),
            'supervisor_ep': self.cspace().alloc(runtime_manager_supervisor.ep, write=True, grantreply=True, badge=REQUEST_BADGE),
            }

    def arg_json(self):
        return self._arg

class RuntimeManagerSupervisor(GenericElfComponent):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.ep = self.alloc(ObjectType.seL4_EndpointObject, name='ep')
        self.runtime_manager_tcb = None

        self.hack_large_pages = []

        self._arg = {
            'ep': self.cspace().alloc(self.ep, read=True),
            'request_badge': REQUEST_BADGE,
            'fault_badge': FAULT_BADGE,
            'mmap_base': MMAP_BASE,
            'pool': {
                'large_pages': [
                    self.cspace().alloc(
                        self.alloc(ObjectType.seL4_FrameObject, name='block_{}'.format(i), size=BLOCK_SIZE),
                        read=True, write=True,
                        )
                    for i in range(64)
                    ],
                'hack_large_pages': self.hack_large_pages,
                }
            }

    # as fault_handler
    def handle(self, thread):
        assert self.runtime_manager_tcb is None
        self.runtime_manager_tcb = thread.tcb
        self._arg['runtime_manager_tcb'] = self.cspace().alloc(self.runtime_manager_tcb, read=True, write=True)
        thread.component.cspace().alloc(self.ep, badge=FAULT_BADGE, write=True, grant=True)

    def after(self, runtime_manager):
        self._arg['runtime_manager_pgd'] = self.cspace().alloc(runtime_manager.pd(), write=True)

        for i in range(4):
            large_frame_addr = MMAP_BASE + 512 * i * BLOCK_SIZE
            large_frame_obj = self.alloc(ObjectType.seL4_FrameObject, name='dummy_large_frame_{}'.format(i), size=BLOCK_SIZE)
            large_frame = self.cspace().alloc(large_frame_obj)
            runtime_manager.addr_space().add_hack_page(large_frame_addr, BLOCK_SIZE, Cap(large_frame_obj, read=True, write=True))
            self.hack_large_pages.append(large_frame)

    def arg_json(self):
        return self._arg

class Composition(BaseRealmComposition):

    def compose(self):
        runtime_manager_supervisor = self.component(RuntimeManagerSupervisor, 'runtime_manager_supervisor', prio=DEFAULT_PRIO + 1)
        runtime_manager = self.component(RuntimeManager, 'runtime_manager', runtime_manager_supervisor=runtime_manager_supervisor)
        runtime_manager_supervisor.after(runtime_manager)

Composition.from_env().run()
