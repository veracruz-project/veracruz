from capdl import ObjectType
from icedl.common import GenericElfComponent
from icedl.realm import BaseRealmComposition
from icedl.utils import PAGE_SIZE_BITS, BLOCK_SIZE


class RuntimeManager(GenericElfComponent):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
            }

    def arg_json(self):
        return self._arg


class Composition(BaseRealmComposition):

    def compose(self):
        self.component(RuntimeManager, 'runtime_manager')


Composition.run()
