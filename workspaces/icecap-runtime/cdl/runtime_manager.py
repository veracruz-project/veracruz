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

from capdl import ObjectType
from icecap_framework.components.generic import GenericElfComponent
from icecap_framework.utils import PAGE_SIZE_BITS, BLOCK_SIZE

BADGE_VIRTIO_CONSOLE_SERVER_RING_BUFFER = 1 << 2

class RuntimeManager(GenericElfComponent):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        event_nfn = self.alloc(ObjectType.seL4_NotificationObject, name='event_nfn')

        virtio_console_server_rb_objs, virtio_console_server_kick_nfn_cap = self.composition.virtio_console_server.register_client(self, event_nfn, BADGE_VIRTIO_CONSOLE_SERVER_RING_BUFFER)

        self._arg = {
            'event_nfn': self.cspace().alloc(event_nfn, read=True),
            'virtio_console_server_ring_buffer': {
                'ring_buffer': self.map_ring_buffer(virtio_console_server_rb_objs),
                'kicks': {
                    'read': virtio_console_server_kick_nfn_cap,
                    'write': virtio_console_server_kick_nfn_cap,
                    },
                },
            'badges': {
                'virtio_console_server_ring_buffer': BADGE_VIRTIO_CONSOLE_SERVER_RING_BUFFER,
                },
        }

    def static_heap_size(self):
        return 128 * BLOCK_SIZE # 256 MiB

    def arg_json(self):
        return self._arg
