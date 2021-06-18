from capdl import ObjectType, Cap
from icedl import *

composition = start()

veracruz_con = composition.extern_ring_buffer('realm_vmm_con', size=4096)
sandbox_con = composition.extern_ring_buffer('realm_vm_con', size=4096)
host_rb = composition.extern_ring_buffer('host_raw', 1 << 21)

class RuntimeManager(GenericElfComponent):

    def __init__(self, *args, **kwargs):
        super().__init__(affinity=2, *args, **kwargs)
        self._arg = {
            'host_ring_buffer': self.map_ring_buffer_with(host_rb, mapped=True),
            }

    def arg_json(self):
        return self._arg

runtime_manager = composition.component(RuntimeManager, 'runtime_manager')

composition.complete()
