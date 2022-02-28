from argparse import ArgumentParser
from pathlib import Path
import os

from icecap_framework import BaseComposition
from runtime_manager import RuntimeManager
from virtio_console_server import VirtioConsoleServer

class Composition(BaseComposition):
    def compose(self):
        self.virtio_console_server = self.component(VirtioConsoleServer, 'virtio_console_server')
        self.component(RuntimeManager, 'runtime_manager')

parser = ArgumentParser()
parser.add_argument('-c', '--components', metavar='COMPONENTS', type=Path)
parser.add_argument('-o', '--out-dir', metavar='OUT_DIR', type=Path)
parser.add_argument('-p', '--plat', metavar='PLAT', type=str)
parser.add_argument('-s', '--object-sizes', metavar='OBJECT_SIZES', type=Path)
args = parser.parse_args()

components_path = os.path.abspath(args.components)

config = {
    "plat": args.plat,
    "num_cores": 4,
    "num_realms": 2,
    "default_affinity": 1,
    "hack_realm_affinity": 1,
    "object_sizes": args.object_sizes,
    "components": {
        "runtime_manager": {
            "image": {
                "full": os.path.join(components_path, "runtime_manager_enclave.full.elf"),
                "min": os.path.join(components_path, "runtime_manager_enclave.min.elf"),
            }
        },
        "virtio_console_server": {
            "image": {
                "full": os.path.join(components_path, "virtio-console-server.full.elf"),
                "min": os.path.join(components_path, "virtio-console-server.min.elf"),
            }

        },
    }
}

Composition(args.out_dir, config).run()