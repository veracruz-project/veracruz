from icecap_hypervisor.realm import BaseRealmComposition

class Composition(BaseRealmComposition):
    def compose(self):
        pass

Composition.from_env().run()
