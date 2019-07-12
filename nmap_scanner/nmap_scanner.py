from shared_task_code.ecs_scanner import EcsScanner
from .nmap_request_sanitiser import sanitise_nmap_target
from json import loads
from json.decoder import JSONDecodeError


class NmapScanner(EcsScanner):
    def __init__(self):
        super().__init__()

    async def create_environment_from_request(self, scan_request_id, scan_request):
        print(f"Nmap scanning {scan_request_id} - {scan_request}")
        # TODO revisit this decision to support both json and a literal string, won't work when we add
        # e.g. address type to the scan request
        try:
            address_to_scan = loads(scan_request)["AddressToScan"]
        except JSONDecodeError:
            address_to_scan = scan_request

        return {
            "NMAP_TARGET_STRING": sanitise_nmap_target(address_to_scan.strip())
        }
