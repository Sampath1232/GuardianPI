import nmap

scanner = nmap.PortScanner()

def scan_network(target):

    try:

        scanner.scan(
            hosts=target,
            arguments='-F -T4'
        )

        hosts = []

        for host in scanner.all_hosts():

            hosts.append({

                "ip": host,

                "hostname": scanner[host].hostname(),

                "state": scanner[host].state()
            })

        return hosts

    except Exception as e:

        return {

            "error": str(e)
        }