import socket

class Orion:
    def __init__(self, target):
        self.target = target

    def scan_services(self):
        print(f"\n[ORION] Coletando serviços em {self.target}\n")

        ports = [21, 22, 80, 443, 3306, 8080]
        results = []

        for port in ports:
            try:
                sock = socket.socket()
                sock.settimeout(1)
                sock.connect((self.target, port))

                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore")
                except:
                    banner = "sem banner"

                service = {
                    "port": port,
                    "banner": banner.strip()
                }

                print(f"[ORION] {service}")
                results.append(service)

                sock.close()

            except:
                pass

        return results