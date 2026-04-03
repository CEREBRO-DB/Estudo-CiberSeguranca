import psutil

def get_connections():
    connections = []

    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr:
            connections.append({
                "local_ip": conn.laddr.ip if conn.laddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "status": conn.status
            })

    return connections