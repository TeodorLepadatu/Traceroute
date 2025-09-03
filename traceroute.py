import socket
import requests
import ipaddress
from scapy.all import IP, UDP, ICMP, sr1
import plotly.graph_objects as go
import pandas as pd

fake_HTTP_header = {
    'referer': 'https://ipinfo.io/',     #pentru locatie se foloseste ipinfo.io
    'user-agent': (
        'Mozilla/5.0 (X11; Linux x86_64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/67.0.3396.79 Safari/537.36'
    )
}

def get_ipinfo(ip):
    url = f'https://ipinfo.io/{ip}/json'
    resp = requests.get(url, headers=fake_HTTP_header, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    loc = data.get('loc', '')
    lat, lon = (loc.split(',') if loc else (None, None))

    return {
        'ip': data.get('ip', ip),
        'city': data.get('city'),
        'region': data.get('region'),
        'country': data.get('country'),
        'lat': float(lat) if lat else None,
        'lon': float(lon) if lon else None
    }


def isPublic(ip_str): # de exemplu 192.168.1.1 nu e public
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError:
        return False

def traceroute_udp(dest_host, max_ttl=30, timeout_sec=3, udp_port=33434, message="salut"):
    hops = []
    try:
        target_ip = socket.gethostbyname(dest_host)
    except socket.gaierror:
        print(f"Can't resolve hostname: {dest_host}")
        return hops, False

    print(f"\nTrying UDP traceroute to {dest_host} ({target_ip}), max hops: {max_ttl}\n")
    reached = False
    for ttl in range(1, max_ttl + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=udp_port) / message
        print(f"Sending with TTL={ttl} to {target_ip}... ", end='')
        ans = sr1(pkt, timeout=timeout_sec, verbose=0)
        if ans is None:
            print("timeout")
        elif ans.haslayer(ICMP):
            icmp_layer = ans.getlayer(ICMP)
            hop_ip = ans.src
            msg = ''
            if icmp_layer.type == 11:
                msg = f"{hop_ip} – Time Exceeded"
            elif icmp_layer.type == 3:
                msg = f"{hop_ip} – Reached Destination"
                reached = True
            else:
                msg = f"{hop_ip} – ICMP Type {icmp_layer.type}"

            if isPublic(hop_ip):
                geo = get_ipinfo(hop_ip)
                if geo:
                    msg += f" [{geo['city']}, {geo['region']}, {geo['country']}]"
            else:
                msg += " [private]"

            print(msg)
            hops.append(hop_ip)
            if icmp_layer.type == 3:
                print(f"\nDestination {target_ip} reached.")
                break
    return hops, reached

# inspiration from https://www.youtube.com/watch?v=mtMY7q4R4q8&ab_channel=Vanish
def traceroute_icmp(target_host, payload="salut"):
    ttl = 1
    print(f"\nFalling back to ICMP traceroute for {target_host}\n")
    hops = []
    reached = False
    while ttl <= 30:
        try:
            packet = IP(dst=target_host, ttl=ttl) / ICMP() / payload
        except socket.gaierror:
            print(f"Can't resolve hostname {target_host}")
            return hops, False
        response = sr1(packet, verbose=False, timeout=1)
        if response is None:
            print(f"{ttl} : (no reply)")
        elif response.type == 11:
            hop_ip = response.src
            line = f"{ttl} : From {hop_ip}"
            if isPublic(hop_ip):
                geo = get_ipinfo(hop_ip)
                if geo:
                    line += f" [{geo['city']}, {geo['region']}, {geo['country']}]"
            print(line)
            hops.append(hop_ip)
        elif response.type == 0:
            hop_ip = response.src
            line = f"{ttl} : Reached final host: {hop_ip}"
            reached = True
            if isPublic(hop_ip):
                geo = get_ipinfo(hop_ip)
                if geo:
                    line += f" [{geo['city']}, {geo['region']}, {geo['country']}]"
            print(line)
            hops.append(hop_ip)
            break
        ttl += 1
    print("\nFinished ICMP traceroute.\n")
    return hops, reached

def plot(udp_hops, icmp_hops):
    data = []
    for hop in udp_hops:
        if isPublic(hop):
            geo = get_ipinfo(hop)
            if geo['lat'] and geo['lon']:
                geo['method'] = 'UDP'
                data.append(geo)
    for hop in icmp_hops:
        if isPublic(hop):
            geo = get_ipinfo(hop)
            if geo['lat'] and geo['lon']:
                geo['method'] = 'ICMP'
                data.append(geo)

    if not data:
        print("Nu am coordonate de afisat.")
        return

    df = pd.DataFrame(data)
    fig = go.Figure()
    for method in ['UDP', 'ICMP']:
        method_df = df[df['method'] == method]
        fig.add_trace(go.Scattergeo(
            lat=method_df['lat'],
            lon=method_df['lon'],
            text=method_df['ip'] + '<br>' + method_df['city'] + ', ' + method_df['country'],
            mode='lines+markers',
            name=method,
            marker=dict(size=8),
            line=dict(width=2)
        ))

    fig.update_layout(
        title='Traceroute Path',
        geo=dict(scope='world', projection_type='natural earth')
    )

    fig.show()

def traceroute(hostname, message="salut"):
    hops_udp, reached = traceroute_udp(hostname, message=message)
    hops_icmp = []
    if not reached:
        hops_icmp, reached = traceroute_icmp(hostname, message)
    if hops_udp or hops_icmp:
        plot(hops_udp, hops_icmp)
    else:
        print("Could not reach the destination.")

if __name__ == "__main__":
    target = input("Target hostname or IP: ")
    msg = input("Message: ")
    traceroute(target, message=msg)
