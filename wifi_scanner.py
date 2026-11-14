#!/usr/bin/env python3
"""Wi-Fi device scanner: finds, identifies and categorizes devices on YOUR network,
and serves a phone-friendly page with a signal-strength finder.

    python3 wifi_scanner.py            # then open the printed URL on your phone
    python3 wifi_scanner.py --subnet 192.168.0.0/24 --port 8080

Standard library only. Only scan networks you own or are authorized to audit.
"""
import argparse, errno, gzip, hmac, ipaddress, json, os, platform, re, secrets
import shutil, socket, subprocess, threading, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORTS = [22, 53, 80, 443, 445, 515, 548, 554, 631, 1883, 3389, 5900, 7000, 8000,
         8009, 8080, 8883, 9100, 32400, 37777, 62078]
MDNS_SERVICES = ['_airplay', '_raop', '_googlecast', '_ipp', '_printer', '_pdl-datastream',
                 '_hap', '_homekit', '_matter', '_companion-link', '_smb', '_ssh', '_rfb',
                 '_afpovertcp', '_spotify-connect', '_sonos', '_amzn-wplay', '_device-info',
                 '_workstation', '_androidtvremote2', '_rtsp', '_axis-video']
OUI_URLS = ['https://www.wireshark.org/download/automated/data/manuf.gz',
            'https://raw.githubusercontent.com/wireshark/wireshark/release-4.0/manuf']
OUI_FILE = os.path.expanduser('~/.cache/wifi-scanner/manuf.txt')

CATS = {  # key: (label, purpose)
    'camera':   ('Security & Cameras', 'Records or streams video / monitors your home'),
    'computer': ('Computers', 'Laptops, desktops, servers and storage'),
    'phone':    ('Phones & Tablets', 'Personal mobile devices'),
    'tv':       ('TVs, Speakers & Media', 'Streams video or music'),
    'printer':  ('Printers & Scanners', 'Prints or scans documents'),
    'console':  ('Game Consoles', 'Gaming'),
    'iot':      ('Smart Home & IoT', 'Smart plugs, lights, thermostats, appliances'),
    'network':  ('Network Gear', 'Routers, access points, extenders - runs the Wi-Fi itself'),
    'unknown':  ('Unidentified', 'Could not tell - check this one manually'),
}
# Tier 1: device's own name/model text (high confidence)
BY_NAME = [
    ('camera', r'camera|ipcam|\bcam\b|\bnvr\b|\bdvr\b|doorbell|hikvision|dahua|amcrest|reolink|wyze|arlo|eufy|lorex|swann|foscam|ezviz|blink|\bring\b|\baxis\b'),
    ('printer', r'printer|laserjet|officejet|deskjet|epson|brother|canon|pixma|ecotank'),
    ('console', r'playstation|\bps[45]\b|xbox|nintendo|steamdeck'),
    ('tv', r'tv\b|\btv|roku|chromecast|fire ?stick|shield|sonos|homepod|bravia|webos|vizio|soundbar|speaker|\becho\b|nest-?(hub|mini|audio)|google-?home|kodi|plex'),
    ('phone', r'iphone|ipad|android|galaxy|pixel|oneplus|redmi|xiaomi|huawei|oppo|\bmoto|phone|tablet|\bsm-[a-z]\d'),
    ('computer', r'macbook|imac|mac-?mini|mac-?studio|macpro|desktop|laptop|thinkpad|surface|\bpc\b|windows|ubuntu|linux|raspberry|workstation|server|\bnas\b|synology|qnap'),
    ('network', r'router|gateway|access ?point|extender|repeater|\bmesh\b|eero|orbi|unifi|\bdeco\b|openwrt|modem'),
    ('iot', r'\bhue\b|tuya|tasmota|shelly|sonoff|kasa|tapo|wemo|lifx|ecobee|thermostat|\bnest\b|smartthings|\bplug\b|bulb|\besp[-_ ]?\w*|homeassistant|roomba|irobot|dyson'),
]
# Tier 2: open ports / advertised services (medium confidence)
BY_SERVICE = [
    ('camera', {554, 37777, '_rtsp', '_axis-video'}, 'video-stream service (RTSP)'),
    ('printer', {515, 631, 9100, '_ipp', '_printer', '_pdl-datastream'}, 'printing service'),
    ('phone', {62078}, 'iPhone/iPad sync port'),
    ('computer', {22, 445, 548, 3389, 5900, '_smb', '_ssh', '_rfb', '_afpovertcp', '_workstation'}, 'file-sharing / remote-login service'),
    ('tv', {7000, 8009, 32400, '_googlecast', '_airplay', '_raop', '_spotify-connect', '_sonos', '_amzn-wplay', '_androidtvremote2'}, 'media-casting service'),
    ('iot', {1883, 8883, '_hap', '_homekit', '_matter'}, 'smart-home service'),
    ('network', {53}, 'DNS server'),
]
# Tier 3: hardware maker from MAC address (low confidence)
BY_VENDOR = [
    ('camera', r'hikvision|dahua|amcrest|reolink|wyze|arlo|axis comm|lorex|foscam|ezviz|uniview|\bring\b'),
    ('printer', r'epson|brother|canon|lexmark|kyocera|xerox|ricoh'),
    ('console', r'nintendo|sony interactive|valve'),
    ('tv', r'roku|sonos|vizio|\btcl\b|hisense|lg electronics|bose|harman|denon|yamaha'),
    ('network', r'ubiquiti|netgear|tp-link|arris|eero|mikrotik|cisco|aruba|linksys|d-link|zyxel|juniper|ruckus|technicolor|sagemcom|commscope|actiontec|\bzte\b'),
    ('computer', r'intel|dell|lenovo|hewlett|hp inc|micro-star|asustek|acer|microsoft|giga-byte|raspberry|framework|synology|qnap'),
    ('iot', r'espressif|tuya|signify|philips lighting|ecobee|shelly|itead|belkin|lifx|ikea|amazon|nest labs|smartthings|texas instruments|shenzhen|irobot|dyson|bouffalo|beken'),
    ('phone', r'apple|samsung|xiaomi|huawei|oneplus|oppo|vivo|motorola|google|hmd global'),
]


def categorize(d):
    """Return (category, why, confidence) for a device dict."""
    if d.get('is_gateway'):
        return 'network', 'it is your network gateway (router)', 'high'
    ident = ' '.join(str(d.get(k) or '') for k in ('hostname', 'name', 'model', 'maker')).lower()
    for cat, rx in BY_NAME:
        m = re.search(rx, ident)
        if m:
            return cat, 'its name/model contains "%s"' % m.group(0).strip(), 'high'
    if d.get('is_self'):
        return 'computer', 'this is the device running the scanner', 'high'
    seen = set(d.get('ports', [])) | set(d.get('services', []))
    for cat, keys, what in BY_SERVICE:
        hit = seen & keys
        if hit:
            return cat, 'it offers a %s (%s)' % (what, ', '.join(map(str, sorted(hit, key=str)))), 'medium'
    vendor = (d.get('vendor') or '').lower()
    for cat, rx in BY_VENDOR:
        if re.search(rx, vendor):
            return cat, 'hardware made by %s' % d['vendor'], 'low'
    if d.get('private_mac'):
        return 'phone', 'uses a private (randomized) Wi-Fi address, typical of phones/tablets', 'low'
    return 'unknown', 'no identifying information found', 'low'


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def norm_mac(mac):
    return ':'.join(p.zfill(2) for p in re.split('[:-]', mac.lower()))


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))  # no packet is sent; just picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()


def load_oui():
    """MAC-prefix -> manufacturer. Downloads the public Wireshark list once, then caches."""
    if not os.path.exists(OUI_FILE):
        for url in OUI_URLS:
            try:
                data = urllib.request.urlopen(url, timeout=15).read()
                if data[:2] == b'\x1f\x8b':
                    data = gzip.decompress(data)
                os.makedirs(os.path.dirname(OUI_FILE), exist_ok=True)
                with open(OUI_FILE, 'wb') as f:
                    f.write(data)
                break
            except (OSError, EOFError):
                continue
        else:
            print('! Could not download the manufacturer list; makers will be blank.')
            return {}
    table = {}
    with open(OUI_FILE, encoding='utf-8', errors='replace') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) >= 2 and len(p[0]) == 8:
                table[p[0].lower()] = p[-1].strip()
    return table


def read_arp(net):
    """ip -> mac from the OS neighbor table (empty on Android 10+, which hides it)."""
    out = {}
    for line in (run(['ip', 'neigh']) + run(['arp', '-a'])).splitlines():
        ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        mac = re.search(r'\b([0-9a-f]{1,2}([:-])[0-9a-f]{1,2}(?:\2[0-9a-f]{1,2}){4})\b', line, re.I)
        if ip and mac:
            m = norm_mac(mac.group(1))
            try:
                ok = ipaddress.ip_address(ip.group(1)) in net
            except ValueError:
                ok = False
            if ok and m not in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                out[ip.group(1)] = m
    return out


def find_gateway(net):
    for line in (run(['ip', 'route']) + run(['netstat', '-rn'])).splitlines():
        if re.match(r'\s*(default|0\.0\.0\.0)\b', line):
            for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', line):
                if ip != '0.0.0.0' and ipaddress.ip_address(ip) in net:
                    return ip
    return None


def mcast_socket(me):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
    except OSError:
        pass
    return s


def collect(s, seconds):
    end = time.time() + seconds
    while True:
        left = end - time.time()
        if left <= 0:
            return
        s.settimeout(left)
        try:
            yield s.recvfrom(9000)
        except OSError:
            return


def ssdp_scan(me):
    """UPnP discovery: devices announce a description URL with friendly name/model."""
    found = {}
    s = mcast_socket(me)
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           'MX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    try:
        s.sendto(msg, ('239.255.255.250', 1900))
        for data, (ip, _) in collect(s, 3.5):
            loc = re.search(rb'^location:\s*(\S+)', data, re.I | re.M)
            if loc and ip not in found:
                found[ip] = loc.group(1).decode('latin1')
    except OSError:
        pass
    s.close()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # LAN: never via proxy
    info = {}
    for ip, loc in found.items():
        info[ip] = {}
        u = urllib.parse.urlparse(loc)
        if u.scheme != 'http' or u.hostname != ip:  # only fetch from the device that answered
            continue
        try:
            xml = opener.open(loc, timeout=2).read(65536).decode('utf-8', 'replace')
        except (OSError, ValueError):
            continue
        for key, tag in (('name', 'friendlyName'), ('maker', 'manufacturer'), ('model', 'modelName')):
            m = re.search(r'<%s>\s*([^<]{1,100})' % tag, xml)
            if m:
                info[ip][key] = m.group(1).strip()
    return info


def mdns_scan(me):
    """Bonjour discovery: which services each device advertises, plus name/model hints."""
    info = {}
    s = mcast_socket(me)
    try:
        for svc in MDNS_SERVICES:
            q = b''.join(bytes([len(l)]) + l.encode() for l in (svc, '_tcp', 'local')) + b'\0'
            # header (1 question) + PTR query with the unicast-reply bit set
            s.sendto(b'\0\0\0\0\0\1\0\0\0\0\0\0' + q + b'\0\x0c\x80\x01', ('224.0.0.251', 5353))
        for data, (ip, _) in collect(s, 3.5):
            d = info.setdefault(ip, {'services': set()})
            d['services'].update(v for v in MDNS_SERVICES if bytes([len(v)]) + v.encode() in data)
            for m in re.finditer(rb'(model|rpMd|md|ty|am|fn)=', data):  # TXT records
                n = data[m.start() - 1] if m.start() else 0
                val = data[m.end():m.start() + n].decode('utf-8', 'replace').strip()
                if val:
                    d.setdefault('name' if m.group(1) == b'fn' else 'model', val)
            for m in re.finditer(rb'([\x01-\x3f])([A-Za-z0-9][A-Za-z0-9\-]{0,62})\x05local\x00', data):
                if m.group(1)[0] == len(m.group(2)):
                    d.setdefault('hostname', m.group(2).decode())
    except OSError:
        pass
    s.close()
    return info


def probe(target):
    ip, port = target
    s = socket.socket()
    s.settimeout(0.5)
    try:
        rc = s.connect_ex((ip, port))
    except OSError:
        rc = -1
    s.close()
    return ip, port, rc


def rdns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return ip, ('' if name == ip else name)
    except OSError:
        return ip, ''


def scan(subnet, oui):
    me = local_ip()
    net = ipaddress.ip_network(subnet or me + '/24', strict=False)
    hosts = [str(h) for h in net.hosts()][:1022]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for h in hosts:  # a stray UDP packet makes the OS resolve each neighbor's MAC
        try:
            s.sendto(b'', (h, 9))
        except OSError:
            pass
    s.close()
    with ThreadPoolExecutor(256) as pool:
        f_ssdp, f_mdns = pool.submit(ssdp_scan, me), pool.submit(mdns_scan, me)
        ssdp, mdns = f_ssdp.result(), f_mdns.result()
        in_net = lambda d: {ip: v for ip, v in d.items() if ip in hosts}
        ssdp, mdns, arp = in_net(ssdp), in_net(mdns), read_arp(net)
        # Without a neighbor table (Android), fall back to probing every address.
        targets = (set(arp) | set(ssdp) | set(mdns) | {me}) if arp else set(hosts)
        ports, alive = {}, set(arp) | set(ssdp) | set(mdns) | {me}
        for ip, port, rc in pool.map(probe, [(ip, p) for ip in targets for p in PORTS]):
            if rc == 0:
                ports.setdefault(ip, []).append(port)
            if rc in (0, errno.ECONNREFUSED):
                alive.add(ip)
        names = dict(pool.map(rdns, alive))
    gw, devices = find_gateway(net), []
    for ip in sorted(alive, key=ipaddress.ip_address):
        mac = arp.get(ip, '')
        up, md = ssdp.get(ip, {}), mdns.get(ip, {})
        d = {
            'ip': ip, 'mac': mac, 'vendor': oui.get(mac[:8], ''),
            'private_mac': bool(mac) and bool(int(mac[:2], 16) & 2),
            'hostname': names.get(ip) or md.get('hostname', ''),
            'model': up.get('model') or md.get('model', ''), 'maker': up.get('maker', ''),
            'services': sorted(md.get('services', [])), 'ports': sorted(ports.get(ip, [])),
            'is_gateway': ip == gw, 'is_self': ip == me,
        }
        if d['is_self']:
            d['hostname'] = d['hostname'] or socket.gethostname()
        d['name'] = (up.get('name') or md.get('name') or d['hostname'].split('.')[0]
                     or (d['vendor'] + ' device' if d['vendor'] else 'Unknown device'))
        d['category'], d['why'], d['confidence'] = categorize(d)
        devices.append(d)
    return {'subnet': str(net), 'devices': devices, 'scanned_at': time.strftime('%H:%M:%S')}


def nearby_radios():
    """Wi-Fi radios this machine can hear: [{bssid, ssid, signal(0-100)}], or None if unsupported."""
    pct = lambda dbm: max(0, min(100, 2 * (int(dbm) + 100)))
    radios = []
    if shutil.which('termux-wifi-scaninfo'):  # Android (Termux + Termux:API)
        try:
            cur = json.loads(run(['termux-wifi-connectioninfo']) or '{}')
            rows = json.loads(run(['termux-wifi-scaninfo']) or '[]')
        except ValueError:
            cur, rows = {}, []
        seen = {r.get('bssid') for r in rows if isinstance(r, dict)}
        if isinstance(cur, dict) and cur.get('bssid') and cur['bssid'] not in seen:
            rows.append(cur)
        for r in rows:
            if isinstance(r, dict) and r.get('bssid') and 'rssi' in r:
                radios.append({'bssid': norm_mac(r['bssid']), 'ssid': str(r.get('ssid', '')), 'signal': pct(r['rssi'])})
    elif shutil.which('nmcli'):  # Linux
        for line in run(['nmcli', '-t', '-f', 'BSSID,SIGNAL,SSID', 'dev', 'wifi', 'list', '--rescan', 'yes']).splitlines():
            m = re.match(r'((?:[0-9A-Fa-f]{2}\\:){5}[0-9A-Fa-f]{2}):(\d+):(.*)', line)
            if m:
                radios.append({'bssid': norm_mac(m.group(1).replace('\\', '')), 'ssid': m.group(3), 'signal': int(m.group(2))})
    elif platform.system() == 'Windows':
        ssid = ''
        for line in run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid']).splitlines():
            m = re.match(r'\s*(SSID|BSSID|Signal)\b[^:]*:\s*(.*)', line)
            if not m:
                continue
            if m.group(1) == 'SSID':
                ssid = m.group(2).strip()
            elif m.group(1) == 'BSSID':
                radios.append({'bssid': norm_mac(m.group(2).strip()), 'ssid': ssid, 'signal': 0})
            elif radios:
                radios[-1]['signal'] = int(m.group(2).strip().rstrip('%') or 0)
    else:
        return None
    return radios


def signal_report(devices):
    radios = nearby_radios()
    if radios is None:
        return {'supported': False, 'radios': []}
    for r in radios:
        # A device's own radio (BSSID) usually differs from its LAN MAC only in the first/last byte.
        match = next((d for d in devices if d['mac'] and d['mac'][3:14] == r['bssid'][3:14]), None)
        r['device'] = match['name'] if match else ''
        r['ip'] = match['ip'] if match else ''
    radios.sort(key=lambda r: (not r['device'], -r['signal']))
    return {'supported': True, 'radios': radios}


PAGE = r'''<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Wi-Fi Scanner</title>
<style>
body{font:15px system-ui,sans-serif;margin:0;background:#0f1419;color:#e6e9ec}
header{position:sticky;top:0;background:#182029;padding:10px 14px;display:flex;gap:8px;align-items:center;z-index:1}
header b{flex:1}button{background:#2b7de9;color:#fff;border:0;border-radius:8px;padding:8px 12px;font-size:14px}
button.off{background:#33404d}main{padding:10px 14px;max-width:760px;margin:auto}
h2{font-size:15px;margin:18px 0 2px}.sub{color:#8a97a5;font-size:12px}
.card{background:#182029;border-radius:10px;padding:10px 12px;margin:8px 0}
.card .n{font-weight:600;font-size:16px}.tag{display:inline-block;font-size:11px;border-radius:6px;padding:1px 6px;margin-left:6px;background:#33404d}
.high{background:#1d6b3a}.medium{background:#7a5a12}.low{background:#6b2a2a}
.bar{height:14px;background:#33404d;border-radius:7px;overflow:hidden;margin:6px 0}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#d9534f,#f0ad4e,#5cb85c);transition:width .5s}
.hide{display:none}.big{font-size:22px;font-weight:700}
</style></head><body>
<header><b>Wi-Fi Scanner</b><button id="tabD">Devices</button><button id="tabS" class="off">Signal</button><button id="rescan" class="off">Rescan</button></header>
<main><div id="status" class="sub"></div><div id="devices"></div><div id="signal" class="hide"></div></main>
<script>
const $=id=>document.getElementById(id);
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
let prev={},sigTimer=null;
async function loadDevices(){
  const s=await (await fetch('api/devices')).json();
  $('status').textContent=s.scanning?'Scanning your network… (about 15-30 seconds)':
    `${s.devices.length} devices on ${s.subnet} · scanned ${s.scanned_at}`;
  const box=$('devices');box.replaceChildren();
  for(const [key,[label,purpose]] of Object.entries(s.categories)){
    const list=s.devices.filter(d=>d.category===key);if(!list.length)continue;
    box.append(el('h2','',`${label} (${list.length})`),el('div','sub',purpose));
    for(const d of list){
      const c=el('div','card'),n=el('div','n',d.name);
      n.append(el('span','tag '+d.confidence,d.confidence+' confidence'));
      if(d.is_self)n.append(el('span','tag','this device'));
      c.append(n);
      const what=[d.maker||d.vendor,d.model].filter(Boolean).join(' · ');
      if(what)c.append(el('div','',what));
      c.append(el('div','sub','Why: '+d.why));
      c.append(el('div','sub',`IP ${d.ip}`+(d.mac?` · MAC ${d.mac}`+(d.private_mac?' (private)':''):'')+(d.hostname?` · ${d.hostname}`:'')));
      const extra=[...d.services,...d.ports.map(p=>'port '+p)].join(', ');
      if(extra)c.append(el('div','sub','Offers: '+extra));
      box.append(c);
    }
  }
  if(s.scanning)setTimeout(loadDevices,3000);
}
const words=p=>p>=75?'Very close (same room)':p>=50?'Near':p>=30?'A few rooms away':'Far / weak';
async function loadSignal(){
  const s=await (await fetch('api/signal')).json(),box=$('signal');box.replaceChildren();
  box.append(el('div','sub','Signal is measured by the machine running the scanner — carry THAT device around. Stronger = closer. Only devices that broadcast their own Wi-Fi radio (routers, extenders, many printers, cameras, TVs) can be ranged.'));
  if(!s.supported)box.append(el('div','card','Signal reading is not supported on this system (needs Linux nmcli, Windows, or Android Termux with Termux:API).'));
  else if(!s.radios.length)box.append(el('div','card','No Wi-Fi radios heard. Is Wi-Fi on?'));
  for(const r of s.radios){
    const c=el('div','card'),p=prev[r.bssid];
    const trend=p==null||p===r.signal?'':r.signal>p?' ▲ getting closer':' ▼ moving away';
    c.append(el('div','n',r.device||r.ssid||'(hidden network)'));
    if(r.device)c.lastChild.append(el('span','tag high','on your device list'));
    const b=el('div','bar'),i=el('i');i.style.width=r.signal+'%';b.append(i);
    c.append(el('div','big',r.signal+'%'+trend),b,el('div','sub',`${words(r.signal)} · ~${Math.round(r.signal/2-100)} dBm · ${r.bssid}`+(r.ip?` · ${r.ip}`:'')));
    box.append(c);prev[r.bssid]=r.signal;
  }
}
function show(sig){
  $('devices').classList.toggle('hide',sig);$('signal').classList.toggle('hide',!sig);
  $('tabD').classList.toggle('off',sig);$('tabS').classList.toggle('off',!sig);
  clearInterval(sigTimer);if(sig){loadSignal();sigTimer=setInterval(loadSignal,4000)}
}
$('tabD').onclick=()=>show(false);$('tabS').onclick=()=>show(true);
$('rescan').onclick=async()=>{await fetch('api/scan',{method:'POST'});show(false);loadDevices()};
loadDevices();
</script></body></html>'''


class App:
    def __init__(self, subnet):
        self.subnet, self.oui = subnet, load_oui()
        self.token = secrets.token_urlsafe(8)
        self.state = {'subnet': '', 'devices': [], 'scanned_at': ''}
        self.scanning = False
        self.lock = threading.Lock()

    def start_scan(self):
        with self.lock:
            if self.scanning:
                return
            self.scanning = True
        threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self):
        try:
            self.state = scan(self.subnet, self.oui)
            print('Scan done: %d devices on %s' % (len(self.state['devices']), self.state['subnet']))
        except Exception as e:  # keep the server alive; show the failure in the console
            print('! Scan failed: %r' % e)
        finally:
            self.scanning = False


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        def send(self, body, ctype='application/json', code=200):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)

        def route(self):
            # Every URL must start with the secret token so other people on the LAN can't browse it.
            token, _, rest = self.path.split('?')[0].lstrip('/').partition('/')
            if not hmac.compare_digest(token.encode(), app.token.encode()):
                return None
            return rest

        def do_GET(self):
            r = self.route()
            if r == '':
                self.send(PAGE.encode(), 'text/html; charset=utf-8')
            elif r == 'api/devices':
                self.send(dict(app.state, scanning=app.scanning, categories=CATS))
            elif r == 'api/signal':
                self.send(signal_report(app.state['devices']))
            else:
                self.send(b'Not found', 'text/plain', 404)

        def do_POST(self):
            if self.route() == 'api/scan':
                app.start_scan()
                self.send({'ok': True})
            else:
                self.send(b'Not found', 'text/plain', 404)

        def log_message(self, *a):
            pass
    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--subnet', help='network to scan, e.g. 192.168.1.0/24 (default: your current /24)')
    ap.add_argument('--port', type=int, default=8737)
    ap.add_argument('--once', action='store_true', help='scan once, print JSON, exit (no web page)')
    a = ap.parse_args()
    if a.once:
        print(json.dumps(scan(a.subnet, load_oui()), indent=1))
        return
    app = App(a.subnet)
    app.start_scan()
    srv = ThreadingHTTPServer(('0.0.0.0', a.port), make_handler(app))
    print('Open in a browser:\n  On this device:          http://127.0.0.1:%d/%s/\n'
          '  From phone (same Wi-Fi): http://%s:%d/%s/\nCtrl+C to stop.'
          % (a.port, app.token, local_ip(), a.port, app.token))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
