#!/usr/bin/env python3
"""Radar for iPhone: finds and identifies nearby wireless devices, with pictures and a closer/farther meter.

Runs in Pythonista 3 (App Store), so nothing is sideloaded. It shows:
  * every nearby device advertising over Bluetooth Low Energy, on any network or none
    (phones, AirPods, AirTags and other trackers, watches, speakers, TVs, cars, cameras, sensors...);
  * the devices on your current Wi-Fi network (needs wifi_scanner.py next to this file).

Install: paste the one-line command from https://radar.ackerworks.com into Pythonista's console,
then open radar_ios.py and tap Run.
"""
import json, os, re, sys, threading, time, urllib.parse, urllib.request
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(HERE, '.radar_ids.json')
SIG_URL = 'https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/'
SIG_LISTS = ('company_identifiers/company_identifiers.yaml', 'uuids/member_uuids.yaml', 'uuids/service_uuids.yaml')
HEADERS = {'User-Agent': 'Radar/1.0 (personal device finder)'}

CATS = {  # key: (label, purpose); keys shared with wifi_scanner.py
    'tracker':  ('Trackers', 'AirTags, Tiles, SmartTags - check any you do not own'),
    'camera':   ('Security & Cameras', 'Records or streams video'),
    'phone':    ('Phones & Tablets', 'Personal mobile devices'),
    'computer': ('Computers', 'Laptops, desktops, servers and storage'),
    'wearable': ('Watches & Fitness', 'Smartwatches, fitness bands, heart-rate and sports sensors'),
    'audio':    ('Headphones & Speakers', 'Earbuds, headphones, smart speakers'),
    'tv':       ('TVs & Streaming', 'TVs, streaming boxes, media players'),
    'input':    ('Keyboards, Mice & Controllers', 'Input devices and remotes'),
    'health':   ('Health Devices', 'Scales, blood-pressure cuffs, glucose meters, thermometers'),
    'printer':  ('Printers & Scanners', 'Prints or scans documents'),
    'console':  ('Game Consoles', 'Gaming'),
    'iot':      ('Smart Home & Gadgets', 'Lights, plugs, locks, sensors, beacons'),
    'vehicle':  ('Vehicles', 'Cars, e-bikes and scooters'),
    'network':  ('Network Gear', 'Routers, access points, extenders'),
    'unknown':  ('Unidentified', 'Broadcasts nothing that says what it is'),
}
RANK = {'low': 0, 'medium': 1, 'high': 2}

# Built-in fallback until the full Bluetooth SIG lists have downloaded once.
BUILTIN = {
    'company': {'004C': 'Apple, Inc.', '0006': 'Microsoft', '0075': 'Samsung Electronics Co. Ltd.', '00E0': 'Google',
                '0087': 'Garmin International, Inc.', '009E': 'Bose Corporation', '05A7': 'Sonos Inc',
                '0171': 'Amazon.com Services LLC', '038F': 'Xiaomi Inc.', '0157': 'Anhui Huami Information Technology Co., Ltd.',
                '02E5': 'Espressif Systems (Shanghai) Co., Ltd.', '0059': 'Nordic Semiconductor ASA', '000D': 'Texas Instruments Inc.'},
    'uuid': {'180D': 'Heart Rate', '180F': 'Battery', '1812': 'Human Interface Device', '180A': 'Device Information'},
}
IDS = {k: dict(v) for k, v in BUILTIN.items()}
IDS_VERSION = 0

APPLE_AUDIO = {  # model bytes in Apple's AirPods/Beats proximity-pairing broadcast
    '0220': 'AirPods (1st generation)', '0f20': 'AirPods (2nd generation)', '1320': 'AirPods (3rd generation)',
    '0e20': 'AirPods Pro', '1420': 'AirPods Pro (2nd generation)', '2420': 'AirPods Pro (2nd generation, USB-C)',
    '0a20': 'AirPods Max', '0320': 'Powerbeats3', '0b20': 'Powerbeats Pro', '0c20': 'Beats Solo Pro',
    '0520': 'BeatsX', '0620': 'Beats Solo3', '0920': 'Beats Studio3', '1020': 'Beats Flex',
    '1120': 'Beats Studio Buds', '1220': 'Beats Fit Pro', '1620': 'Beats Studio Buds+', '1720': 'Beats Studio Pro',
}
# uuid: (category, product, confidence, picture search)
SERVICES = {
    'FEED': ('tracker', 'Tile tracker', 'medium', 'Tile tracker'), 'FEEC': ('tracker', 'Tile tracker', 'medium', 'Tile tracker'),
    'FD84': ('tracker', 'Tile tracker', 'medium', 'Tile tracker'),
    'FD5A': ('tracker', 'Samsung Galaxy SmartTag', 'medium', 'Galaxy SmartTag'),
    'FE33': ('tracker', 'Chipolo tracker', 'medium', 'Chipolo'),
    'FE2C': ('audio', 'Google Fast Pair accessory (earbuds, headphones or speaker)', 'medium', ''),
    'FD6F': ('phone', 'Phone with exposure notifications on', 'low', ''),
    'FE03': ('audio', 'Amazon Echo or Alexa device', 'medium', 'Amazon Echo'),
    'FE07': ('audio', 'Sonos speaker', 'medium', 'Sonos speaker'),
    'FEBE': ('audio', 'Bose headphones or speaker', 'medium', 'Bose headphones'),
    'FD82': ('audio', 'Sony headphones or speaker', 'low', 'Sony headphones'),
    'FE0F': ('iot', 'Philips Hue light', 'medium', 'Philips Hue'),
    'FE61': ('input', 'Logitech keyboard, mouse or remote', 'medium', 'Logitech mouse'),
    'FE78': ('printer', 'HP printer', 'medium', 'HP OfficeJet'),
    'FEE0': ('wearable', 'Amazfit or Mi Band', 'medium', 'Amazfit'),
    'FE95': ('iot', 'Xiaomi gadget (band, sensor or smart-home)', 'low', ''),
    'FD5F': ('wearable', 'Meta Quest headset or Ray-Ban Meta glasses', 'medium', 'Meta Quest'),
    '180D': ('wearable', 'Heart-rate sensor (watch, band or chest strap)', 'medium', ''),
    '1814': ('wearable', 'Running sensor', 'medium', ''), '1816': ('wearable', 'Cycling speed/cadence sensor', 'medium', ''),
    '1818': ('wearable', 'Cycling power meter', 'medium', ''), '1826': ('wearable', 'Fitness machine (treadmill, bike...)', 'medium', ''),
    '1812': ('input', 'Keyboard, mouse or game controller', 'medium', ''),
    '1808': ('health', 'Glucose meter', 'medium', ''), '1809': ('health', 'Thermometer', 'medium', ''),
    '1810': ('health', 'Blood-pressure monitor', 'medium', ''), '181D': ('health', 'Weight scale', 'medium', ''),
    '181B': ('health', 'Body-composition scale', 'medium', ''), '1822': ('health', 'Pulse oximeter', 'medium', ''),
    '183A': ('health', 'Insulin pump', 'medium', ''),
    '1802': ('tracker', 'Key finder tag', 'low', ''), '1803': ('tracker', 'Key finder tag', 'low', ''),
}
for _u in ('184E', '184F', '1850', '1853', '1854', '1855', '1856', '1844', '1845'):
    SERVICES[_u] = ('audio', 'LE Audio headphones or speaker', 'medium', '')
# Device's own broadcast name -> category (order matters: first match wins)
BY_NAME = [
    ('tracker', r'airtag|\btile\b|smarttag|chipolo|pebblebee|tracker|\bitag\b'),
    ('camera', r'camera|\bcam\b|doorbell|wyze|arlo|eufy|blink|\bring\b|reolink|gopro|insta360|\bdji\b|osmo'),
    ('audio', r'airpods|beats|buds|bose|jbl|\bwh-|\bwf-|jabra|sennheiser|skullcandy|soundcore|ue ?boom|marshall|speaker|headphone|earbud|soundbar|sonos|\becho\b|homepod|\bqc ?\d|quietcomfort|powerbeats'),
    ('wearable', r'watch|band\b|fitbit|garmin|forerunner|fenix|venu|polar|whoop|oura|amazfit|charge ?\d|versa|inspire|\bhrm|heart|ray-ban|quest'),
    ('tv', r'\btv\b|\[tv\]|roku|fire ?tv|chromecast|bravia|vizio|hisense|\btcl\b'),
    ('input', r'keyboard|mouse|trackpad|pencil|controller|dualsense|dualshock|joy-con|mx master|mx keys|gamepad|remote'),
    ('health', r'scale|blood|glucose|thermometer|oximeter|omron|withings|accu-chek|dexcom|libre'),
    ('vehicle', r'tesla|\bcar\b|ford|toyota|honda|bmw|audi|mercedes|hyundai|\bkia\b|subaru|rivian|volkswagen|chevrolet|scooter|segway|ninebot'),
    ('printer', r'printer|officejet|deskjet|laserjet|epson|brother|canon|zebra|instax'),
    ('iot', r'\bhue\b|govee|ihoment|kasa|tapo|wemo|\bnest\b|ecobee|switchbot|tuya|smart ?life|meross|lifx|nanoleaf|yeelight|aqara|lock|august|yale|schlage|plug|bulb|light|thermostat|sensor|esp32|roomba|beacon'),
    ('console', r'nintendo|switch|playstation|\bps[45]\b|xbox'),
    ('computer', r'macbook|imac|mac ?mini|laptop|desktop|thinkpad|surface|windows|\bpc\b|chromebook'),
    ('phone', r'iphone|ipad|galaxy|pixel|oneplus|redmi|motorola|\bmoto\b|phone|android'),
]
# Registered maker name -> category guess (low confidence)
BY_MAKER = [
    ('tracker', r'tile, inc|chipolo|pebblebee'),
    ('wearable', r'garmin|fitbit|polar|huami|whoop|oura|suunto|coros|wahoo|zepp'),
    ('audio', r'bose|sonos|jabra|gn audio|sennheiser|harman|skullcandy|anker|plantronics|bang & olufsen|sony'),
    ('input', r'logitech|razer'), ('console', r'nintendo'),
    ('vehicle', r'tesla|ford|bmw|toyota|honda|hyundai|kia|volkswagen|general motors|rivian|segway'),
    ('health', r'omron|withings|dexcom|abbott|roche|medtronic'),
    ('printer', r'hewlett|hp inc|canon|seiko epson|brother'),
    ('audio', r'amazon'),
    ('iot', r'espressif|nordic|texas instruments|silicon lab|telink|realtek|beken|bouffalo|dialog|cypress|xiaomi|tuya|signify|ikea'),
]


def tlv(data):
    i = 0
    while i + 2 <= len(data):
        t, n = data[i], data[i + 1]
        yield t, data[i + 2:i + 2 + n]
        i += 2 + n


def apple(data):
    """Decode Apple's (company 0x004C) broadcasts. Formats are reverse-engineered, not documented by Apple."""
    found = []
    for t, v in tlv(data):
        if t == 0x07 and len(v) >= 3:
            model = APPLE_AUDIO.get(v[1:3].hex())
            found.append((0, 'audio', model or 'AirPods or Beats headphones', 'high' if model else 'medium',
                          "it sends Apple's AirPods/Beats pairing signal" + ('' if model else ' (model code %s)' % v[1:3].hex()),
                          model or 'AirPods', False))
        elif t == 0x12 and v:
            kind = (v[0] >> 4) & 3
            away = len(v) >= 20
            cat, prod, q = [('phone', 'iPhone, iPad, Mac or Apple Watch', 'iPhone'), ('tracker', 'AirTag', 'AirTag'),
                            ('tracker', 'Find My tracker (Chipolo, Pebblebee, Belkin...)', ''),
                            ('audio', 'AirPods', 'AirPods')][kind]
            found.append((1, cat, prod, 'medium', 'it sends a Find My signal' + (' as a device away from its owner' if away else ''),
                          q, away and cat == 'tracker'))
        elif t == 0x09:
            found.append((2, 'tv', 'Apple TV, HomePod or AirPlay speaker', 'medium', 'it advertises itself as an AirPlay receiver', 'Apple TV', False))
        elif t == 0x0B:
            found.append((3, 'wearable', 'Apple Watch', 'medium', 'it sends the Apple Watch wrist signal', 'Apple Watch', False))
        elif t in (0x0D, 0x0E):
            found.append((4, 'phone', 'iPhone or iPad (Personal Hotspot)', 'medium', 'it offers Instant Hotspot', 'iPhone', False))
        elif t == 0x05:
            found.append((5, 'phone', 'iPhone, iPad or Mac (AirDrop)', 'medium', 'it is looking for AirDrop', 'iPhone', False))
        elif t == 0x02:
            found.append((6, 'iot', 'iBeacon', 'medium', 'it is an iBeacon', 'iBeacon', False))
        elif t in (0x10, 0x0C, 0x0F, 0x0A):
            found.append((7, 'phone', 'iPhone, iPad, Mac or Apple Watch', 'low', 'it sends Apple Continuity (Handoff/nearby) signals', 'iPhone', False))
    if not found:
        return 'phone', 'Apple device', 'low', 'it is registered to Apple', '', False
    return min(found)[1:]


def microsoft(v):
    if v[:1] == b'\x01' and len(v) > 1:
        kind = {1: ('console', 'Xbox'), 9: ('computer', 'Windows desktop PC'), 14: ('computer', 'Surface Hub'),
                15: ('computer', 'Windows laptop'), 16: ('computer', 'Windows tablet')}.get(v[1] & 0x1F)
        cat, prod = kind or ('computer', 'Windows PC or Microsoft device')
        return cat, prod, 'medium', 'it sends the Microsoft Connected Devices signal', prod, False
    if v[:1] == b'\x03':
        return 'input', 'Swift Pair accessory (keyboard, mouse or headset)', 'medium', 'it is offering Microsoft Swift Pair', '', False
    return None


def short_uuid(u):
    u = str(u).upper()
    m = re.match(r'0000([0-9A-F]{4})-0000-1000-8000-00805F9B34FB$', u)
    return m.group(1) if m else u


def clean_name(name):
    """"Keith's AirPods Pro" -> "AirPods Pro", "LE-Bose QC35 (1A2B)" -> "Bose QC35"."""
    n = re.sub(r"^.{1,30}?['’]s\s+", '', name.strip())
    n = re.sub(r'^(LE[-_ ]|\[[A-Za-z]+\]\s*)', '', n)
    n = re.sub(r'[\s_-]*[(\[]?[0-9A-Fa-f]{4,}[)\]]?$', '', n)
    return n.strip() or name.strip()


def identify(a):
    """a: dict(name, mfr bytes, services list, service_data {uuid: bytes}, tx) -> what the device is."""
    name = (a.get('name') or '').strip()
    mfr = a.get('mfr') or b''
    company = '%04X' % int.from_bytes(mfr[:2], 'little') if len(mfr) >= 2 else ''
    sdata = {short_uuid(k): v for k, v in (a.get('service_data') or {}).items()}
    uuids = list(dict.fromkeys([short_uuid(u) for u in a.get('services') or []] + list(sdata)))
    maker = IDS['company'].get(company, '')
    if not maker:
        maker = next((IDS['uuid'][u] for u in uuids if u in IDS['uuid'] and not u.startswith('18')), '')
    cands = []  # (confidence, order, category, product, why, query, alert)

    def add(cat, prod, conf, why, query='', alert=False):
        cands.append((RANK[conf], -len(cands), cat, prod, why, query, alert))

    hit = apple(mfr[2:]) if company == '004C' else microsoft(mfr[2:]) if company == '0006' else None
    if hit:
        cat, prod, conf, why, q, alert = hit
        add(cat, prod, conf, why, q, alert)
    for u in uuids:
        if u == 'FEAA':
            if sdata.get(u, b'')[:1] in (b'\x40', b'\x41'):
                add('tracker', 'Google Find Hub tracker or Android device', 'medium', 'it sends a Google Find Hub signal')
            else:
                add('iot', 'Eddystone beacon', 'medium', 'it is an Eddystone beacon')
        elif u in SERVICES:
            cat, prod, conf, q = SERVICES[u]
            add(cat, prod, conf, 'it advertises the %s service (%s)' % (IDS['uuid'].get(u, u), u), q)
    if name:
        for cat, rx in BY_NAME:
            m = re.search(rx, name.lower())
            if m:
                add(cat, clean_name(name), 'high', 'its broadcast name contains "%s"' % m.group(0).strip(), clean_name(name))
                break
    if company == '0075':
        add('phone', 'Samsung Galaxy phone, tablet, watch, earbuds or TV', 'low', 'it is registered to Samsung')
    for cat, rx in BY_MAKER:
        if maker and re.search(rx, maker.lower()):
            add(cat, '%s device' % maker.split(',')[0], 'low', 'it is registered to %s' % maker)
            break
    if name and not cands:
        add('unknown', clean_name(name), 'low', 'it broadcasts a name, but nothing says what kind of device it is')
    if not cands:
        add('unknown', 'Unknown device', 'low', 'no name or maker broadcast (many phones and gadgets hide this)')
    conf, _, cat, prod, why, query, alert = max(cands)
    if name and RANK['high'] > conf and cat != 'unknown':
        prod = '%s (%s)' % (clean_name(name), prod)
    notes = []
    if alert:
        notes.append('Away from its owner. If it keeps showing up wherever you go, it may be travelling '
                     'with you: check bags, coats and your car.')
    return {'category': cat, 'product': prod, 'maker': maker, 'why': why,
            'confidence': {v: k for k, v in RANK.items()}[conf], 'query': query, 'notes': notes, 'alert': alert}


def proximity(rssi):
    return 'Very close' if rssi >= -55 else 'Same room' if rssi >= -67 else 'Nearby' if rssi >= -80 else 'Far'


def distance_m(rssi):
    """Very rough distance from signal strength (walls, bodies and pockets change it a lot).
    Uses one typical 1 m reference for every device: advertised transmit powers are too unreliable."""
    return round(10 ** ((-59 - rssi) / 25.0), 1)


class Device:
    def __init__(self, key, source='ble'):
        self.key, self.source, self.name = key, source, ''
        self.mfr, self.services, self.sdata, self.tx = b'', set(), {}, None
        self.rssi, self.hist = None, deque(maxlen=20)
        self.first = self.last = time.time()
        self.info, self.sig, self.wifi = None, None, None

    def update(self, name, mfr, services, sdata, tx, rssi):
        # iOS delivers the advertisement and the scan response separately: merge them.
        self.name = name or self.name
        self.mfr = mfr or self.mfr
        self.services.update(services)
        self.sdata.update(sdata)
        self.tx = tx if tx is not None else self.tx
        self.last = time.time()
        if rssi is not None and -127 < rssi < 0:  # 127 = not available
            self.rssi = rssi if self.rssi is None else round(self.rssi * 0.7 + rssi * 0.3, 1)
            self.hist.append(self.rssi)

    def ident(self):
        if self.source != 'ble':
            return self.info
        sig = (self.name, self.mfr, tuple(sorted(self.services)), tuple(sorted(self.sdata.items())), IDS_VERSION)
        if sig != self.sig:
            self.info, self.sig = identify({'name': self.name, 'mfr': self.mfr, 'services': self.services,
                                            'service_data': self.sdata, 'tx': self.tx}), sig
        return self.info

    def trend(self):
        h = list(self.hist)
        if len(h) < 6:
            return ''
        d = sum(h[-3:]) / 3 - sum(h[-6:-3]) / 3
        return ' ▲ closer' if d > 2 else ' ▼ farther' if d < -2 else ''


def wifi_device(w):
    d = Device('wifi:' + w['ip'], 'wifi')
    d.name, d.wifi = w['name'], w
    maker = w.get('maker') or w.get('vendor') or ''
    d.info = {'category': w['category'] if w['category'] in CATS else 'unknown',
              'product': ('This iPhone' if w.get('is_self') else (w.get('model') or w['name'])),
              'maker': maker, 'why': w['why'], 'confidence': w['confidence'],
              'query': ' '.join(filter(None, [maker, w.get('model')])) if w.get('model') else '',
              'notes': [], 'alert': False}
    return d


DEVICES, LOCK = {}, threading.Lock()


def record(key, name, mfr, services, sdata, tx, rssi):
    with LOCK:
        d = DEVICES.get(key) or DEVICES.setdefault(key, Device(key))
        d.update(name, mfr, services, sdata, tx, rssi)


def fetch(url, timeout=20):
    return urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=timeout).read()


def parse_sig(text):
    return {m.group(1).upper().zfill(4): m.group(2).strip().strip('\'"')
            for m in re.finditer(r'(?:value|uuid):\s*0x([0-9A-Fa-f]+)\s*\n\s*name:\s*(.+)', text)}


def load_ids():
    """Full Bluetooth SIG maker/service name lists, downloaded once and cached for 30 days."""
    global IDS, IDS_VERSION
    try:
        if time.time() - os.path.getmtime(CACHE_FILE) > 30 * 86400:
            raise OSError('stale')
        with open(CACHE_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {'company': {}, 'uuid': {}}
        try:
            for path in SIG_LISTS:
                data['company' if 'company' in path else 'uuid'].update(parse_sig(fetch(SIG_URL + path).decode('utf-8', 'replace')))
        except OSError as e:
            print('Could not download the Bluetooth maker list (%s); using the short built-in list.' % e)
            return
        with open(CACHE_FILE, 'w') as f:
            json.dump(data, f)
    IDS = {k: dict(BUILTIN[k], **data[k]) for k in BUILTIN}
    IDS_VERSION += 1


IMAGES = {}


def product_image(query):
    """(page title, image bytes) of the best-matching Wikipedia article, or (None, None)."""
    if query not in IMAGES:
        IMAGES[query] = (None, None)
        try:
            q = urllib.parse.urlencode({'action': 'query', 'format': 'json', 'generator': 'search', 'gsrsearch': query,
                                        'gsrlimit': 1, 'prop': 'pageimages', 'piprop': 'thumbnail', 'pithumbsize': 600})
            pages = json.loads(fetch('https://en.wikipedia.org/w/api.php?' + q)).get('query', {}).get('pages', {})
            page = next(iter(pages.values()), {})
            src = page.get('thumbnail', {}).get('source')
            if src:
                IMAGES[query] = (page.get('title'), fetch(src))
        except (OSError, ValueError):
            IMAGES.pop(query)  # retry next time
            return None, None
    return IMAGES[query]


def details_text(d):
    i = d.ident()
    out = ['What it is: %s' % i['product'], 'Type: %s - %s' % CATS[i['category']],
           'How we know: %s (%s confidence)' % (i['why'], i['confidence'])]
    out += i['notes']
    if i['maker']:
        out.append('Maker: %s' % i['maker'])
    if d.source == 'ble':
        if d.name:
            out.append('Name it broadcasts: %s' % d.name)
        svcs = ['%s (%s)' % (IDS['uuid'].get(short_uuid(u), 'unregistered'), short_uuid(u))
                for u in sorted(set(map(short_uuid, d.services)) | set(map(short_uuid, d.sdata)))]
        if svcs:
            out.append('Advertises: ' + ', '.join(svcs))
        if d.tx is not None:
            out.append('Transmit power: %d dBm' % d.tx)
        if d.mfr:
            out.append('Maker data: ' + d.mfr.hex())
        out.append('First seen %s, last seen %s' % (time.strftime('%H:%M:%S', time.localtime(d.first)),
                                                     time.strftime('%H:%M:%S', time.localtime(d.last))))
        out.append('Bluetooth ID: %s\n(iOS gives each app its own ID per device, and many phones and trackers '
                   'change their address every few minutes, so one device can appear more than once.)' % d.key)
    else:
        w = d.wifi
        out.append('On your Wi-Fi: %s%s%s' % (w['ip'], ' / ' + w['mac'] if w.get('mac') else '',
                                              ' / ' + w['hostname'] if w.get('hostname') else ''))
        offers = list(w.get('services') or []) + ['port %d' % p for p in w.get('ports') or []]
        if offers:
            out.append('Offers: ' + ', '.join(offers))
        if w.get('web'):
            out.append('Web page: ' + w['web'])
    return '\n\n'.join(out)


def start_ble(on_state):
    """Scan for every Bluetooth LE advertiser through Apple's CoreBluetooth."""
    from objc_util import ObjCClass, ObjCInstance, create_objc_class, nsdata_to_bytes, ns
    try:
        from objc_util import load_framework
        load_framework('CoreBluetooth')
    except Exception:
        pass

    def obj(ad, key):
        v = ad.objectForKey_(key)
        return None if v is None else ObjCInstance(v)

    def centralManagerDidUpdateState_(_self, _cmd, central):
        mgr = ObjCInstance(central)
        state = int(mgr.state())
        on_state(state)
        if state == 5:  # powered on
            mgr.scanForPeripheralsWithServices_options_(None, ns({'kCBScanOptionAllowDuplicates': True}))

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(_self, _cmd, central, peripheral, adv, rssi):
        try:
            p, ad = ObjCInstance(peripheral), ObjCInstance(adv)
            name = obj(ad, 'kCBAdvDataLocalName') or p.name()
            mfr, svcs = obj(ad, 'kCBAdvDataManufacturerData'), obj(ad, 'kCBAdvDataServiceUUIDs')
            sd, tx = obj(ad, 'kCBAdvDataServiceData'), obj(ad, 'kCBAdvDataTxPowerLevel')
            record(str(p.identifier().UUIDString()), str(name) if name is not None else '',
                   nsdata_to_bytes(mfr) if mfr is not None else b'',
                   [str(u.UUIDString()) for u in svcs] if svcs is not None else [],
                   {str(k.UUIDString()): nsdata_to_bytes(sd.objectForKey_(k)) for k in sd.allKeys()} if sd is not None else {},
                   int(tx.intValue()) if tx is not None else None, int(ObjCInstance(rssi).intValue()))
        except Exception as e:
            print('Skipped one Bluetooth packet:', e)

    Delegate = create_objc_class('RadarCentral%d' % int(time.time() * 1000), methods=[
        centralManagerDidUpdateState_, centralManager_didDiscoverPeripheral_advertisementData_RSSI_],
        protocols=['CBCentralManagerDelegate'])
    delegate = Delegate.alloc().init()
    return ObjCClass('CBCentralManager').alloc().initWithDelegate_queue_(delegate, None), delegate


BT_STATES = {2: 'This device has no Bluetooth LE', 3: 'Bluetooth not allowed: Settings > Pythonista > Bluetooth',
             4: 'Bluetooth is off: turn it on in Control Center', 5: 'Bluetooth: scanning'}


def run_app():
    import ui, clipboard, console, webbrowser

    def row_detail(d, i):
        parts = [d.name] if d.name and d.name not in i['product'] else []
        parts += [i['maker'].split(',')[0]] if i['maker'] else []
        if d.source == 'ble' and d.rssi is not None:
            parts.append('%s, ~%s m (%d dBm)' % (proximity(d.rssi), distance_m(d.rssi), d.rssi))
            age = time.time() - d.last
            if age > 10:
                parts.append('seen %d s ago' % age)
        elif d.source == 'wifi':
            parts.append('Wi-Fi ' + d.wifi['ip'])
        return ' · '.join(parts)

    class Main(ui.View):
        def __init__(self):
            self.name, self.background_color = 'Radar', 'white'
            self.search = ui.TextField(placeholder='Search devices', clear_button_mode='while_editing',
                                       autocorrection_type=False, autocapitalization_type=ui.AUTOCAPITALIZE_NONE)
            self.search.delegate = self
            self.table = ui.TableView(row_height=60)
            self.table.data_source = self.table.delegate = self
            self.status = ui.Label(font=('<system>', 12), text_color='#666', number_of_lines=2, alignment=ui.ALIGN_CENTER)
            for v in (self.search, self.table, self.status):
                self.add_subview(v)
            self.right_button_items = [ui.ButtonItem(title='Scan Wi-Fi', action=self.scan_wifi)]
            self.sections, self.nav, self.ble = [], None, None
            self.bt_state, self.wifi_state = 'Bluetooth: starting', 'Wi-Fi: tap Scan Wi-Fi'

        def layout(self):
            w, h = self.width, self.height
            self.search.frame = (8, 8, w - 16, 34)
            self.table.frame = (0, 50, w, h - 94)
            self.status.frame = (8, h - 42, w - 16, 38)

        def textfield_did_change(self, tf):
            self.reload()

        def loop(self):
            if not self.nav.on_screen:  # app closed
                if self.ble:
                    self.ble[0].stopScan()
                return
            self.reload()
            ui.delay(self.loop, 1.5)

        def reload(self):
            q, now = self.search.text.strip().lower(), time.time()
            with LOCK:
                for k in [k for k, d in DEVICES.items() if d.source == 'ble' and now - d.last > 300]:
                    del DEVICES[k]
                devs = list(DEVICES.values())
            groups = {}
            for d in devs:
                i = d.ident()
                if d.source == 'ble' and now - d.last > 120:
                    continue
                if q and q not in ' '.join([d.name, i['product'], i['maker'], CATS[i['category']][0]]).lower():
                    continue
                groups.setdefault(i['category'], []).append(d)
            self.sections = [(k, sorted(groups[k], key=lambda d: -(d.rssi if d.rssi is not None else -200)))
                             for k in CATS if k in groups]
            self.table.reload_data()
            n = sum(1 for d in devs if d.source == 'ble' and now - d.last <= 120)
            self.status.text = '%s (%d devices)\n%s' % (self.bt_state, n, self.wifi_state)

        def tableview_number_of_sections(self, tv):
            return len(self.sections)

        def tableview_number_of_rows(self, tv, s):
            return len(self.sections[s][1])

        def tableview_title_for_header(self, tv, s):
            k, items = self.sections[s]
            return '%s (%d)' % (CATS[k][0], len(items))

        def tableview_cell_for_row(self, tv, s, r):
            d = self.sections[s][1][r]
            i = d.ident()
            c = ui.TableViewCell('subtitle')
            c.accessory_type = 'disclosure_indicator'
            c.text_label.text = i['product']
            c.text_label.text_color = '#d70015' if i['alert'] else 'black'
            c.detail_text_label.text = row_detail(d, i)
            return c

        def tableview_did_select(self, tv, s, r):
            self.nav.push_view(Detail(self.sections[s][1][r]))

        def scan_wifi(self, sender):
            sys.path.insert(0, HERE)
            try:
                import wifi_scanner
            except ImportError:
                self.wifi_state = 'Wi-Fi: wifi_scanner.py missing - run the install line again'
                return
            self.wifi_state = 'Wi-Fi: scanning your network (about 40 s)'

            def work():
                try:
                    res = wifi_scanner.scan()
                    with LOCK:
                        for w in res['devices']:
                            DEVICES['wifi:' + w['ip']] = wifi_device(w)
                    self.wifi_state = 'Wi-Fi: %d devices on %s' % (len(res['devices']), res['subnet'])
                except Exception as e:
                    self.wifi_state = 'Wi-Fi scan failed: %s' % e
            threading.Thread(target=work, daemon=True).start()

        def on_bt_state(self, state):
            self.bt_state = BT_STATES.get(state, 'Bluetooth: waiting')

    class Detail(ui.View):
        def __init__(self, d):
            self.d, i = d, d.ident()
            self.name, self.background_color = i['product'][:40], 'white'
            self.img = ui.ImageView(content_mode=ui.CONTENT_SCALE_ASPECT_FIT, background_color='#f2f2f7')
            self.cap = ui.Label(font=('<system>', 11), text_color='#888', alignment=ui.ALIGN_CENTER, number_of_lines=2)
            self.sig = ui.Label(font=('<system-bold>', 24))
            self.sub = ui.Label(font=('<system>', 13), text_color='#555', number_of_lines=2)
            self.bar_bg = ui.View(background_color='#e5e5ea', corner_radius=6)
            self.bar = ui.View(corner_radius=6)
            self.bar_bg.add_subview(self.bar)
            self.b1 = ui.Button(title='Search images', action=self.web, background_color='#007aff', tint_color='white', corner_radius=8)
            self.b2 = ui.Button(title='Copy details', action=self.copy, background_color='#e5e5ea', corner_radius=8)
            self.info = ui.TextView(editable=False, font=('<system>', 14))
            for v in (self.img, self.cap, self.sig, self.sub, self.bar_bg, self.b1, self.b2, self.info):
                self.add_subview(v)
            self.seen, self.ticks = False, 0
            if i['query']:
                self.cap.text = 'Looking for a picture...'
                threading.Thread(target=self.load_image, args=(i['query'],), daemon=True).start()
            else:
                self.cap.text = 'No picture: the exact model is not known. Tap Search images.'
            self.tick()

        def layout(self):
            w, y = self.width, 8
            for v, h in ((self.img, 190), (self.cap, 30), (self.sig, 32), (self.sub, 36), (self.bar_bg, 12)):
                v.frame = (12, y, w - 24, h)
                y += h + 4
            self.bar.height = 12
            self.b1.frame, self.b2.frame = (12, y + 6, (w - 32) / 2, 36), (w / 2 + 4, y + 6, (w - 32) / 2, 36)
            self.info.frame = (8, y + 50, w - 16, self.height - y - 54)
            self.show_signal()

        def load_image(self, query):
            title, data = product_image(query)
            if data:
                self.img.image = ui.Image.from_data(data)
                self.cap.text = 'Picture: Wikipedia, "%s" (may be a similar model)' % title
            else:
                self.cap.text = 'No picture found. Tap Search images.'

        def show_signal(self):
            d = self.d
            if d.source != 'ble' or d.rssi is None:
                self.sig.text = 'On your Wi-Fi network' if d.source == 'wifi' else 'No signal yet'
                self.sub.text = 'iPhones cannot measure Wi-Fi signal from other devices.' if d.source == 'wifi' else ''
                self.bar_bg.hidden = True
                return
            age = time.time() - d.last
            self.sig.text = '%d dBm%s' % (d.rssi, d.trend())
            self.sub.text = '%s, roughly %s m away%s. Walk around: higher number = closer.' % (
                proximity(d.rssi), distance_m(d.rssi), ' (last heard %d s ago)' % age if age > 5 else '')
            frac = max(0.03, min(1, (d.rssi + 100) / 60.0))
            self.bar.width = self.bar_bg.width * frac
            self.bar.background_color = '#34c759' if d.rssi >= -60 else '#ff9500' if d.rssi >= -75 else '#ff3b30'

        def tick(self):
            self.ticks += 1
            if self.on_screen:
                self.seen = True
            elif self.seen or self.ticks > 20:
                return
            self.show_signal()
            self.info.text = details_text(self.d)
            ui.delay(self.tick, 0.7)

        def web(self, sender):
            i = self.d.ident()
            q = i['query'] or ' '.join(filter(None, [i['maker'].split(',')[0], clean_name(self.d.name) if self.d.name else i['product']]))
            webbrowser.open('https://www.google.com/search?tbm=isch&q=' + urllib.parse.quote(q))

        def copy(self, sender):
            clipboard.set(details_text(self.d))
            console.hud_alert('Copied')

    threading.Thread(target=load_ids, daemon=True).start()
    main = Main()
    main.nav = ui.NavigationView(main)
    main.nav.present('fullscreen')
    main.ble = start_ble(main.on_bt_state)
    main.loop()


if __name__ == '__main__':
    try:
        import ui  # noqa: F401  (Pythonista only)
    except ImportError:
        sys.exit('Radar for iPhone runs inside the Pythonista app. On a computer, use wifi_scanner.py.')
    run_app()
