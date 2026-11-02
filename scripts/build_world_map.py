#!/usr/bin/env python3
"""Build static/world-110m.json, the Traffic Map's world, from two vendored sources.

Usage: build_world_map.py <world-atlas countries-110m.json> <i18n-iso-countries langs/en.json> <out>

world-atlas's TopoJSON (Natural Earth 1:110m, public domain) keys each
country by its ISO 3166-1 numeric code; this rekeys them by alpha-2 - the
codes geo_lookup.py returns - and drops Antarctica, which the map leaves
out. It adds the English names of every code (from i18n-iso-countries)
and a point for each place too small to have a shape at 1:110m, so their
traffic still has somewhere to land. See AGENTS.md's "Updating Vendored
Dependencies" for where the sources come from.
"""

import json
import sys

# ISO 3166-1 numeric -> alpha-2, for the codes world-atlas uses.
# Features with no numeric id are matched by Natural Earth's name.
NAME_TO_CC = {'Kosovo': 'XK', 'N. Cyprus': 'CY', 'Somaliland': 'SO'}

# [longitude, latitude] of places DB-IP can return that have no shape at 1:110m
PLACES = {
    'AD': [1.52, 42.55], 'AG': [-61.8, 17.07], 'AI': [-63.05, 18.22], 'AS': [-170.7, -14.3],
    'AW': [-69.97, 12.52], 'AX': [19.95, 60.2], 'BB': [-59.54, 13.19], 'BH': [50.56, 26.07],
    'BL': [-62.83, 17.9], 'BM': [-64.78, 32.3], 'BQ': [-68.27, 12.18], 'BV': [3.4, -54.42],
    'CC': [96.87, -12.17], 'CK': [-159.78, -21.24], 'CV': [-23.6, 15.12], 'CW': [-68.99, 12.17],
    'CX': [105.69, -10.49], 'DM': [-61.37, 15.41], 'FM': [158.2, 6.9], 'FO': [-6.91, 61.89],
    'GD': [-61.68, 12.12], 'GF': [-53.1, 3.93], 'GG': [-2.58, 49.45], 'GI': [-5.35, 36.14],
    'GP': [-61.55, 16.25], 'GS': [-36.6, -54.4], 'GU': [144.79, 13.44], 'HK': [114.17, 22.32],
    'HM': [73.5, -53.1], 'IM': [-4.55, 54.24], 'IO': [72.4, -7.3], 'JE': [-2.13, 49.21],
    'KI': [173.0, 1.42], 'KM': [43.87, -11.88], 'KN': [-62.78, 17.36], 'KY': [-81.25, 19.31],
    'LC': [-60.98, 13.91], 'LI': [9.55, 47.16], 'MC': [7.42, 43.74], 'MF': [-63.08, 18.07],
    'MH': [171.18, 7.1], 'MO': [113.55, 22.19], 'MP': [145.7, 15.1], 'MQ': [-61.0, 14.64],
    'MS': [-62.19, 16.74], 'MT': [14.45, 35.9], 'MU': [57.55, -20.3], 'MV': [73.22, 3.2],
    'NF': [167.95, -29.04], 'NR': [166.93, -0.52], 'NU': [-169.87, -19.05], 'PF': [-149.4, -17.65],
    'PM': [-56.3, 46.9], 'PN': [-130.1, -25.07], 'PW': [134.58, 7.51], 'RE': [55.53, -21.12],
    'SC': [55.45, -4.68], 'SG': [103.82, 1.35], 'SH': [-5.7, -15.95], 'SJ': [15.6, 78.2],
    'SM': [12.46, 43.94], 'ST': [6.61, 0.19], 'SX': [-63.05, 18.04], 'TC': [-71.8, 21.8],
    'TK': [-171.85, -9.2], 'TO': [-175.2, -21.18], 'TV': [179.2, -8.52], 'UM': [-177.4, 28.2],
    'VA': [12.45, 41.9], 'VC': [-61.2, 13.25], 'VG': [-64.62, 18.42], 'VI': [-64.9, 18.34],
    'WF': [-176.2, -13.29], 'WS': [-172.1, -13.76], 'YT': [45.17, -12.83],
}

# i18n-iso-countries has no numeric codes in langs/en.json, so they're here.
NUMERIC = {
    '004': 'AF', '008': 'AL', '010': 'AQ', '012': 'DZ', '016': 'AS', '020': 'AD', '024': 'AO', '028': 'AG', '031': 'AZ',
    '032': 'AR', '036': 'AU', '040': 'AT', '044': 'BS', '048': 'BH', '050': 'BD', '051': 'AM', '052': 'BB', '056': 'BE',
    '060': 'BM', '064': 'BT', '068': 'BO', '070': 'BA', '072': 'BW', '074': 'BV', '076': 'BR', '084': 'BZ', '086': 'IO',
    '090': 'SB', '092': 'VG', '096': 'BN', '100': 'BG', '104': 'MM', '108': 'BI', '112': 'BY', '116': 'KH', '120': 'CM',
    '124': 'CA', '132': 'CV', '136': 'KY', '140': 'CF', '144': 'LK', '148': 'TD', '152': 'CL', '156': 'CN', '158': 'TW',
    '162': 'CX', '166': 'CC', '170': 'CO', '174': 'KM', '175': 'YT', '178': 'CG', '180': 'CD', '184': 'CK', '188': 'CR',
    '191': 'HR', '192': 'CU', '196': 'CY', '203': 'CZ', '204': 'BJ', '208': 'DK', '212': 'DM', '214': 'DO', '218': 'EC',
    '222': 'SV', '226': 'GQ', '231': 'ET', '232': 'ER', '233': 'EE', '234': 'FO', '238': 'FK', '239': 'GS', '242': 'FJ',
    '246': 'FI', '248': 'AX', '250': 'FR', '254': 'GF', '258': 'PF', '260': 'TF', '262': 'DJ', '266': 'GA', '268': 'GE',
    '270': 'GM', '275': 'PS', '276': 'DE', '288': 'GH', '292': 'GI', '296': 'KI', '300': 'GR', '304': 'GL', '308': 'GD',
    '312': 'GP', '316': 'GU', '320': 'GT', '324': 'GN', '328': 'GY', '332': 'HT', '334': 'HM', '336': 'VA', '340': 'HN',
    '344': 'HK', '348': 'HU', '352': 'IS', '356': 'IN', '360': 'ID', '364': 'IR', '368': 'IQ', '372': 'IE', '376': 'IL',
    '380': 'IT', '384': 'CI', '388': 'JM', '392': 'JP', '398': 'KZ', '400': 'JO', '404': 'KE', '408': 'KP', '410': 'KR',
    '414': 'KW', '417': 'KG', '418': 'LA', '422': 'LB', '426': 'LS', '428': 'LV', '430': 'LR', '434': 'LY', '438': 'LI',
    '440': 'LT', '442': 'LU', '446': 'MO', '450': 'MG', '454': 'MW', '458': 'MY', '462': 'MV', '466': 'ML', '470': 'MT',
    '474': 'MQ', '478': 'MR', '480': 'MU', '484': 'MX', '492': 'MC', '496': 'MN', '498': 'MD', '499': 'ME', '500': 'MS',
    '504': 'MA', '508': 'MZ', '512': 'OM', '516': 'NA', '520': 'NR', '524': 'NP', '528': 'NL', '531': 'CW', '533': 'AW',
    '534': 'SX', '535': 'BQ', '540': 'NC', '548': 'VU', '554': 'NZ', '558': 'NI', '562': 'NE', '566': 'NG', '570': 'NU',
    '574': 'NF', '578': 'NO', '580': 'MP', '581': 'UM', '583': 'FM', '584': 'MH', '585': 'PW', '586': 'PK', '591': 'PA',
    '598': 'PG', '600': 'PY', '604': 'PE', '608': 'PH', '612': 'PN', '616': 'PL', '620': 'PT', '624': 'GW', '626': 'TL',
    '630': 'PR', '634': 'QA', '638': 'RE', '642': 'RO', '643': 'RU', '646': 'RW', '652': 'BL', '654': 'SH', '659': 'KN',
    '660': 'AI', '662': 'LC', '663': 'MF', '666': 'PM', '670': 'VC', '674': 'SM', '678': 'ST', '682': 'SA', '686': 'SN',
    '688': 'RS', '690': 'SC', '694': 'SL', '702': 'SG', '703': 'SK', '704': 'VN', '705': 'SI', '706': 'SO', '710': 'ZA',
    '716': 'ZW', '724': 'ES', '728': 'SS', '729': 'SD', '732': 'EH', '740': 'SR', '744': 'SJ', '748': 'SZ', '752': 'SE',
    '756': 'CH', '760': 'SY', '762': 'TJ', '764': 'TH', '768': 'TG', '772': 'TK', '776': 'TO', '780': 'TT', '784': 'AE',
    '788': 'TN', '792': 'TR', '795': 'TM', '796': 'TC', '798': 'TV', '800': 'UG', '804': 'UA', '807': 'MK', '818': 'EG',
    '826': 'GB', '831': 'GG', '832': 'JE', '833': 'IM', '834': 'TZ', '840': 'US', '850': 'VI', '854': 'BF', '858': 'UY',
    '860': 'UZ', '862': 'VE', '876': 'WF', '882': 'WS', '887': 'YE', '894': 'ZM',
}


def build(atlas_path, names_path, out_path):
    with open(atlas_path) as f:
        topo = json.load(f)
    with open(names_path) as f:
        names = json.load(f)['countries']
    names = {cc: (n if isinstance(n, str) else n[0]) for cc, n in names.items()}
    names['XK'] = 'Kosovo'
    kept = []
    for g in topo['objects']['countries']['geometries']:
        cc = NUMERIC.get(g.get('id')) or NAME_TO_CC.get(g.get('properties', {}).get('name'))
        if not cc:
            raise ValueError(f'no code for {g.get("id")} {g.get("properties")}')
        if cc == 'AQ':
            continue
        kept.append({k: v for k, v in g.items() if k not in ('id', 'properties')} | {'id': cc})
    topo['objects'] = {'countries': {'type': 'GeometryCollection', 'geometries': kept}}
    shaped = {g['id'] for g in kept}
    topo['places'] = {cc: ll for cc, ll in PLACES.items() if cc not in shaped}
    topo['names'] = dict(sorted(names.items()))
    with open(out_path, 'w') as f:
        json.dump(topo, f, separators=(',', ':'))
    # arcs keep a world-atlas topology's shared borders, so dropping Antarctica's
    # geometry leaves its arcs in place - harmless, a few KB
    return len(kept), len(topo['places'])


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(__doc__.split('\n\n')[1])
    shapes, places = build(*sys.argv[1:4])
    print(f'world map: {shapes} country shapes, {places} points')
