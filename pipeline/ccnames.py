# Short English country names for the ISO 3166-1 alpha-2 codes the dashboard's atlas uses (lib/num2iso.json plus XK),
# from pycountry's common_name/name with the formal "X, Republic of" forms rewritten to the names newsrooms use.
# Prints the compact 'CC:Name/Alt|...' table that neon/parts/35-cyber.mjs embeds as CA_NAMES.
# python3 -I build/ccnames.py threat-feeds/lib/num2iso.json
import json, sys, pycountry
codes = sorted(set(json.load(open(sys.argv[1])).values()) | {'XK'})
OVR = {
 'BO': 'Bolivia', 'BQ': 'Caribbean Netherlands', 'BN': 'Brunei', 'CD': 'DR Congo/Democratic Republic of the Congo', 'CG': 'Republic of the Congo/Congo',
 'CI': "Ivory Coast/Cote d'Ivoire", 'CV': 'Cape Verde/Cabo Verde', 'CZ': 'Czechia/Czech Republic', 'FK': 'Falkland Islands', 'FM': 'Micronesia',
 'GB': 'United Kingdom/Britain', 'IR': 'Iran', 'KP': 'North Korea', 'KR': 'South Korea', 'LA': 'Laos', 'MD': 'Moldova', 'MK': 'North Macedonia',
 'MM': 'Myanmar/Burma', 'PS': 'Palestine', 'RU': 'Russia', 'SH': 'Saint Helena', 'SY': 'Syria', 'SZ': 'Eswatini/Swaziland', 'TR': 'Turkey/Turkiye',
 'TW': 'Taiwan', 'TZ': 'Tanzania', 'US': 'United States', 'VA': 'Vatican City', 'VE': 'Venezuela', 'VG': 'British Virgin Islands',
 'VI': 'US Virgin Islands', 'VN': 'Vietnam', 'XK': 'Kosovo', 'CC': 'Cocos Islands', 'SX': 'Sint Maarten', 'MF': 'Saint Martin', 'HM': 'Heard and McDonald Islands',
 'UM': 'US Minor Outlying Islands', 'IO': 'British Indian Ocean Territory', 'PN': 'Pitcairn Islands', 'KN': 'Saint Kitts and Nevis',
 'VC': 'Saint Vincent and the Grenadines', 'LC': 'Saint Lucia', 'PM': 'Saint Pierre and Miquelon', 'BL': 'Saint Barthelemy', 'NL': 'Netherlands',
 'AE': 'United Arab Emirates', 'DO': 'Dominican Republic', 'CF': 'Central African Republic', 'TL': 'Timor-Leste/East Timor', 'CW': 'Curacao',
 'RE': 'Reunion', 'AX': 'Aland Islands', 'SJ': 'Svalbard and Jan Mayen', 'TF': 'French Southern Territories', 'GS': 'South Georgia and the South Sandwich Islands',
}
out, miss = [], []
for c in codes:
    if c in OVR: out.append(f'{c}:{OVR[c]}'); continue
    p = pycountry.countries.get(alpha_2=c)
    if not p: miss.append(c); continue
    n = getattr(p, 'common_name', None) or p.name
    if ',' in n or '(' in n: miss.append(c + '=' + n)
    out.append(f'{c}:{n}')
s = '|'.join(out)
import unicodedata
s2 = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode()
print('codes', len(codes), 'bytes', len(s2), 'needs review:', miss)
print(s2)
