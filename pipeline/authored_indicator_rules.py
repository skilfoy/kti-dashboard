#!/usr/bin/env python3
"""Measurable rules for the theater warning indicators: which live measurement can show each indicator moving, at what
threshold, and whether the measurement is the indicator itself (Direct) or a stand-in for it (Proxy). The page
evaluates every rule against the live feeds and proposes state changes; a proposal changes nothing until the analyst
applies it in theater_indicators during the daily reassessment (Suryavanshi ch4: specific, leading, measurable
indicators judged on consistency and momentum; Arici 3.5.2: corroboration only across independent collection).

An analyst-set lens, like the vertical weights: the daily run carries it unchanged and Sean changes it.
Indicators no live feed can measure (statements, prices, sorties, sabotage) carry no rule and stay analyst-judged.
Run: python3 -I authored_indicator_rules.py OUT
"""
import json
import os
import sys

OUT = sys.argv[1]
# (ind_id, metric, threshold, scope, kind, why)
# metric: gdelt_ratio, lanes_delta7, fires_ratio, fires_novel, outages_72h (IODA warning or critical), outages_alert
#         (IODA critical), maritime_incidents_30d,
#         maritime_hostile, maritime_mines, maritime_military, ofac_designations_14d, ofac_removals_14d, ofac_gl_14d
# scope: the theater, or a comma list of ISO country codes for the internet-measurement metrics
R = [
    ("W-HRM-1", "maritime_incidents_30d", 43, None, "Proxy", "Ten attacks a week is about 43 in 30 days; NGA ASAM records piracy and robbery, and UKMTO, which records attacks on shipping, refuses automated collection."),
    ("W-HRM-1", "maritime_hostile", 1, None, "Proxy", "Navigational warnings naming hostile activity in the theater's waters."),
    ("W-HRM-2", "maritime_mines", 1, None, "Proxy", "Navigational warnings naming mines in the theater's waters."),
    ("W-HRM-6", "ofac_removals_14d", 1, None, "Proxy", "OFAC removals under the theater's programs; removals are also routine, so a hit needs reading."),
    ("W-HRM-6", "ofac_gl_14d", 1, None, "Proxy", "OFAC general licenses under the theater's programs authorize otherwise barred dealings."),
    ("W-RSY-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Yemen and Saudi Arabia at 1.5 times the 48-hour rate."),
    ("W-RSY-3", "fires_novel", 1, None, "Proxy", "New thermal anomalies (no detection in the 30 days before) in the theater's area; a strike on a terminal burns, so do gas flares."),
    ("W-RSY-3", "fires_ratio", 1.5, None, "Proxy", "Yesterday's VIIRS detections at 1.5 times the area's daily median."),
    ("W-LEV-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Lebanon, Israel and Syria at 1.5 times the 48-hour rate."),
    ("W-LEV-1", "lanes_delta7", 0.05, None, "Proxy", "Lanes temperature of the theater's pairs up 0.05 or more week on week, above the 0.3 amber line. Lanes derives from GDELT, so it corroborates nothing GDELT shows."),
    ("W-LEV-1", "fires_novel", 1, None, "Proxy", "New thermal anomalies in the Levant area."),
    ("W-UKR-1", "fires_novel", 3, None, "Proxy", "Three or more new thermal anomalies in the Russia and Ukraine area; refinery fires are large and persistent."),
    ("W-UKR-1", "fires_ratio", 1.5, None, "Proxy", "Yesterday's VIIRS detections at 1.5 times the area's daily median."),
    ("W-UKR-3", "outages_alert", 1, "UA", "Proxy", "An IODA outage rated critical in Ukraine; outages have many causes, a destructive attack on the grid among them."),
    ("W-UKR-3", "outages_72h", 3, "UA", "Proxy", "Three or more IODA outage events rated warning or critical in Ukraine in 72 hours."),
    ("W-TWN-1", "maritime_military", 1, None, "Proxy", "Navigational warnings for military exercises or firing in the theater's waters; named PLA exercises close sea areas by warning."),
    ("W-TWN-1", "lanes_delta7", 0.05, None, "Proxy", "Lanes China-Taiwan temperature up 0.05 or more week on week, above the 0.3 amber line."),
    ("W-SCS-3", "maritime_military", 1, None, "Proxy", "Navigational warnings for military or law-enforcement operations in the South China Sea and Luzon Strait."),
    ("W-SCS-4", "maritime_military", 1, None, "Proxy", "Navigational warnings for military operations near Philippine features."),
    ("W-KOR-1", "maritime_military", 1, None, "Proxy", "Navigational warnings for rocket or missile hazard areas around the Korean Peninsula."),
    ("W-SAS-3", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across India and Pakistan at 1.5 times the 48-hour rate."),
    ("W-SAS-3", "lanes_delta7", 0.05, None, "Proxy", "Lanes India-Pakistan temperature up 0.05 or more week on week, above the 0.3 amber line."),
    ("W-SAS-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across India and Pakistan at 1.5 times the 48-hour rate."),
    ("W-AFP-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Afghanistan and Pakistan at 1.5 times the 48-hour rate."),
    ("W-AFP-1", "lanes_delta7", 0.05, None, "Proxy", "Lanes Afghanistan-Pakistan temperature up 0.05 or more week on week, above the 0.3 amber line."),
    ("W-AFP-1", "fires_novel", 1, None, "Proxy", "New thermal anomalies along the Af-Pak area."),
    ("W-AFP-2", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Afghanistan and Pakistan at 1.5 times the 48-hour rate."),
    ("W-SAH-2", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Mali, Burkina Faso and Niger at 1.5 times the 48-hour rate."),
    ("W-SAH-2", "outages_alert", 1, "ML", "Proxy", "An IODA outage rated critical in Mali."),
    ("W-SAH-1", "fires_novel", 1, None, "Proxy", "New thermal anomalies in the Sahel area; burning convoys show as hot spots, so does seasonal burning."),
    ("W-SDN-2", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events in Sudan at 1.5 times the 48-hour rate."),
    ("W-SDN-2", "fires_novel", 3, None, "Proxy", "Three or more new thermal anomalies in the Sudan area; village burnings show as hot spots, so does agricultural burning."),
    ("W-SDN-2", "outages_alert", 1, "SD", "Proxy", "An IODA outage rated critical in Sudan."),
    ("W-HOA-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Ethiopia, Eritrea, Somalia and Egypt at 1.5 times the 48-hour rate."),
    ("W-HOA-1", "outages_alert", 1, "ET", "Proxy", "An IODA outage rated critical in Ethiopia, which has cut connectivity in Tigray during offensives."),
    ("W-HOA-1", "fires_novel", 3, None, "Proxy", "Three or more new thermal anomalies in the Horn of Africa area."),
    ("W-BAL-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Serbia, Kosovo and Bosnia at 1.5 times the 48-hour rate."),
    ("W-CAS-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events across Central Asia at 1.5 times the 48-hour rate."),
    ("W-CAS-1", "outages_alert", 1, "KZ,KG,TJ,UZ", "Proxy", "An IODA outage rated critical in Central Asia, where governments have cut connectivity during unrest."),
    ("W-VEN-1", "ofac_removals_14d", 1, None, "Proxy", "OFAC removals under the Venezuela program; removals are also routine, so a hit needs reading."),
    ("W-VEN-1", "ofac_gl_14d", 1, None, "Direct", "OFAC general licenses under the Venezuela program are sanctions relief."),
    ("W-VEN-2", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events in Venezuela at 1.5 times the 48-hour rate."),
    ("W-VEN-2", "outages_alert", 1, "VE", "Proxy", "An IODA outage rated critical in Venezuela."),
    ("W-MEX-1", "gdelt_ratio", 1.5, None, "Proxy", "Armed-conflict events in Mexico at 1.5 times the 48-hour rate."),
    ("W-MEX-2", "ofac_designations_14d", 1, None, "Direct", "An OFAC action adding SDN entries under a program tied to Mexican cartels."),
]
FAMILY = {"gdelt": "Press events (GDELT)", "lanes": "Press events (GDELT)", "fires": "Satellite thermal (FIRMS)", "outages": "Internet measurement (IODA)",
          "maritime": "Maritime notices (NGA, MARAD, UKMTO)", "ofac": "Sanctions actions (OFAC)"}
ind = {r["ind_id"]: r for r in json.load(open(os.path.join(OUT, "theater_indicators.json")))}
rows, n = [], {}
for ind_id, metric, thr, scope, kind, why in R:
    if ind_id not in ind:
        raise SystemExit(f"{ind_id} is not in theater_indicators")
    n[ind_id] = n.get(ind_id, 0) + 1
    rows.append({"rule_id": f"{ind_id}.{n[ind_id]}", "ind_id": ind_id, "theater_id": ind[ind_id]["theater_id"], "metric": metric, "threshold": thr,
                 "scope": scope, "family": FAMILY[metric.split("_")[0]], "kind": kind, "rationale": why})
json.dump(rows, open(os.path.join(OUT, "indicator_rules.json"), "w"), indent=1, ensure_ascii=False)
print(len(rows), "rules for", len(n), "of", len(ind), "indicators")
