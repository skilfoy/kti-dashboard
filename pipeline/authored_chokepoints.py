"""Maritime oil-transit chokepoints for the map, with flows from the U.S. Energy Information Administration.

Source: EIA, "World Oil Transit Chokepoints" (special topics analysis, last updated March 3, 2026),
https://www.eia.gov/international/content/analysis/special_topics/World_Oil_Transit_Chokepoints
Flows are million barrels per day of crude oil and petroleum products; the Panama Canal is by U.S. fiscal year
(FY2025 in the 1H25 column), and the Turkish Straits figure is the Dardanelles. Shares are as EIA states them.
Coordinates are approximate positions of each passage for plotting, not survey points. theater_id links a
chokepoint to the theater whose escalation threatens it.
"""

EIA_URL = "https://www.eia.gov/international/content/analysis/special_topics/World_Oil_Transit_Chokepoints"


def cp(cid, name, lon, lat, f2023, f2024, f1h25, share, theater_id, note=""):
    return {"chokepoint_id": cid, "name": name, "lon": lon, "lat": lat, "flow_2023": f2023, "flow_2024": f2024,
            "flow_1h25": f1h25, "share": share, "theater_id": theater_id, "note": note,
            "source": "U.S. EIA, World Oil Transit Chokepoints (updated 2026-03-03)", "url": EIA_URL, "as_of": "2026-03-03"}


CHOKEPOINTS = [
    cp("CP-MAL", "Strait of Malacca", 101.4, 2.6, 24.0, 22.5, 23.2, "29% of total maritime oil flows in 1H25", "T-SCS"),
    cp("CP-HRM", "Strait of Hormuz", 56.4, 26.6, 21.8, 20.7, 20.9,
       "About 20% of global petroleum liquids consumption; one-quarter of maritime traded oil in 1H25", "T-HRM"),
    cp("CP-SUZ", "Suez Canal and SUMED Pipeline", 32.35, 30.6, 8.8, 4.8, 4.9,
       "With Bab el-Mandeb, about 6% of seaborne-traded oil in 1H25", "T-RSY",
       "1H25 flows about half of 2023 after Houthi attacks on Red Sea shipping began in November 2023"),
    cp("CP-BAB", "Bab el-Mandeb", 43.4, 12.6, 9.3, 4.1, 4.2,
       "With Suez and SUMED, about 6% of seaborne-traded oil in 1H25", "T-RSY",
       "1H25 flows about half of 2023 after Houthi attacks on Red Sea shipping began in November 2023"),
    cp("CP-DAN", "Danish Straits", 11.5, 55.5, 5.0, 4.9, 4.9, "6% of global maritime oil trade in 1H25", "T-EUH"),
    cp("CP-TUR", "Turkish Straits (Dardanelles)", 26.4, 40.2, 3.5, 3.6, 3.7, "5% of global maritime oil trade in 1H25", "T-UKR"),
    cp("CP-PAN", "Panama Canal", -79.7, 9.1, 2.2, 2.0, 2.3, "3% of global maritime petroleum and product flows in FY2025", "",
       "Fiscal-year figures (October to September); the 1H25 column holds FY2025"),
    cp("CP-CGH", "Cape of Good Hope", 18.5, -34.4, 6.2, 9.3, 9.1, "11% of seaborne-traded oil in 1H25", "T-RSY",
       "Rerouting around the Cape rose as Red Sea transits fell"),
]
