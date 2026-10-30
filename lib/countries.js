// Point-in-country lookup on the world-atlas 50m boundaries (bundled), returning ISO 3166-1 alpha-2.
// Planar ray casting on lon/lat with a bounding-box prefilter. GDELT and IP geocodes often sit on a coastline
// (Beirut, Gaza, Odesa, Hodeidah) where a generalized boundary leaves them just offshore, so a point inside no
// polygon takes the nearest country whose boundary lies within NEAR_DEG (about 40 km). Results are memoized
// on a 0.01-degree grid because geocoders repeat the same feature coordinates thousands of times.
const topo = require('world-atlas/countries-50m.json');
const num2iso = require('./num2iso.json');
const { feature } = require('topojson-client');

const NAMED = { Kosovo: 'XK', Somaliland: 'SO', 'N. Cyprus': 'CY' };
const NEAR_DEG = 0.36;
let index = null;
const memo = new Map();

function build() {
  const fc = feature(topo, topo.objects.countries);
  index = [];
  for (const f of fc.features) {
    const iso = f.id != null ? num2iso[String(+f.id)] : NAMED[f.properties && f.properties.name];
    if (!iso || !f.geometry) continue;
    const polys = f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
    for (const rings of polys) {
      let x0 = 180, x1 = -180, y0 = 90, y1 = -90;
      for (const [x, y] of rings[0]) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
      index.push({ iso, rings, x0, x1, y0, y1 });
    }
  }
}

function inRing(x, y, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
    if (((yi > y) !== (yj > y)) && (x < ((xj - xi) * (y - yi)) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}

// Squared distance in degrees from (x, y) to a ring, longitude scaled by cos(latitude).
function ringDist2(x, y, ring, kx) {
  let best = Infinity;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const ax = ring[j][0] * kx, ay = ring[j][1], bx = ring[i][0] * kx, by = ring[i][1], px = x * kx;
    const dx = bx - ax, dy = by - ay, l2 = dx * dx + dy * dy;
    let t = l2 ? ((px - ax) * dx + (y - ay) * dy) / l2 : 0;
    t = t < 0 ? 0 : t > 1 ? 1 : t;
    const ex = ax + t * dx - px, ey = ay + t * dy - y, d2 = ex * ex + ey * ey;
    if (d2 < best) best = d2;
  }
  return best;
}

function lookup(lon, lat) {
  for (const p of index) {
    if (lon < p.x0 || lon > p.x1 || lat < p.y0 || lat > p.y1) continue;
    if (!inRing(lon, lat, p.rings[0])) continue;
    let hole = false;
    for (let k = 1; k < p.rings.length; k++) if (inRing(lon, lat, p.rings[k])) { hole = true; break; }
    if (!hole) return p.iso;
  }
  const kx = Math.cos((lat * Math.PI) / 180);
  let best = '', bd = NEAR_DEG * NEAR_DEG;
  for (const p of index) {
    if (lon < p.x0 - NEAR_DEG / Math.max(kx, 0.2) || lon > p.x1 + NEAR_DEG / Math.max(kx, 0.2) || lat < p.y0 - NEAR_DEG || lat > p.y1 + NEAR_DEG) continue;
    const d = ringDist2(lon, lat, p.rings[0], kx);
    if (d < bd) { bd = d; best = p.iso; }
  }
  return best;
}

function isoAt(lon, lat) {
  if (!isFinite(lon) || !isFinite(lat)) return '';
  if (!index) build();
  const k = Math.round(lon * 100) + ',' + Math.round(lat * 100);
  let v = memo.get(k);
  if (v === undefined) {
    v = lookup(lon, lat);
    if (memo.size > 200000) memo.clear();
    memo.set(k, v);
  }
  return v;
}

module.exports = { isoAt };
