/**
 * Australian Cyber Threat Landscape - Dashboard Charts
 * Uses Chart.js to render interactive charts from JSON data.
 */

const CHART_COLORS = {
  teal: '#00bfa5',
  cyan: '#00e5ff',
  red: '#f44336',
  orange: '#ff9800',
  yellow: '#ffc107',
  green: '#4caf50',
  blue: '#2196f3',
  purple: '#9c27b0',
  pink: '#e91e63',
  indigo: '#3f51b5',
  grey: '#9e9e9e',
};

const PALETTE = [
  CHART_COLORS.teal, CHART_COLORS.cyan, CHART_COLORS.blue,
  CHART_COLORS.purple, CHART_COLORS.pink, CHART_COLORS.red,
  CHART_COLORS.orange, CHART_COLORS.yellow, CHART_COLORS.green,
  CHART_COLORS.indigo, CHART_COLORS.grey,
];

// Detect dark mode
function isDarkMode() {
  return document.body.getAttribute('data-md-color-scheme') === 'slate' ||
    window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function chartTextColor() {
  return isDarkMode() ? '#ccc' : '#333';
}

function chartGridColor() {
  return isDarkMode() ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
}

// Common chart options
function baseOptions(title) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      title: {
        display: !!title,
        text: title || '',
        color: chartTextColor(),
        font: { size: 14, family: 'Inter' },
      },
      legend: {
        labels: { color: chartTextColor(), font: { family: 'Inter' } }
      }
    },
    scales: {
      x: {
        ticks: { color: chartTextColor() },
        grid: { color: chartGridColor() }
      },
      y: {
        ticks: { color: chartTextColor() },
        grid: { color: chartGridColor() }
      }
    }
  };
}

// Load JSON data file.
// Uses absolute path from the site root so it works regardless of page depth.
// The base path is derived from the <link rel="canonical"> tag that MkDocs
// Material injects on every page, falling back to the script src attribute.
function getSiteRoot() {
  // Method 1: canonical link (MkDocs Material always sets this from site_url)
  const canonical = document.querySelector('link[rel="canonical"]');
  if (canonical) {
    try {
      const href = canonical.getAttribute('href');
      const url = new URL(href);
      // e.g. /cyber-landscape-au/threats/advisories/ -> extract /cyber-landscape-au/
      const match = url.pathname.match(/^(\/[^/]+\/)/);
      if (match) return match[1];
    } catch (e) { /* fall through */ }
  }
  // Method 2: script src attribute
  const scripts = document.querySelectorAll('script[src]');
  for (const s of scripts) {
    const src = s.getAttribute('src');
    if (src && src.includes('dashboard.js')) {
      const idx = src.indexOf('assets/js/dashboard.js');
      if (idx >= 0) return src.substring(0, idx) || './';
    }
  }
  return '/cyber-landscape-au/';
}

async function loadData(filename) {
  const root = getSiteRoot();
  const candidates = [
    `${root}assets/data/${filename}`,
    `/assets/data/${filename}`,
    `/cyber-landscape-au/assets/data/${filename}`,
    new URL(`assets/data/${filename}`, window.location.href).toString(),
  ];

  for (const url of [...new Set(candidates)]) {
    try {
      const resp = await fetch(url, { cache: 'no-cache' });
      if (resp.ok) return await resp.json();
    } catch (e) {
      // Continue trying fallback URLs.
    }
  }

  console.warn(`Could not load ${filename} from any known path`, candidates);
  return null;
}

// ---------------------------------------------------------------------------
// NDB Trend Chart (index page and NDB stats page)
// ---------------------------------------------------------------------------
async function renderNdbTrendChart(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  const data = await loadData('ndb.json');
  if (!data || !data.trend_summary) return;

  const trend = data.trend_summary.reverse(); // chronological
  const labels = trend.map(t => t.period);

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Malicious Attacks',
          data: trend.map(t => t.malicious),
          backgroundColor: CHART_COLORS.red + '99',
          borderColor: CHART_COLORS.red,
          borderWidth: 1,
        },
        {
          label: 'Human Error',
          data: trend.map(t => t.human_error),
          backgroundColor: CHART_COLORS.orange + '99',
          borderColor: CHART_COLORS.orange,
          borderWidth: 1,
        },
        {
          label: 'System Faults',
          data: trend.map(t => t.system_faults),
          backgroundColor: CHART_COLORS.blue + '99',
          borderColor: CHART_COLORS.blue,
          borderWidth: 1,
        },
      ]
    },
    options: {
      ...baseOptions('Notifiable Data Breaches by Cause'),
      scales: {
        x: {
          stacked: true,
          ticks: { color: chartTextColor() },
          grid: { color: chartGridColor() }
        },
        y: {
          stacked: true,
          ticks: { color: chartTextColor() },
          grid: { color: chartGridColor() },
          title: { display: true, text: 'Notifications', color: chartTextColor() }
        }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// KEV Vendor Chart (vulnerabilities page)
// ---------------------------------------------------------------------------
async function renderKevVendorChart() {
  const canvas = document.getElementById('kevVendorChart');
  if (!canvas) return;

  const data = await loadData('vulnerabilities.json');
  if (!data || !data.kev) return;

  const vendors = data.kev.top_vendors || [];
  const labels = vendors.map(v => v.vendor);
  const counts = vendors.map(v => v.count);

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Exploited CVEs',
        data: counts,
        backgroundColor: PALETTE.slice(0, labels.length).map(c => c + '99'),
        borderColor: PALETTE.slice(0, labels.length),
        borderWidth: 1,
      }]
    },
    options: {
      ...baseOptions('Top Vendors in CISA KEV'),
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        title: { display: true, text: 'Top Vendors in CISA KEV', color: chartTextColor() }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// CVE Severity Chart (vulnerabilities page)
// ---------------------------------------------------------------------------
async function renderCveSeverityChart() {
  const canvas = document.getElementById('cveSeverityChart');
  if (!canvas) return;

  const data = await loadData('vulnerabilities.json');
  if (!data || !data.recent_cves) return;

  const dist = data.recent_cves.severity_distribution || {};
  const severityColors = {
    'CRITICAL': CHART_COLORS.red,
    'HIGH': CHART_COLORS.orange,
    'MEDIUM': CHART_COLORS.yellow,
    'LOW': CHART_COLORS.green,
    'UNKNOWN': CHART_COLORS.grey,
  };

  const labels = Object.keys(dist);
  const values = Object.values(dist);
  const colors = labels.map(l => severityColors[l] || CHART_COLORS.grey);

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + 'cc'),
        borderColor: colors,
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        title: { display: true, text: 'CVE Severity Distribution (14 Days)', color: chartTextColor() },
        legend: { position: 'right', labels: { color: chartTextColor() } }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// URLhaus Threat Chart (malware page)
// ---------------------------------------------------------------------------
async function renderUrlhausThreatChart() {
  const canvas = document.getElementById('urlhausThreatChart');
  if (!canvas) return;

  const data = await loadData('threats.json');
  if (!data || !data.analysis || !data.analysis.urlhaus) return;

  const threats = data.analysis.urlhaus.threat_types || {};
  const labels = Object.keys(threats);
  const values = Object.values(threats);

  new Chart(canvas, {
    type: 'pie',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: PALETTE.slice(0, labels.length).map(c => c + 'cc'),
        borderColor: PALETTE.slice(0, labels.length),
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        title: { display: true, text: 'URLhaus Threat Types', color: chartTextColor() },
        legend: { position: 'right', labels: { color: chartTextColor() } }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Malware File Type Chart (malware page)
// ---------------------------------------------------------------------------
async function renderMalwareFileTypeChart() {
  const canvas = document.getElementById('malwareFileTypeChart');
  if (!canvas) return;

  const data = await loadData('threats.json');
  if (!data || !data.analysis || !data.analysis.malwarebazaar) return;

  const types = data.analysis.malwarebazaar.file_types || {};
  const labels = Object.keys(types);
  const values = Object.values(types);

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Samples',
        data: values,
        backgroundColor: CHART_COLORS.purple + '99',
        borderColor: CHART_COLORS.purple,
        borderWidth: 1,
      }]
    },
    options: baseOptions('Recent Malware Sample File Types')
  });
}

// ---------------------------------------------------------------------------
// OTX Country Chart (OSINT page)
// ---------------------------------------------------------------------------
async function renderOtxCountryChart() {
  const canvas = document.getElementById('otxCountryChart');
  if (!canvas) return;

  const data = await loadData('osint.json');
  if (!data || !data.otx_analysis) return;

  const countries = data.otx_analysis.targeted_countries || [];
  const labels = countries.map(c => c.country);
  const values = countries.map(c => c.count);

  // Highlight Australia
  const bgColors = labels.map(l =>
    l === 'AU' ? CHART_COLORS.teal + 'cc' : CHART_COLORS.blue + '66'
  );
  const borderColors = labels.map(l =>
    l === 'AU' ? CHART_COLORS.teal : CHART_COLORS.blue
  );

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Threat Pulses',
        data: values,
        backgroundColor: bgColors,
        borderColor: borderColors,
        borderWidth: 1,
      }]
    },
    options: baseOptions('OTX: Most Targeted Countries')
  });
}

// ---------------------------------------------------------------------------
// NDB Sector Chart (NDB stats page)
// ---------------------------------------------------------------------------
async function renderNdbSectorChart() {
  const canvas = document.getElementById('ndbSectorChart');
  if (!canvas) return;

  const data = await loadData('ndb.json');
  if (!data || !data.detailed_periods || !data.detailed_periods[0]) return;

  const sectors = data.detailed_periods[0].top_sectors || [];
  const labels = sectors.map(s => s.sector);
  const values = sectors.map(s => s.count);

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Notifications',
        data: values,
        backgroundColor: PALETTE.slice(0, labels.length).map(c => c + '99'),
        borderColor: PALETTE.slice(0, labels.length),
        borderWidth: 1,
      }]
    },
    options: {
      ...baseOptions('Top Affected Sectors'),
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        title: { display: true, text: 'Top Affected Sectors (Latest Period)', color: chartTextColor() }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Shodan Exposure Chart (exposure page)
// ---------------------------------------------------------------------------
async function renderShodanExposureChart() {
  const canvas = document.getElementById('shodanExposureChart');
  if (!canvas) return;

  const data = await loadData('shodan.json');
  if (!data || !data.shodan || !data.shodan.available) return;

  const results = data.shodan.exposure_results || [];
  const labels = results.map(r => r.name.replace('Australian ', '').replace(' exposed', ''));
  const values = results.map(r => r.count);

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Exposed Hosts',
        data: values,
        backgroundColor: CHART_COLORS.red + '99',
        borderColor: CHART_COLORS.red,
        borderWidth: 1,
      }]
    },
    options: {
      ...baseOptions('Australian Internet Exposure (Shodan)'),
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        title: { display: true, text: 'Australian Internet Exposure by Service', color: chartTextColor() }
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Initialise all charts on page load
// ---------------------------------------------------------------------------
// Wait for Chart.js to be available before rendering
function waitForChartJs(callback, maxWait) {
  maxWait = maxWait || 5000;
  const start = Date.now();
  function check() {
    if (typeof Chart !== 'undefined') {
      callback();
    } else if (Date.now() - start < maxWait) {
      setTimeout(check, 100);
    } else {
      console.warn('Chart.js did not load within timeout');
    }
  }
  check();
}

function initCharts() {
  renderNdbTrendChart('ndbTrendChart');
  renderNdbTrendChart('ndbDetailChart');
  renderKevVendorChart();
  renderCveSeverityChart();
  renderUrlhausThreatChart();
  renderMalwareFileTypeChart();
  renderOtxCountryChart();
  renderNdbSectorChart();
  renderShodanExposureChart();
}

// MkDocs Material loads extra_javascript at the end of <body>, so
// DOMContentLoaded may have already fired by the time this script runs.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    waitForChartJs(initCharts);
  });
} else {
  // DOM already parsed; just wait for Chart.js CDN to finish loading
  waitForChartJs(initCharts);
}
