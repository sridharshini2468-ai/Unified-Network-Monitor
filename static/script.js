function showPage(id) {

  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));

  document.getElementById(id).classList.add('active');

  const navEl = document.getElementById('nav-' + id);

  if (navEl) navEl.classList.add('active');

  document.documentElement.style.overflow = '';
  document.body.style.overflow = '';

  window.scrollTo(0, 0);
}


if (document.getElementById('home').classList.contains('active')) {
    document.documentElement.style.overflow = 'hidden';
    document.body.style.overflow = 'hidden';
}
/* ── SCAN ── */
function runScan() {
  const label = document.getElementById('scan-label');
  const statusEl = document.getElementById('status');

  label.textContent = 'Scanning…';
  statusEl.textContent = '…';
  statusEl.classList.add('scanning');

  fetch('http://127.0.0.1:5000/api/scan')
    .then(response => {
      if (!response.ok) {
        throw new Error('Scan failed');
      }
      return response.json();
    })
    .then(data => {
      statusEl.classList.remove('scanning');
      label.textContent = 'Last Scan';
      statusEl.textContent = 'Done ✓';

      document.getElementById('devicecount').textContent =
        data.device_count;

      document.getElementById('net-count').textContent =
        data.device_count + ' device' +
        (data.device_count !== 1 ? 's' : '');

      const table = document.getElementById('devicetable');

      table.innerHTML = '';

      data.devices.forEach(device => {
        const row = document.createElement('tr');

        row.innerHTML = `
          <td>${device.hostname}</td>
          <td>${device.ip}</td>
          <td>${device.mac}</td>
          <td>${device.status}</td>
          <td>${device.vendor}</td>
        `;

        table.appendChild(row);
      });
    })
    .catch(error => {
      console.error(error);

      statusEl.classList.remove('scanning');
      statusEl.textContent = 'Scan Failed';
      label.textContent = 'Last Scan';
    });
}

/* ── LOG HISTORY ── */
function loadLogs() {
  fetch('http://127.0.0.1:5000/api/log-history?ip=10.127.4.236')
    .then(response => {
      if (!response.ok) {
        throw new Error('Could not load logs');
      }
      return response.json();
    })
    .then(data => {
      const table = document.getElementById('logtable');
      const count = document.getElementById('log-count');

      table.innerHTML = '';

      const logs = data.history || [];

      logs.forEach(log => {
        const dateTime = (log.detected_at || '').split(' ');
        const date = dateTime[0] || '';
        const time = dateTime[1] || '';

        const row = document.createElement('tr');

        row.innerHTML = `
          <td>${log.hostname || 'Unknown'}</td>
          <td>${log.ip_address || '—'}</td>
          <td>${log.mac_address || '—'}</td>
          <td>${log.status || '—'}</td>
          <td>${date}</td>
          <td>${time}</td>
        `;

        table.appendChild(row);
      });

      count.textContent = logs.length + ' entries';
    })
    .catch(error => {
      console.error('Log history error:', error);
    });
}

loadLogs();
