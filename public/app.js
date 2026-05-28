const API = '/api';
let categories = [];

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function esc(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (res.status === 401) {
    window.location.href = '/login.html';
    return;
  }
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Request failed');
  }
  return res.json();
}

function formatDate(d) {
  const [y, m, day] = d.split('-');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${day} ${months[+m - 1]} ${y}`;
}

function todayStr() {
  return new Date().toISOString().split('T')[0];
}

function currentMonth() { return String(new Date().getMonth() + 1); }
function currentYear() { return String(new Date().getFullYear()); }

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// --- Populate selects ---
function populateSelect(sel, items, val) {
  sel.innerHTML = items.map(i =>
    `<option value="${i}"${i === val ? ' selected' : ''}>${i}</option>`
  ).join('');
}

function populateMonthSelect(sel, val) {
  sel.innerHTML = MONTHS.map((m, i) =>
    `<option value="${i + 1}"${String(i + 1) === val ? ' selected' : ''}>${m}</option>`
  ).join('');
}

function populateYearSelect(sel, val) {
  const y = val || currentYear();
  const years = [];
  for (let i = 2024; i <= 2030; i++) years.push(String(i));
  sel.innerHTML = years.map(yy =>
    `<option value="${yy}"${yy === y ? ' selected' : ''}>${yy}</option>`
  ).join('');
}

// --- Tabs ---
$$('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    $$('.tab').forEach(t => t.classList.remove('active'));
    $$('.tab-content').forEach(tc => tc.classList.remove('active'));
    tab.classList.add('active');
    $(`#${tab.dataset.tab}`).classList.add('active');

    if (tab.dataset.tab === 'list') loadExpenses();
    if (tab.dataset.tab === 'summary') loadSummary();
  });
});

// --- Add expense ---
async function init() {
  categories = await api('/categories');
  populateSelect($('#category'), categories, categories[0]);

  $('#date').value = todayStr();

  populateMonthSelect($('#month-filter'), currentMonth());
  populateYearSelect($('#year-filter'), currentYear());
  populateYearSelect($('#summary-year-filter'), currentYear());

  $('#month-filter').addEventListener('change', loadExpenses);
  $('#year-filter').addEventListener('change', loadExpenses);
  $('#summary-year-filter').addEventListener('change', loadSummary);

  $('#logout-btn').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });

  $('#change-pwd-btn').addEventListener('click', () => {
    $('#pwd-modal').classList.add('open');
    $('#current-pwd').value = '';
    $('#new-pwd').value = '';
    $('#confirm-pwd').value = '';
    $('#pwd-error').textContent = '';
  });

  $('#pwd-cancel').addEventListener('click', () => {
    $('#pwd-modal').classList.remove('open');
  });

  $('#pwd-modal').addEventListener('click', (e) => {
    if (e.target === $('#pwd-modal')) $('#pwd-modal').classList.remove('open');
  });

  $('#pwd-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#pwd-error');
    err.textContent = '';
    const newPwd = $('#new-pwd').value;
    const confirmPwd = $('#confirm-pwd').value;
    if (newPwd !== confirmPwd) {
      err.textContent = 'Passwords do not match';
      return;
    }
    const btn = e.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Updating...';
    const res = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: $('#current-pwd').value, newPassword: newPwd }),
    });
    if (res.ok) {
      $('#pwd-modal').classList.remove('open');
      window.location.href = '/login.html';
    } else {
      const data = await res.json();
      err.textContent = data.error || 'Failed to update password';
    }
    btn.disabled = false;
    btn.textContent = 'Update Password';
  });

  $('#expense-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      amount: parseFloat($('#amount').value),
      category: $('#category').value,
      date: $('#date').value,
      description: $('#description').value,
    };
    await api('/expenses', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    $('#expense-form').reset();
    $('#date').value = todayStr();
    $('#amount').focus();
    loadExpenses();
    loadSummary();
    showToast('Expense added successfully');
  });

  loadExpenses();
}

// --- Load expenses ---
async function loadExpenses() {
  const month = $('#month-filter').value;
  const year = $('#year-filter').value;
  const expenses = await api(`/expenses?month=${month}&year=${year}`);

  const tbody = $('#expense-tbody');
  let total = 0;

  if (expenses.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:32px;color:#999;font-size:1.1rem">No expenses for this month</td></tr>`;
    $('#list-total').textContent = '';
  } else {
    tbody.innerHTML = expenses.map(e => {
      total += e.amount;
      return `<tr>
        <td>${formatDate(e.date)}</td>
        <td><strong>${e.category}</strong></td>
        <td>${esc(e.description || '—')}</td>
        <td class="amount">₹${e.amount.toFixed(2)}</td>
        <td><button class="delete-btn" data-id="${e.id}">✕</button></td>
      </tr>`;
    }).join('');
    $('#list-total').textContent = `Total: ₹${total.toFixed(2)}`;
  }

  $$('.delete-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (confirm('Delete this expense?')) {
        await api(`/expenses/${btn.dataset.id}`, { method: 'DELETE' });
        loadExpenses();
        loadSummary();
      }
    });
  });
}

// --- Load summary ---
async function loadSummary() {
  const year = $('#summary-year-filter').value;
  const data = await api(`/summary?year=${year}`);

  const grouped = {};
  let grandTotal = 0;
  for (const row of data) {
    if (!grouped[row.category]) grouped[row.category] = {};
    grouped[row.category][row.month] = row.total;
    grandTotal += row.total;
  }

  // Bar chart (top 5 categories by total)
  const catTotals = Object.entries(grouped).map(([cat, months]) => {
    const total = Object.values(months).reduce((a, b) => a + b, 0);
    return { cat, total };
  }).sort((a, b) => b.total - a.total);

  const chart = $('#summary-chart');
  const maxTotal = catTotals.length > 0 ? catTotals[0].total : 1;
  const colors = ['#16213e','#0f3460','#533483','#e94560','#f5a623','#2ecc71','#3498db','#9b59b6','#1abc9c','#e67e22','#34495e','#7f8c8d'];

  chart.innerHTML = `<h3 style="margin-bottom:12px">Top Categories (${year})</h3>
    <div class="bar-container">${
      catTotals.slice(0, 8).map((item, i) => `
        <div class="bar-row">
          <div class="bar-label">${item.cat}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${(item.total / maxTotal) * 100}%;background:${colors[i % colors.length]}">
              ${item.total > maxTotal * 0.15 ? `₹${item.total.toFixed(0)}` : ''}
            </div>
          </div>
          <div class="bar-amount">₹${item.total.toFixed(0)}</div>
        </div>
      `).join('')
    }</div>`;

  // Month-wise summary table (all categories, zero-spend shows —)
  const tbody = $('#summary-tbody');
  tbody.innerHTML = categories.map(cat => {
    const months = grouped[cat] || {};
    let catTotal = 0;
    const cells = MONTHS.map((_, i) => {
      const key = String(i + 1).padStart(2, '0');
      const val = months[key];
      if (val) catTotal += val;
      return val != null ? `<td>₹${val.toFixed(0)}</td>` : '<td>—</td>';
    }).join('');
    return `<tr>
      <td>${cat}</td>
      ${cells}
      <td><strong>${catTotal > 0 ? `₹${catTotal.toFixed(0)}` : '—'}</strong></td>
    </tr>`;
  }).join('');

  // Grand total row
  if (tbody.innerHTML) {
    tbody.innerHTML += `<tr style="font-weight:700;border-top:2px solid #333">
      <td>Total</td>
      ${MONTHS.map((_, i) => {
        const key = String(i + 1).padStart(2, '0');
        let mTotal = 0;
        for (const cat of categories) {
          const months = grouped[cat] || {};
          mTotal += months[key] || 0;
        }
        return mTotal ? `<td>₹${mTotal.toFixed(0)}</td>` : '<td>—</td>';
      }).join('')}
      <td>₹${grandTotal.toFixed(0)}</td>
    </tr>`;
  }
}

function showToast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._timeout);
  el._timeout = setTimeout(() => el.classList.remove('show'), 2500);
}

init();
