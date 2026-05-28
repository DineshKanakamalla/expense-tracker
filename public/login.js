document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('login-error');
  err.textContent = '';
  err.style.color = '';
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: document.getElementById('username').value,
      password: document.getElementById('password').value,
    }),
  });
  const data = await res.json();
  if (res.ok) {
    if (data.warning) {
      const w = document.getElementById('login-error');
      w.textContent = data.warning;
      w.style.color = '#ffa726';
    }
    setTimeout(() => { window.location.href = '/'; }, 300);
  } else {
    err.textContent = data.error || 'Invalid credentials';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
});
