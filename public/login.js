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
    window.location.href = '/';
  } else {
    err.textContent = data.error || 'Invalid credentials';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
});
