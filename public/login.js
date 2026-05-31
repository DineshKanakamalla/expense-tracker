document.querySelectorAll('.pwd-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = btn.closest('.pwd-wrapper').querySelector('input');
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    btn.classList.toggle('visible');
    btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  });
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('login-error');
  err.textContent = '';
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  try {
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
  } catch {
    err.textContent = 'Network error — check your connection';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
});
