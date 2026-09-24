const signin = document.getElementById('signin');
const password = document.getElementById('signin-password');
const problem = document.getElementById('signin-error');

signin.addEventListener('submit', async event => {
  event.preventDefault();
  const submit = signin.querySelector('button');
  submit.disabled = true;
  problem.hidden = true;
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    cache: 'no-store',
    body: JSON.stringify({ password: password.value })
  }).catch(() => null);

  if (response?.ok) {
    window.location.href = '/';
    return;
  }
  submit.disabled = false;
  problem.textContent = !response ? 'Could not reach the server.'
    : response.status === 429 ? 'Too many attempts. Wait a minute and try again.'
    : 'Wrong password.';
  problem.hidden = false;
  password.select();
});
