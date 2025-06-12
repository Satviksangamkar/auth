// ─── 1) Toggle “show password” eye icon ─────────────────────────
document.querySelectorAll('.toggle-password').forEach(icon => {
  icon.addEventListener('click', () => {
    const inp = icon.closest('.form-group').querySelector('input');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });
});

// ─── 2) Handle “Create Account” ───────────────────────────────
async function handleRegister(e) {
  e.preventDefault();
  const f = e.target;
  const payload = {
    email: f.email.value,
    password: f.password.value
  };

  const res = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const j = await res.json();
  if (!res.ok) {
    return alert(j.detail || j.msg);
  }

  localStorage.setItem('pendingEmail', payload.email);
  window.location.href = 'verify.html';
}

// ─── 3) Handle OTP Verification ────────────────────────────────
async function handleVerify(e) {
  e.preventDefault();
  const email = localStorage.getItem('pendingEmail');
  const otp   = e.target.otp.value;

  const res = await fetch('/verify-registration-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, otp })
  });
  const j = await res.json();
  if (!res.ok) {
    return alert(j.detail || j.msg);
  }

  alert(j.msg);
  window.location.href = 'login.html';
}

// ─── 4) Handle Login ───────────────────────────────────────────
async function handleLogin(e) {
  e.preventDefault();
  const f = e.target;

  const formData = new URLSearchParams(new FormData(f));

  const res = await fetch('/token', {
    method: 'POST',
    /* THE MISSING PIECE 👇 */
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formData          // <-- username & password in URL-encoded form
  });

  const j = await res.json();
  if (!res.ok) return alert(j.detail);

  document.querySelector('.container').innerHTML = `
    <h1>Welcome!</h1>
    <p>Your login token is:</p>
    <pre style="word-break:break-all;">${j.access_token}</pre>`;
}


// ─── 5) Handle “Forgot Password” ───────────────────────────────
// (Ensure you have a matching /forgot-password endpoint)
async function handleForgot(e) {
  e.preventDefault();
  const email = e.target.email.value;

  const res = await fetch('/forgot-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  const j = await res.json();
  if (!res.ok) {
    return alert(j.detail || j.msg);
  }

  alert(j.msg);
  // Optionally redirect or show a reset-link page
}

// ─── 6) Handle “Resend Confirmation” ──────────────────────────
// (Ensure you have a matching /resend-confirmation endpoint)
async function handleResendConfirmation(e) {
  e.preventDefault();
  const email = localStorage.getItem('pendingEmail');
  if (!email) {
    return alert('No email stored for resending.');
  }

  const res = await fetch('/resend-confirmation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  const j = await res.json();
  const alertBox = document.getElementById('resendAlert');
  if (!res.ok) {
    alertBox.innerHTML = `<p class="error-text">${j.detail || j.msg}</p>`;
  } else {
    alertBox.innerHTML = `<p style="color:#4cd137;">${j.msg}</p>`;
  }
}

// ─── 7) Wire up event listeners on page load ─────────────────
window.addEventListener('DOMContentLoaded', () => {
  document.getElementById('registerForm')?.addEventListener('submit', handleRegister);
  document.getElementById('verifyForm')?.addEventListener('submit',   handleVerify);
  document.getElementById('loginForm')?.addEventListener('submit',    handleLogin);
  document.getElementById('forgotForm')?.addEventListener('submit',   handleForgot);
  document.getElementById('resend-link')?.addEventListener('click',   handleResendConfirmation);
});
