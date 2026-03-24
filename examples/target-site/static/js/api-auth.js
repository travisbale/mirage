/**
 * Two-step API authentication (login → MFA) used by api_login and multi_login.
 *
 * @param {string} loginUrl  - POST endpoint for email+password (returns pending_token)
 * @param {string} mfaUrl    - POST endpoint for MFA code
 * @param {string} redirectTo - URL to navigate to after successful auth
 */
function apiAuth(loginUrl, mfaUrl, redirectTo) {
  var errorEl = document.getElementById("error");
  var pendingToken = null;

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.classList.remove("hidden");
  }

  function hideError() {
    errorEl.classList.add("hidden");
  }

  function apiCall(url, body) {
    return fetch(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "include",
      body: JSON.stringify(body)
    }).then(function(resp) {
      return resp.json().then(function(data) { return {ok: resp.ok, data: data}; });
    });
  }

  // Step 1: email + password
  document.getElementById("login-form").addEventListener("submit", function(e) {
    e.preventDefault();
    hideError();
    var btn = document.getElementById("login-btn");
    btn.textContent = "Signing in...";
    btn.disabled = true;

    apiCall(loginUrl, {
      email: document.getElementById("email").value,
      password: document.getElementById("password").value
    })
    .then(function(result) {
      if (!result.ok) {
        showError(result.data.error || "Login failed.");
        btn.textContent = "Sign in";
        btn.disabled = false;
        return;
      }
      pendingToken = result.data.pending_token;
      document.getElementById("step-login").classList.add("hidden");
      document.getElementById("step-mfa").classList.remove("hidden");
      document.getElementById("code").focus();
    })
    .catch(function() {
      showError("Network error. Please try again.");
      btn.textContent = "Sign in";
      btn.disabled = false;
    });
  });

  // Step 2: MFA code
  document.getElementById("mfa-form").addEventListener("submit", function(e) {
    e.preventDefault();
    hideError();
    var btn = document.getElementById("mfa-btn");
    btn.textContent = "Verifying...";
    btn.disabled = true;

    apiCall(mfaUrl, {
      pending_token: pendingToken,
      code: document.getElementById("code").value
    })
    .then(function(result) {
      if (!result.ok) {
        showError(result.data.error || "Verification failed.");
        btn.textContent = "Verify";
        btn.disabled = false;
        return;
      }
      window.location.href = redirectTo;
    })
    .catch(function() {
      showError("Network error. Please try again.");
      btn.textContent = "Verify";
      btn.disabled = false;
    });
  });
}
