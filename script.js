/* ==========================================================================
   Lauwak - script.js  (plain JavaScript, no libraries)

   1. Start-up loading screen  - moves on to the next page after a short moment
   2. Show / Hide password buttons
   3. Instant form checks      - the server checks everything again, so these
                          are only a convenience for the person typing
   4. Loading state while a form is being sent
   5. Back-button fixes
   ========================================================================== */
(function () {
  "use strict";

  // How long the start-up loading screen stays visible (milliseconds).
  const SPLASH_MS = 600;

  // Safety net: if a page never arrives, the loading screen hides itself again.
  const LOADING_TIMEOUT_MS = 10000;

  const USERNAME_CHARACTERS = /^[A-Za-z0-9_]+$/;


  /* 1. START-UP LOADING SCREEN ------------------------------------------ */
  // loading.html puts the next page's address in data-next-url.
  const splash = document.querySelector("[data-next-url]");
  if (splash) {
    window.setTimeout(function () {
      window.location.replace(splash.dataset.nextUrl);
    }, SPLASH_MS);
  }


  /* 2. SHOW / HIDE PASSWORD --------------------------------------------- */
  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      const input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;

      const wasHidden = input.type === "password";
      input.type = wasHidden ? "text" : "password";
      button.textContent = wasHidden ? "Hide" : "Show";
      button.setAttribute("aria-label", wasHidden ? "Hide password" : "Show password");
    });
  });


  /* 3. INSTANT FORM CHECKS ---------------------------------------------- */
  // Each input names its rule with data-rule="...". A rule returns an error
  // message, or "" when the value is fine. The limits (minimum / maximum
  // length) are read from the input itself, and the page gets them from app.py,
  // so the browser and the server always use the same numbers.
  const RULES = {
    name: function (input) {
      const value = input.value.trim();
      if (!value) return "Enter your name.";
      if (value.length > input.maxLength) {
        return "Name must be " + input.maxLength + " characters or fewer.";
      }
      return "";
    },

    // Registration: a brand-new username must follow the format rules.
    "new-username": function (input) {
      const value = input.value.trim();
      if (!value) return "Choose a username.";
      if (value.length < input.minLength || value.length > input.maxLength) {
        return "Username must be " + input.minLength + "\u2013" + input.maxLength + " characters long.";
      }
      if (!USERNAME_CHARACTERS.test(value)) {
        return "Username can only contain letters, numbers, and underscores.";
      }
      return "";
    },

    // Login and Forgot password: only check that something was typed.
    username: function (input) {
      return input.value.trim() ? "" : "Enter your username.";
    },

    password: function (input) {
      return input.value ? "" : "Enter your password.";
    },

    "new-password": function (input) {
      const value = input.value;
      if (!value) return "Enter a password.";
      if (value.length < input.minLength) {
        return "Password must be at least " + input.minLength + " characters.";
      }
      if (value.length > input.maxLength) {
        return "Password must be " + input.maxLength + " characters or fewer.";
      }
      return "";
    },

    "confirm-password": function (input, form) {
      const original = form.querySelector('[data-rule="new-password"]');
      if (!input.value) return "Confirm your password.";
      if (original && input.value !== original.value) return "Passwords do not match.";
      return "";
    }
  };

  // Show (or clear) the message under one input. Each message box has the id
  // "<input id>-error", for example "username-error".
  function setError(input, message) {
    const messageBox = document.getElementById(input.id + "-error");
    if (messageBox) messageBox.textContent = message;

    input.classList.toggle("is-invalid", message !== "");
    if (message) {
      input.setAttribute("aria-invalid", "true");
    } else {
      input.removeAttribute("aria-invalid");
    }
  }

  // Check one input. Returns true when it is valid.
  function validateInput(input, form) {
    const rule = RULES[input.dataset.rule];
    const message = rule ? rule(input, form) : "";
    setError(input, message);
    return message === "";
  }

  // Check every input in a form. Returns the first invalid input (or null).
  function validateForm(form) {
    let firstInvalid = null;
    form.querySelectorAll("[data-rule]").forEach(function (input) {
      if (!validateInput(input, form) && !firstInvalid) firstInvalid = input;
    });
    return firstInvalid;
  }

  document.querySelectorAll("form[data-validate]").forEach(function (form) {
    // While typing: a message disappears as soon as the problem is fixed, and the
    // "passwords match" check keeps up with both password boxes.
    form.addEventListener("input", function (event) {
      const input = event.target;
      if (!input.matches("[data-rule]")) return;

      if (input.classList.contains("is-invalid")) validateInput(input, form);

      const confirm = form.querySelector('[data-rule="confirm-password"]');
      if (confirm && confirm.value && input.dataset.rule === "new-password") {
        validateInput(confirm, form);
      }
    });

    // When leaving a box that has something typed in it, check it.
    form.addEventListener("focusout", function (event) {
      const input = event.target;
      if (input.matches("[data-rule]") && input.value) validateInput(input, form);
    });
  });

  // Errors that came back from the server: put the cursor in the first bad box.
  const firstServerError = document.querySelector("input.is-invalid");
  if (firstServerError) firstServerError.focus();


  /* 4. LOADING STATE WHILE A FORM IS SENT -------------------------------- */
  const overlay = document.getElementById("loading-overlay");
  const overlayText = document.getElementById("loading-text");
  let loadingTimer = null;

  function showLoading(message) {
    if (!overlay) return;
    overlayText.textContent = message || "Loading\u2026";
    overlay.hidden = false;
    loadingTimer = window.setTimeout(resetLoading, LOADING_TIMEOUT_MS);
  }

  function resetLoading() {
    window.clearTimeout(loadingTimer);
    if (overlay) overlay.hidden = true;
    document.querySelectorAll("form[data-submitting]").forEach(function (form) {
      form.removeAttribute("data-submitting");
    });
  }

  document.querySelectorAll("form[data-loading-text]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      // Ignore a second click or Enter press while the first is still sending.
      if (form.hasAttribute("data-submitting")) {
        event.preventDefault();
        return;
      }

      // Forms with data-validate are checked first; a bad form is not sent.
      if (form.hasAttribute("data-validate")) {
        const firstInvalid = validateForm(form);
        if (firstInvalid) {
          event.preventDefault();
          firstInvalid.focus();
          return;
        }
      }

      form.setAttribute("data-submitting", "");
      showLoading(form.dataset.loadingText);
    });
  });


  /* 5. BACK-BUTTON FIXES ------------------------------------------------- */
  // Some browsers keep a page in memory and show it again when you press Back.
  window.addEventListener("pageshow", function (event) {
    if (!event.persisted) return;

    resetLoading(); // never come back to a loading screen that is stuck

    // Reload Home so a person who just logged out cannot see it again.
    if (document.body.dataset.page === "home") window.location.reload();
  });
})();