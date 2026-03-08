/**
 * setup.js — First-time setup wizard
 *
 * Shown once after a user sets their passphrase for the first time
 * (i.e. passphrase_set was false when the passphrase gate was displayed).
 *
 * Dismissal navigates to the status screen.
 */

(function wireSetupWizard() {
  let _currentStep = 1;
  const TOTAL_STEPS = 4;

  function _showStep(n) {
    _currentStep = n;
    for (let i = 1; i <= TOTAL_STEPS; i++) {
      const el = document.getElementById(`wizard-step-${i}`);
      if (el) el.style.display = (i === n) ? 'block' : 'none';
    }
    const indicator = document.getElementById('wizard-step-indicator');
    if (indicator) indicator.textContent = `Step ${n} of ${TOTAL_STEPS}`;
  }

  function showWizard() {
    const gate = document.getElementById('setup-wizard-gate');
    if (!gate) return;
    _showStep(1);
    gate.style.display = 'flex';
  }

  function hideWizard() {
    const gate = document.getElementById('setup-wizard-gate');
    if (gate) gate.style.display = 'none';
  }

  // Step 1 → Step 2
  document.getElementById('btn-wizard-1')?.addEventListener('click', () => {
    _showStep(2);
  });

  // Step 2 → Step 3
  document.getElementById('btn-wizard-2')?.addEventListener('click', () => {
    _showStep(3);
  });

  // Step 3 → Step 4
  document.getElementById('btn-wizard-3')?.addEventListener('click', () => {
    _showStep(4);
  });

  // Step 4 → dismiss, go to status
  document.getElementById('btn-wizard-4')?.addEventListener('click', () => {
    hideWizard();
    window.navigateTo && window.navigateTo('status');
  });

  // Expose for app.js
  window.SetupWizard = { show: showWizard, hide: hideWizard };
})();
