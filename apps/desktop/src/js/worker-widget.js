/* Copyright (c) 2026 pyhall.dev — https://pyhall.dev
 * All Rights Reserved.
 */
/**
 * worker-widget.js — pyhall Python worker mascot
 * Inline SVG with anim-target / hat-element / text-hat-element class hooks.
 * Consumed by: login gate (anim-enter → anim-float), status screen (state machine),
 *              alerts (anim-alert), enroll success (anim-celebrate).
 */
window.WorkerWidget = (() => {
  // Inline SVG with class hooks for animation and hat-level coloring.
  // Gradient/filter IDs prefixed `ww-` to avoid conflicts with page-level defs.
  const _SVG = `<svg viewBox="0 0 96.878487 86.70839" xmlns="http://www.w3.org/2000/svg" overflow="visible" class="anim-target" style="display:block;width:100%;height:100%">
<defs>
  <linearGradient id="ww-snakeSheen" x1="95.536713" y1="275.17169" x2="289.61917" y2="469.25415"
    gradientTransform="matrix(1.3293319,0,0,0.75225758,209.92269,384.03756)" gradientUnits="userSpaceOnUse">
    <stop offset="0%" style="stop-color:#4B8BBE;stop-opacity:1"/>
    <stop offset="100%" style="stop-color:#3776AB;stop-opacity:1"/>
  </linearGradient>
  <filter id="ww-dropShadow" x="-0.057791333" y="-0.070071147" width="1.1273903" height="1.1530257">
    <feGaussianBlur in="SourceAlpha" stdDeviation="8.1573402"/>
    <feOffset dx="4" dy="4" result="offsetblur"/>
    <feComponentTransfer><feFuncA type="linear" slope="0.3"/></feComponentTransfer>
    <feMerge><feMergeNode in="offsetblur"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
</defs>
<g transform="translate(-46.116246,-194.1075)">
  <g transform="matrix(0.26458333,0,0,0.26458333,26.160657,179.67777)" filter="url(#ww-dropShadow)">
    <path d="m 154,244 h 232.6 v 63.70926 h -58.15 v 50.96741 H 270.3 v -50.96741 h -58.15 v -25.4837 H 154 Z" fill="#1e4b6e" style="stroke-width:0.850631"/>
    <path d="m 128,208 h 256 v 80 h -64 v 64 h -64 v -32 h -32 v -32 h -32 -32 l -32,-32 v 0 z" style="fill:url(#ww-snakeSheen);stroke:#28567e;stroke-width:2"/>
    <rect x="320" y="208" width="64" height="80" fill="#4b8bbe" fill-opacity="0.2"/>
    <rect x="192" y="256" width="64" height="32" fill="#28567e" fill-opacity="0.2"/>
    <path d="m 160,228 16,16 -16,16 -16,-16 z" fill="#ffffff" style="stroke:none"/>
    <path d="m 160,236 8,8 -8,8 -8,-8 z" fill="#3776ab"/>
    <path class="hat-element" d="m 114,194 h 304 v 16 l -32,16 H 130 L 98,210 Z" style="fill:#e8e8e8;fill-opacity:0.7"/>
    <path class="hat-element" d="m 160,96 h 192 l 32,32 v 64 H 128 v -64 z" style="fill:#f5f5f5;stroke:#d0d0d0;stroke-width:1.99937"/>
    <path class="hat-element" d="m 96,192 h 320 v 16 l -32,16 H 128 L 96,208 Z" style="fill:#e0e0e0;stroke:#d0d0d0;stroke-width:1.99937"/>
    <path d="m 164,100 h 184 l 22,22 H 142 Z" style="fill:#ffffff;fill-opacity:0.35"/>
    <path d="m 172.76959,89 h 22.33485 116.39993 26.61084 l 19.76958,22 H 153 Z" style="fill:#ffffff;fill-opacity:0.5;stroke:none"/>
    <rect class="hat-element" style="fill:#f0f0f0;stroke:#d0d0d0;stroke-width:0.67647;stroke-linejoin:round" width="90.74144" height="14.682677" x="209.56288" y="74.453407"/>
    <g>
      <text class="text-hat-element" style="font-weight:bold;font-size:53.3333px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="171.15337" y="161.99997">p</text>
      <text class="text-hat-element" style="font-weight:bold;font-size:53.3333px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="207.15341" y="161.99997">y</text>
      <text class="text-hat-element" style="font-weight:bold;font-size:53.3333px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="239.04670" y="161.99997">h</text>
      <text class="text-hat-element" style="font-weight:bold;font-size:53.3333px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="275.90001" y="161.99997">a</text>
      <text class="text-hat-element" style="font-weight:bold;font-size:53.3333px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="308.80669" y="161.99997">l</text>
      <text class="text-hat-element" style="font-weight:bold;font-size:53.3333px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="324.86004" y="161.99997">l</text>
    </g>
    <g>
      <text style="font-weight:bold;font-size:26.6667px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;fill-opacity:0.7;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="323.03995" y="212.69336">w</text>
      <text style="font-weight:bold;font-size:26.6667px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;fill-opacity:0.7;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="347.62667" y="212.69336">c</text>
      <text style="font-weight:bold;font-size:26.6667px;font-family:Montserrat,'JetBrains Mono',sans-serif;text-align:center;fill-opacity:0.7;stroke:#f0f0f0;stroke-width:0.948661;stroke-linejoin:round;paint-order:stroke fill markers" x="363.38668" y="212.69336">p</text>
    </g>
  </g>
</g>
</svg>`;

  const _ANIM_CLASSES = [
    'anim-float','anim-think','anim-patrol','anim-nod','anim-shine',
    'anim-badge','anim-dig','anim-spin','anim-type','anim-bob','anim-celebrate',
    'anim-shake','anim-angry','anim-glitch','anim-alert','anim-powerup',
    'anim-hat-tip','anim-enter','anim-warp','anim-direct','anim-process','anim-paused',
  ];

  /**
   * Create a worker widget div.
   * @param {object} opts
   * @param {string} [opts.sizeClass] — 'worker-widget-sm' | 'worker-widget-md' | 'worker-widget-lg' | 'worker-widget-xl'
   * @param {string} [opts.animClass] — initial animation class (default: 'anim-float')
   * @param {number|null} [opts.hatLevel] — 0-8 for hat level coloring, null for default white
   * @returns {HTMLDivElement}
   */
  function create(opts = {}) {
    const {
      sizeClass = 'worker-widget-md',
      animClass = 'anim-float',
      hatLevel = null,
    } = opts;
    const div = document.createElement('div');
    div.className = ['worker-widget', sizeClass, animClass].filter(Boolean).join(' ');
    if (hatLevel !== null) div.classList.add(`hat-l${hatLevel}`);
    div.innerHTML = _SVG;
    return div;
  }

  /**
   * Switch animation class on a worker widget container.
   * @param {HTMLElement} el — the worker-widget div
   * @param {string|null} animClass — new animation class, or null to clear all
   */
  function setAnimation(el, animClass) {
    _ANIM_CLASSES.forEach(c => el.classList.remove(c));
    if (animClass) el.classList.add(animClass);
  }

  /**
   * Set hat level color (0-8) on a worker widget container.
   * @param {HTMLElement} el
   * @param {number|null} level
   */
  function setHatLevel(el, level) {
    for (let i = 0; i <= 8; i++) el.classList.remove(`hat-l${i}`);
    if (level !== null && level !== undefined) el.classList.add(`hat-l${level}`);
  }

  /**
   * Determine the correct animation class for the current Hall Server state.
   * @param {object} data — status response data
   * @param {boolean} online — whether the Hall Server is reachable
   * @returns {string} animation class name
   */
  function animForState(data, online) {
    if (!online) return 'anim-float';                              // offline — idle float
    const state = data.state || 'locked';
    if (state === 'locked') return 'anim-nod';                    // locked — standing by
    if (state === 'ready')  return 'anim-shine';                  // ready — glowing
    // online state:
    if (data.hall_hash_verified === false) return 'anim-glitch';  // tamper detected!
    const standing = data.account_standing || 'unknown';
    if (standing === 'suspended') return 'anim-shake';            // suspended — blocked
    if (standing === 'degraded')  return 'anim-alert';            // degraded — warning
    return 'anim-patrol';                                         // ok — active monitoring
  }

  /** Return the raw SVG markup string for direct injection. */
  function getSVG() { return _SVG; }

  return { create, getSVG, setAnimation, setHatLevel, animForState };
})();
