/* Settings -> General. Read-only display of real deployment config. */
(function () {
  'use strict';
  SentinelAPI.systemHealth().then((data) => {
    document.getElementById('envValue').textContent = data.environment;
  }).catch(() => { /* leave the em-dash placeholder */ });
})();
