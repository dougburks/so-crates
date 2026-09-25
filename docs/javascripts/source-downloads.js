// Adds the container image's total download count to the repository
// widget, after Material's own stars/forks. The count is read at build
// time (hooks/ghcr_downloads.py) and passed in data-md-downloads, since
// GitHub offers no public API for it. Material renders its facts list only
// once its GitHub API fetch returns, so wait for that list and append to it.
(function () {
  function formatCount(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1).replace(/\.0$/, '') + 'k';
    return String(n);
  }

  function addFact(source, facts) {
    if (facts.querySelector('.md-source__fact--downloads')) return;
    const n = Number(source.dataset.mdDownloads);
    const li = document.createElement('li');
    li.className = 'md-source__fact md-source__fact--downloads';
    li.title = n.toLocaleString() + ' container image downloads';
    li.textContent = formatCount(n);
    facts.appendChild(li);
  }

  document.querySelectorAll('.md-source[data-md-downloads]').forEach(function (source) {
    const repo = source.querySelector('.md-source__repository');
    if (!repo || !Number(source.dataset.mdDownloads)) return;
    const existing = repo.querySelector('.md-source__facts');
    if (existing) {
      addFact(source, existing);
      return;
    }
    const observer = new MutationObserver(function () {
      const facts = repo.querySelector('.md-source__facts');
      if (facts) {
        observer.disconnect();
        addFact(source, facts);
      }
    });
    observer.observe(repo, { childList: true });
  });
})();
