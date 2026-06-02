document.querySelectorAll(".bar-chart").forEach((chart) => {
  const rows = chart.querySelectorAll(".bar-row");
  const counts = Array.from(rows).map((row) => Number(row.querySelector("b")?.textContent || 0));
  const max = Math.max(...counts, 1);
  rows.forEach((row) => {
    const count = Number(row.querySelector("b")?.textContent || 0);
    const bar = row.querySelector("i");
    if (bar) {
      bar.style.width = `${Math.max((count / max) * 100, count > 0 ? 8 : 2)}%`;
    }
  });
});
