const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

document.querySelectorAll(".bar-chart").forEach((chart) => {
  const rows = chart.querySelectorAll(".bar-row");
  const counts = Array.from(rows).map((row) => Number(row.querySelector("b")?.textContent || 0));
  const max = Math.max(...counts, 1);
  rows.forEach((row) => {
    const count = Number(row.querySelector("b")?.textContent || 0);
    const bar = row.querySelector("i");
    if (bar) {
      bar.style.width = "0%";
      requestAnimationFrame(() => {
        bar.style.width = `${Math.max((count / max) * 100, count > 0 ? 8 : 2)}%`;
      });
    }
  });
});

const revealTargets = document.querySelectorAll(
  ".metric, .panel, .result-card, .activity-list a, .source-card"
);

if (!prefersReducedMotion && "IntersectionObserver" in window) {
  revealTargets.forEach((target) => target.classList.add("reveal-on-scroll"));
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12 }
  );
  revealTargets.forEach((target) => observer.observe(target));
}

if (!prefersReducedMotion) {
  document.querySelectorAll(".metric").forEach((card) => {
    card.addEventListener("mousemove", (event) => {
      const rect = card.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width - 0.5) * 7;
      const y = ((event.clientY - rect.top) / rect.height - 0.5) * -7;
      card.style.transform = `perspective(700px) rotateX(${y}deg) rotateY(${x}deg) translateY(-2px)`;
    });
    card.addEventListener("mouseleave", () => {
      card.style.transform = "";
    });
  });
}
