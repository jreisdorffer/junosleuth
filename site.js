const sectionLinks = [...document.querySelectorAll(".side-nav nav a")];
const sections = sectionLinks
  .map((link) => document.querySelector(link.getAttribute("href")))
  .filter(Boolean);

const setActiveLink = (id) => {
  sectionLinks.forEach((link) => {
    link.toggleAttribute("aria-current", link.getAttribute("href") === `#${id}`);
  });
};

const observer = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];

    if (visible) setActiveLink(visible.target.id || "top");
  },
  { rootMargin: "-30% 0px -55% 0px", threshold: [0.2, 0.45, 0.7] }
);

sections.forEach((section) => observer.observe(section));
