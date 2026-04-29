(function () {
  var storageKey = "vp-sidebar-collapsed";
  var root = document.documentElement;

  function readCollapsedState() {
    try {
      return window.localStorage.getItem(storageKey) === "1";
    } catch (_) {
      return false;
    }
  }

  function writeCollapsedState(collapsed) {
    try {
      window.localStorage.setItem(storageKey, collapsed ? "1" : "0");
    } catch (_) {}
  }

  function applyState(button, collapsed, persist) {
    var text = button.querySelector(".sidebar-toggle-text");
    root.classList.toggle("sidebar-collapsed", collapsed);
    button.setAttribute("aria-pressed", collapsed ? "true" : "false");
    button.setAttribute("aria-label", collapsed ? "Expand navigation" : "Collapse navigation");
    if (text) {
      text.textContent = collapsed ? "Expand" : "Collapse";
    }
    if (persist) {
      writeCollapsedState(collapsed);
    }
  }

  function onReady(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback, { once: true });
      return;
    }
    callback();
  }

  if (readCollapsedState()) {
    root.classList.add("sidebar-collapsed");
  }

  onReady(function () {
    var button = document.querySelector("[data-sidebar-toggle]");
    if (!button) {
      return;
    }
    applyState(button, root.classList.contains("sidebar-collapsed"), false);
    button.addEventListener("click", function () {
      applyState(button, !root.classList.contains("sidebar-collapsed"), true);
    });
  });
})();

(function () {
  function onReady(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback, { once: true });
      return;
    }
    callback();
  }

  function compactText(value, maxLength) {
    var text = (value || "").replace(/\s+/g, " ").trim();
    if (text.length <= maxLength) {
      return text;
    }
    return text.slice(0, maxLength - 1).trim() + "…";
  }

  function insightText(element) {
    var title = element.querySelector ? element.querySelector("title") : null;
    return compactText(
      element.getAttribute("data-insight") ||
        element.getAttribute("aria-label") ||
        element.getAttribute("title") ||
        (title ? title.textContent : "") ||
        element.innerText ||
        element.textContent,
      220
    );
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function createTooltip() {
    var tooltip = document.createElement("div");
    tooltip.className = "er-floating-tip";
    tooltip.setAttribute("role", "status");
    tooltip.setAttribute("aria-live", "polite");
    document.body.appendChild(tooltip);
    return tooltip;
  }

  function moveTooltip(tooltip, event, fallbackElement) {
    var width = tooltip.offsetWidth || 260;
    var height = tooltip.offsetHeight || 70;
    var x = event && typeof event.clientX === "number" ? event.clientX + 14 : 0;
    var y = event && typeof event.clientY === "number" ? event.clientY + 14 : 0;
    if (!x && fallbackElement) {
      var rect = fallbackElement.getBoundingClientRect();
      x = rect.left + Math.min(30, rect.width / 2);
      y = rect.top + Math.min(34, rect.height / 2);
    }
    tooltip.style.left = clamp(x, 8, window.innerWidth - width - 8) + "px";
    tooltip.style.top = clamp(y, 8, window.innerHeight - height - 8) + "px";
  }

  function ensureInsightPanel(section) {
    var existing = section.querySelector(".er-live-insight");
    if (existing) {
      return existing;
    }
    var panel = document.createElement("article");
    panel.className = "er-live-insight";
    panel.hidden = true;
    panel.setAttribute("aria-live", "polite");
    panel.innerHTML =
      "<span>Selected signal</span><strong></strong><p></p>";
    var head = section.querySelector(".er-section-head");
    if (head && head.nextSibling) {
      section.insertBefore(panel, head.nextSibling);
    } else {
      section.insertBefore(panel, section.firstChild);
    }
    return panel;
  }

  function clearHighlights(report) {
    Array.prototype.forEach.call(
      report.querySelectorAll(".is-selected, .er-cve-spotlight"),
      function (node) {
        node.classList.remove("is-selected");
        node.classList.remove("er-cve-spotlight");
      }
    );
  }

  function spotlightRelatedCve(report, text) {
    var match = text.match(/CVE-\d{4}-\d{4,7}/i);
    if (!match) {
      return;
    }
    var cve = match[0].toUpperCase();
    Array.prototype.forEach.call(
      report.querySelectorAll(
        ".er-table tbody tr, .er-ranked-row, .er-dossier-card, .er-heat-cell"
      ),
      function (node) {
        if ((node.textContent || "").toUpperCase().indexOf(cve) !== -1) {
          node.classList.add("er-cve-spotlight");
        }
      }
    );
  }

  function pinInsight(report, element) {
    var text = insightText(element);
    var section = element.closest(".er-section");
    if (!text || !section) {
      return;
    }
    var tooltip = document.querySelector(".er-floating-tip");
    if (tooltip) {
      tooltip.classList.remove("is-visible");
    }
    clearHighlights(report);
    element.classList.add("is-selected");
    spotlightRelatedCve(report, text);
    Array.prototype.forEach.call(report.querySelectorAll(".er-live-insight"), function (node) {
      if (!section.contains(node)) {
        node.remove();
      }
    });
    var panel = ensureInsightPanel(section);
    var title = section.querySelector("h2");
    panel.querySelector("strong").textContent = text;
    panel.querySelector("p").textContent = title ? title.textContent : "";
    panel.hidden = false;
  }

  function initReportInteractions() {
    var report = document.querySelector(".executive-report-page");
    if (!report || report.getAttribute("data-er-interactive") === "true") {
      return;
    }
    report.setAttribute("data-er-interactive", "true");

    var tooltip = createTooltip();
    var selector = [
      ".er-provider-card",
      ".er-signal-card",
      ".er-quality-matrix > article",
      ".er-summary-item",
      ".er-ranked-row",
      ".er-driver-row",
      ".er-bar-row",
      ".er-remed-row",
      ".er-status-segment",
      ".er-exposure-tile",
      ".er-heat-cell",
      ".er-donut-legend-row",
      ".er-focus-card",
      ".er-method-card",
      ".er-pipeline-step",
      ".er-evidence-file-list li",
      ".er-command-list code",
      ".er-stacked-chart rect",
      ".er-quadrant-scatter .er-dot",
      ".er-donut-segment"
    ].join(",");

    Array.prototype.forEach.call(report.querySelectorAll(selector), function (element) {
      var text = insightText(element);
      if (!text) {
        return;
      }
      element.classList.add("er-interactive-target");
      element.setAttribute("data-er-insight", text);
      if (!element.hasAttribute("tabindex")) {
        element.setAttribute("tabindex", "0");
      }
      if (!element.hasAttribute("role")) {
        element.setAttribute("role", "button");
      }
      element.addEventListener("pointerenter", function (event) {
        tooltip.textContent = text;
        tooltip.classList.add("is-visible");
        moveTooltip(tooltip, event, element);
      });
      element.addEventListener("pointermove", function (event) {
        if (tooltip.classList.contains("is-visible")) {
          moveTooltip(tooltip, event, element);
        }
      });
      element.addEventListener("pointerleave", function () {
        tooltip.classList.remove("is-visible");
      });
      element.addEventListener("focus", function () {
        tooltip.textContent = text;
        tooltip.classList.add("is-visible");
        moveTooltip(tooltip, null, element);
      });
      element.addEventListener("blur", function () {
        tooltip.classList.remove("is-visible");
      });
      element.addEventListener("click", function () {
        pinInsight(report, element);
      });
      element.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          pinInsight(report, element);
        }
      });
    });

    var navLinks = {};
    Array.prototype.forEach.call(
      report.querySelectorAll('.er-section-nav a[href^="#"]'),
      function (link) {
        navLinks[link.getAttribute("href").slice(1)] = link;
      }
    );
    if ("IntersectionObserver" in window) {
      var observer = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (!entry.isIntersecting) {
              return;
            }
            Object.keys(navLinks).forEach(function (key) {
              navLinks[key].classList.toggle("is-active", key === entry.target.id);
            });
          });
        },
        { rootMargin: "-20% 0px -65% 0px", threshold: 0.01 }
      );
      Array.prototype.forEach.call(report.querySelectorAll(".er-section[id]"), function (section) {
        observer.observe(section);
      });
    }
  }

  onReady(initReportInteractions);
})();
