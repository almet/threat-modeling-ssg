(function () {
    function trackZoomOrigin(el) {
        el.addEventListener("mousemove", function (e) {
            var r = el.getBoundingClientRect();
            el.style.transformOrigin =
                ((e.clientX - r.left) / r.width * 100).toFixed(1) + "% " +
                ((e.clientY - r.top) / r.height * 100).toFixed(1) + "%";
        });
    }

    var dfdContainers = Array.prototype.slice.call(
        document.querySelectorAll(".dfd-container")
    );
    if (dfdContainers.length && typeof Viz !== "undefined") {
        Viz.instance().then(function (viz) {
            dfdContainers.forEach(function (container) {
                var source = container.querySelector(".diagram-source");
                if (!source) return;
                container.appendChild(viz.renderSVGElement(source.textContent));
            });
        });
        dfdContainers.forEach(trackZoomOrigin);
    }

    var mermaidContainers = Array.prototype.slice.call(
        document.querySelectorAll(".mermaid-container")
    );
    if (mermaidContainers.length && typeof mermaid !== "undefined") {
        var themeVars = function () {
            var s = getComputedStyle(document.documentElement);
            var v = function (name) { return s.getPropertyValue(name).trim(); };
            return {
                background:         v('--color-bg'),
                primaryColor:       v('--color-bg-header'),
                primaryTextColor:   v('--color-text'),
                primaryBorderColor: v('--color-border'),
                lineColor:          v('--color-accent'),
                secondaryColor:     v('--color-bg-container'),
                tertiaryColor:      v('--color-bg-hover'),
                noteBkgColor:       v('--color-bg-hover'),
                noteTextColor:      v('--color-text'),
                activationBkgColor: v('--color-bg-hover'),
                actorBkg:           v('--color-bg-header'),
                actorBorder:        v('--color-border'),
                actorTextColor:     v('--color-text'),
                actorLineColor:     v('--color-border'),
                signalColor:        v('--color-text-dim'),
                signalTextColor:    v('--color-text-dim'),
                fontFamily:         "'Share Tech Mono', monospace",
            };
        };

        var renderDiagrams = function () {
            mermaid.initialize({
                startOnLoad: false,
                theme: "base",
                themeVariables: themeVars(),
            });
            var nodes = [];
            mermaidContainers.forEach(function (container) {
                var source = container.querySelector(".diagram-source");
                if (!source) return;
                container.querySelectorAll(".mermaid").forEach(function (el) {
                    el.remove();
                });
                var pre = document.createElement("pre");
                pre.className = "mermaid";
                pre.textContent = source.textContent;
                container.appendChild(pre);
                nodes.push(pre);
            });
            mermaid.run({ nodes: nodes });
        };

        renderDiagrams();
        document.addEventListener("theme-changed", function () {
            if (!mermaidContainers.some(function (c) { return document.contains(c); })) return;
            setTimeout(renderDiagrams, 50);
        });
        mermaidContainers.forEach(trackZoomOrigin);
    }
})();
