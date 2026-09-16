/* ============================================================
   ELITE TRADING — نظام الإشعارات
   ملف مشترك يُحمَّل في كل الصفحات
   ============================================================ */
(function () {
    "use strict";

    const PANEL_ID = "eliteNotifPanel";
    const BG_ID = "eliteNotifBg";
    const BADGE_ID = "eliteNotifBadge";
    let panel = null;
    let bg = null;
    let listEl = null;
    let unreadCountEl = null;

    // ===============================
    // CSS
    // ===============================
    function injectStyles() {
        if (document.getElementById("eliteNotifStyles")) return;
        const style = document.createElement("style");
        style.id = "eliteNotifStyles";
        style.textContent = `
            .elite-notif-bg{
                position:fixed; inset:0;
                background:rgba(0,0,0,0.6);
                backdrop-filter:blur(4px);
                z-index:9000;
                opacity:0; pointer-events:none;
                transition:opacity .25s ease;
            }
            .elite-notif-bg.show{ opacity:1; pointer-events:auto; }

            .elite-notif-panel{
                position:fixed;
                top:0; right:0;
                width:min(380px,92vw);
                height:100vh;
                background:#0d1615;
                border-left:1px solid #0e8f76;
                border-radius:26px 0 0 26px;
                z-index:9100;
                transform:translateX(105%);
                transition:transform .35s cubic-bezier(.22,1,.36,1);
                display:flex;
                flex-direction:column;
                box-shadow:-20px 0 60px rgba(0,0,0,.55);
                font-family:'Tajawal','Segoe UI',sans-serif;
                color:#eef4f2;
            }
            .elite-notif-panel.show{ transform:translateX(0); }

            .elite-notif-head{
                padding:20px 18px 14px;
                border-bottom:1px solid #1c2b28;
                display:flex; align-items:center; justify-content:space-between;
                gap:10px;
            }
            .elite-notif-head h3{
                font-size:17px; font-weight:800;
                display:flex; align-items:center; gap:8px;
                margin:0;
            }
            .elite-notif-head h3 svg{
                width:20px; height:20px; color:#17f0c3;
            }
            .elite-notif-head .count{
                background:rgba(239,74,74,0.15);
                color:#ef4a4a;
                font-size:10.5px;
                font-weight:800;
                padding:2px 8px;
                border-radius:6px;
                font-family:'Rajdhani',sans-serif;
                min-width:22px;
                text-align:center;
            }
            .elite-notif-head .count:empty{ display:none; }
            .elite-notif-close{
                width:34px; height:34px;
                border-radius:50%;
                border:1px solid #1c2b28;
                background:none;
                color:#8fa39e;
                cursor:pointer;
                display:flex;
                align-items:center;
                justify-content:center;
                font-size:16px;
                flex-shrink:0;
            }
            .elite-notif-close:hover{ color:#ef4a4a; border-color:rgba(239,74,74,.4); }

            .elite-notif-actions{
                padding:10px 18px;
                border-bottom:1px solid #1c2b28;
                display:flex;
                justify-content:flex-end;
            }
            .elite-notif-actions button{
                background:none;
                border:1px solid #0e8f76;
                color:#17f0c3;
                padding:6px 12px;
                border-radius:8px;
                font-size:11.5px;
                font-weight:700;
                cursor:pointer;
                font-family:inherit;
                transition:all .2s;
            }
            .elite-notif-actions button:hover{
                background:rgba(23,240,195,.08);
            }
            .elite-notif-actions button:disabled{
                opacity:.4;
                cursor:not-allowed;
            }

            .elite-notif-list{
                flex:1;
                overflow-y:auto;
                padding:8px 12px 20px;
            }
            .elite-notif-list::-webkit-scrollbar{ width:6px; }
            .elite-notif-list::-webkit-scrollbar-thumb{
                background:#1c2b28; border-radius:3px;
            }

            .elite-notif-item{
                display:flex;
                gap:12px;
                padding:12px 12px;
                border-radius:12px;
                background:#0f1a18;
                border:1px solid #1c2b28;
                margin-bottom:8px;
                cursor:pointer;
                transition:all .2s;
                position:relative;
            }
            .elite-notif-item:hover{
                border-color:#0e8f76;
                background:rgba(23,240,195,.03);
            }
            .elite-notif-item.unread{
                background:rgba(23,240,195,.05);
                border-color:rgba(23,240,195,.25);
            }
            .elite-notif-item.unread::after{
                content:'';
                position:absolute;
                top:14px; right:14px;
                width:8px; height:8px;
                border-radius:50%;
                background:#17f0c3;
                box-shadow:0 0 8px #17f0c3;
            }

            .elite-notif-icon{
                width:38px; height:38px;
                border-radius:11px;
                flex-shrink:0;
                display:flex;
                align-items:center;
                justify-content:center;
                font-size:17px;
                background:rgba(23,240,195,.1);
                color:#17f0c3;
            }
            .elite-notif-item[data-type="success"] .elite-notif-icon{
                background:rgba(34,224,106,.12); color:#22e06a;
            }
            .elite-notif-item[data-type="warning"] .elite-notif-icon{
                background:rgba(232,163,61,.12); color:#e8a33d;
            }
            .elite-notif-item[data-type="error"] .elite-notif-icon{
                background:rgba(239,74,74,.12); color:#ef4a4a;
            }
            .elite-notif-item[data-type="referral"] .elite-notif-icon{
                background:rgba(232,163,61,.15); color:#e8a33d;
            }

            .elite-notif-body{
                flex:1;
                min-width:0;
                padding-left:14px;
            }
            .elite-notif-title{
                font-size:13.5px;
                font-weight:800;
                margin-bottom:3px;
                line-height:1.4;
            }
            .elite-notif-message{
                font-size:12px;
                color:#8fa39e;
                line-height:1.6;
                word-break:break-word;
            }
            .elite-notif-time{
                font-size:10.5px;
                color:#5d726c;
                margin-top:5px;
            }

            .elite-notif-empty{
                text-align:center;
                padding:50px 20px;
                color:#5d726c;
                font-size:13px;
                line-height:1.9;
            }
            .elite-notif-empty svg{
                width:42px; height:42px;
                color:#5d726c;
                margin-bottom:10px;
                opacity:.6;
            }

            .elite-notif-loading{
                text-align:center;
                padding:40px 20px;
                color:#5d726c;
                font-size:13px;
            }

            /* شارة حمراء على 🔔 */
            .bell{
                position:relative;
            }
            .elite-notif-badge{
                position:absolute;
                top:-2px; left:-2px;
                background:#ef4a4a;
                color:#fff;
                font-size:9.5px;
                font-weight:900;
                min-width:18px;
                height:18px;
                border-radius:9px;
                display:flex;
                align-items:center;
                justify-content:center;
                padding:0 4px;
                border:2px solid #060a09;
                box-shadow:0 0 8px rgba(239,74,74,.6);
                font-family:'Rajdhani',sans-serif;
                animation:eliteNotifPulse 2s ease-in-out infinite;
                z-index:100;
            }
            .elite-notif-badge[hidden]{ display:none; }

            @keyframes eliteNotifPulse{
                0%,100%{ transform:scale(1); }
                50%{ transform:scale(1.1); }
            }

            @media (max-width:480px){
                .elite-notif-panel{
                    width:100vw;
                    border-radius:0;
                    border-left:none;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // ===============================
    // بناء الـ Panel
    // ===============================
    function buildPanel() {
        if (panel) return;

        bg = document.createElement("div");
        bg.className = "elite-notif-bg";
        bg.id = BG_ID;
        bg.addEventListener("click", closePanel);

        panel = document.createElement("aside");
        panel.className = "elite-notif-panel";
        panel.id = PANEL_ID;
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-modal", "true");
        panel.innerHTML = `
            <div class="elite-notif-head">
                <h3>
                    <svg viewBox="0 0 24 24" fill="none">
                        <path d="M12 2a6 6 0 0 0-6 6v3.5c0 .8-.3 1.6-.9 2.2L4 15h16l-1.1-1.3c-.6-.6-.9-1.4-.9-2.2V8a6 6 0 0 0-6-6z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
                        <path d="M9.5 18a2.5 2.5 0 0 0 5 0" stroke="currentColor" stroke-width="1.8"/>
                    </svg>
                    الإشعارات
                    <span class="count" id="${BADGE_ID}-panel"></span>
                </h3>
                <button class="elite-notif-close" aria-label="إغلاق" id="eliteNotifClose">✕</button>
            </div>
            <div class="elite-notif-actions">
                <button id="eliteNotifReadAll" disabled>تحديد الكل كمقروء</button>
            </div>
            <div class="elite-notif-list" id="eliteNotifList">
                <div class="elite-notif-loading">جارٍ التحميل...</div>
            </div>
        `;

        document.body.appendChild(bg);
        document.body.appendChild(panel);

        listEl = document.getElementById("eliteNotifList");
        unreadCountEl = document.getElementById(`${BADGE_ID}-panel`);

        document.getElementById("eliteNotifClose").addEventListener("click", closePanel);
        document.getElementById("eliteNotifReadAll").addEventListener("click", markAllRead);

        // ESC لإغلاق
        document.addEventListener("keydown", (e)=>{
            if (e.key === "Escape" && panel.classList.contains("show")) closePanel();
        });
    }

    // ===============================
    // فتح / إغلاق
    // ===============================
    function openPanel() {
        buildPanel();
        panel.classList.add("show");
        bg.classList.add("show");
        loadNotifications();
    }

    function closePanel() {
        if (panel) panel.classList.remove("show");
        if (bg) bg.classList.remove("show");
    }

    // ===============================
    // جلب الإشعارات
    // ===============================
    async function loadNotifications() {
        if (!listEl) return;
        listEl.innerHTML = '<div class="elite-notif-loading">جارٍ التحميل...</div>';
        try {
            const res = await fetch("/api/user/notifications", {
                credentials: "same-origin"
            });
            if (res.status === 401) {
                listEl.innerHTML = '<div class="elite-notif-empty">يجب تسجيل الدخول</div>';
                return;
            }
            if (!res.ok) throw new Error("HTTP " + res.status);
            const data = await res.json();
            const list = Array.isArray(data.notifications) ? data.notifications : [];
            renderList(list);
            updateBadgeFromList(list);
        } catch (e) {
            console.warn("failed to load notifications:", e.message);
            listEl.innerHTML = '<div class="elite-notif-empty">تعذر تحميل الإشعارات</div>';
        }
    }

    // ===============================
    // عرض
    // ===============================
    function renderList(list) {
        if (!list.length) {
            listEl.innerHTML = `
                <div class="elite-notif-empty">
                    <svg viewBox="0 0 24 24" fill="none">
                        <path d="M12 2a6 6 0 0 0-6 6v3.5c0 .8-.3 1.6-.9 2.2L4 15h16l-1.1-1.3c-.6-.6-.9-1.4-.9-2.2V8a6 6 0 0 0-6-6z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
                        <path d="M9.5 18a2.5 2.5 0 0 0 5 0" stroke="currentColor" stroke-width="1.5"/>
                    </svg>
                    <div>لا توجد إشعارات بعد</div>
                </div>
            `;
            return;
        }
        listEl.innerHTML = list.map(notifItemHTML).join("");

        // ربط click على كل عنصر
        listEl.querySelectorAll(".elite-notif-item").forEach(el=>{
            el.addEventListener("click", ()=> markRead(Number(el.dataset.id), el));
        });
    }

    const TYPE_ICONS = {
        info:     "ℹ️",
        success:  "✅",
        warning:  "⚠️",
        error:    "❌",
        referral: "🎁"
    };

    function notifItemHTML(n) {
        const type = n.type || "info";
        const icon = TYPE_ICONS[type] || "ℹ️";
        const unreadClass = n.read ? "" : "unread";
        const timeStr = formatTime(n.created_at);
        return `
            <div class="elite-notif-item ${unreadClass}" data-id="${n.id}" data-type="${type}">
                <div class="elite-notif-icon">${icon}</div>
                <div class="elite-notif-body">
                    <div class="elite-notif-title">${escapeHtml(n.title || "")}</div>
                    <div class="elite-notif-message">${escapeHtml(n.message || "")}</div>
                    <div class="elite-notif-time">${timeStr}</div>
                </div>
            </div>
        `;
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function formatTime(iso) {
        if (!iso) return "";
        let d;
        try { d = new Date(iso); } catch (e) { return ""; }
        if (isNaN(d)) return iso;

        const diff = (Date.now() - d.getTime()) / 1000; // seconds
        if (diff < 60) return "الآن";
        if (diff < 3600) return `منذ ${Math.floor(diff/60)} دقيقة`;
        if (diff < 86400) return `منذ ${Math.floor(diff/3600)} ساعة`;
        if (diff < 604800) return `منذ ${Math.floor(diff/86400)} يوم`;

        try {
            return d.toLocaleDateString("ar-EG", { day: "numeric", month: "short", year: "numeric" })
                 + " · "
                 + d.toLocaleTimeString("ar-EG", { hour: "2-digit", minute: "2-digit" });
        } catch (e) { return iso; }
    }

    // ===============================
    // تحديد كمقروء
    // ===============================
    async function markRead(id, el) {
        if (!el || !el.classList.contains("unread")) return;
        try {
            const res = await fetch(`/api/user/notifications/${id}/read`, {
                method: "POST",
                credentials: "same-origin"
            });
            if (!res.ok) return;
            el.classList.remove("unread");
            refreshBadgeCount();
        } catch (e) {
            console.warn("markRead error:", e.message);
        }
    }

    async function markAllRead() {
        const btn = document.getElementById("eliteNotifReadAll");
        if (!btn) return;
        btn.disabled = true;
        try {
            const res = await fetch("/api/user/notifications/read-all", {
                method: "POST",
                credentials: "same-origin"
            });
            if (!res.ok) return;
            if (listEl) listEl.querySelectorAll(".elite-notif-item.unread").forEach(el=>{
                el.classList.remove("unread");
            });
            refreshBadgeCount();
        } catch (e) {
            console.warn("markAllRead error:", e.message);
        } finally {
            btn.disabled = false;
        }
    }

    // ===============================
    // الشارة
    // ===============================
    function updateBadgeFromList(list) {
        const count = list.filter(n => !n.read).length;
        applyBadge(count);
    }

    async function refreshBadgeCount() {
        try {
            const res = await fetch("/api/user/notifications/unread-count", {
                credentials: "same-origin"
            });
            if (res.status === 401) {
                applyBadge(0);
                return;
            }
            if (!res.ok) return;
            const data = await res.json();
            applyBadge(Number(data.count) || 0);
        } catch (e) { /* silent */ }
    }

    function applyBadge(count) {
        const bell = document.getElementById("btnBell");
        if (!bell) return;

        let badge = bell.querySelector(".elite-notif-badge");
        if (!badge) {
            badge = document.createElement("span");
            badge.className = "elite-notif-badge";
            bell.appendChild(badge);
        }

        if (count > 0) {
            badge.textContent = count > 99 ? "99+" : String(count);
            badge.hidden = false;
        } else {
            badge.hidden = true;
        }

        if (unreadCountEl) {
            unreadCountEl.textContent = count > 0 ? count : "";
        }
        const readAllBtn = document.getElementById("eliteNotifReadAll");
        if (readAllBtn) readAllBtn.disabled = count === 0;
    }

    // ===============================
    // ربط زر 🔔 تلقائياً
    // ===============================
    function bindBell() {
        const bell = document.getElementById("btnBell");
        if (!bell) return;
        // نتأكد أننا لا نربط أكثر من مرة
        if (bell.dataset.eliteNotifBound === "1") return;
        bell.dataset.eliteNotifBound = "1";

        // نستخدم capture لنأخذ أولوية على المستمعين السابقين
        bell.addEventListener("click", (e)=>{
            e.preventDefault();
            e.stopPropagation();
            openPanel();
        }, true);

        refreshBadgeCount();
    }

    // ===============================
    // التشغيل
    // ===============================
    function init() {
        injectStyles();

        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", bindBell);
        } else {
            bindBell();
        }

        // فحص الشارة كل 30 ثانية
        setInterval(refreshBadgeCount, 30000);
    }

    init();

    // كشف للاستخدام الخارجي
    window.EliteNotifications = {
        open: openPanel,
        close: closePanel,
        refresh: refreshBadgeCount
    };
})();