document.body.addEventListener('htmx:afterRequest', function (evt) {
  const targetError = evt.target.attributes.getNamedItem('hx-target-error')
  if (evt.detail.failed && targetError) {
    msg = "Something bad happened. Please contact site admin";
    if(evt.detail.xhr.status == 400 || evt.detail.xhr.status == 401 || evt.detail.xhr.status == 429) {
        msg = evt.detail.xhr.responseText;
    }

    errAlert = document.getElementById(targetError.value)
    errAlert.innerHTML = msg;
    errAlert.style.display = "block";
    window.scrollTo(0, 0);
    if(targetError.value.indexOf('dismiss') !== -1) {
        setTimeout(() => {
            errAlert.style.display = "none";
        }, 3000);
    }
  }
});
document.body.addEventListener('htmx:beforeRequest', function (evt) {
  const targetError = evt.target.attributes.getNamedItem('hx-target-error')
  if (targetError) {
    document.getElementById(targetError.value).style.display = "none";
  }
});

function closeModal(ele) {
    var container = document.getElementById(ele)
    var backdrop = document.getElementById("modal-backdrop")
    var modal = document.getElementById("modal")

    modal.classList.remove("show")
    backdrop.classList.remove("show")

    setTimeout(function() {
        container.removeChild(backdrop)
        container.removeChild(modal)
    }, 200)
}

// dark/light toggle; the pre-paint init lives inline in header.html
(function () {
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var root = document.documentElement;
    var next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-bs-theme', next);
    localStorage.setItem('mokey-theme', next);
  });
})();

// Country code picker. One popover is shared by every phone field: opening a
// field moves it inside that field's wrapper, so its position is plain CSS.
// Follows the APG combobox pattern — focus stays in the search box and the
// active row is published through aria-activedescendant.
(function () {
  var pop, search, list, empty, wrap, btn, hidden, active;

  // visible options in the order they are shown, best match first
  var ranked = [];

  function setActive(li) {
    if (active) {
      active.classList.remove('is-active');
      active.setAttribute('aria-selected', 'false');
    }
    active = li;
    if (!active) {
      search.removeAttribute('aria-activedescendant');
      return;
    }
    active.classList.add('is-active');
    active.setAttribute('aria-selected', 'true');
    search.setAttribute('aria-activedescendant', active.id);
    active.scrollIntoView({ block: 'nearest' });
  }

  function filter() {
    var q = search.value.trim().toLowerCase();
    var digits = q.replace(/^\+/, '');
    var lead = [];
    var rest = [];

    Array.prototype.forEach.call(list.children, function (li) {
      var name = li.getAttribute('data-name').toLowerCase();
      var code = li.getAttribute('data-code');
      var hit = !q || name.indexOf(q) !== -1 || (digits && code.indexOf(digits) === 0);
      li.hidden = !hit;
      if (!hit) return;
      // what someone typing "un" wants is United Kingdom, not Brunei, and
      // "+44" is the UK rather than whoever shares the prefix and sorts first
      var best = !q || name.indexOf(q) === 0 || code === digits;
      (best ? lead : rest).push(li);
    });

    ranked = lead.concat(rest);
    ranked.forEach(function (li, i) { li.style.order = i; });
    empty.hidden = ranked.length > 0;
    setActive(ranked[0] || null);
  }

  function move(step) {
    if (!ranked.length) return;
    var i = ranked.indexOf(active) + step;
    if (i < 0) i = ranked.length - 1;
    if (i >= ranked.length) i = 0;
    setActive(ranked[i]);
  }

  // called on every outside click, so it has to be safe when nothing is open
  function close(refocus) {
    if (pop) pop.hidden = true;
    if (btn) {
      btn.setAttribute('aria-expanded', 'false');
      if (refocus) btn.focus();
    }
    wrap = btn = hidden = null;
  }

  function commit(li) {
    if (!li) return;
    hidden.value = li.getAttribute('data-code');
    btn.innerHTML = '';
    var flag = document.createElement('span');
    flag.className = 'mokey-dial-flag';
    flag.textContent = li.getAttribute('data-flag');
    var code = document.createElement('span');
    code.className = 'mokey-dial-code';
    code.textContent = '+' + li.getAttribute('data-code');
    var caret = document.createElement('i');
    caret.className = 'fa fa-chevron-down mokey-dial-caret';
    caret.setAttribute('aria-hidden', 'true');
    btn.appendChild(flag);
    btn.appendChild(code);
    btn.appendChild(caret);
    close(true);
  }

  function open(trigger) {
    pop = document.getElementById('dial-picker');
    if (!pop) return;
    search = document.getElementById('dial-search');
    list = document.getElementById('dial-list');
    empty = pop.querySelector('.mokey-dial-empty');

    btn = trigger;
    wrap = trigger.closest('[data-dial]');
    hidden = wrap.querySelector('input[type=hidden]');

    wrap.appendChild(pop);
    pop.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    search.value = '';
    filter();

    var current = hidden.value &&
      list.querySelector('[data-code="' + hidden.value + '"]');
    if (current) setActive(current);
    search.focus();
  }

  document.addEventListener('click', function (evt) {
    var trigger = evt.target.closest && evt.target.closest('.mokey-dial-btn');
    if (trigger) {
      evt.preventDefault();
      if (btn === trigger) { close(true); } else { close(false); open(trigger); }
      return;
    }
    if (!pop || pop.hidden) return;
    var opt = evt.target.closest('.mokey-dial-opt');
    if (opt) { commit(opt); return; }
    if (!evt.target.closest('.mokey-dial-pop')) close(false);
  });

  document.addEventListener('input', function (evt) {
    if (pop && !pop.hidden && evt.target === search) filter();
  });

  document.addEventListener('keydown', function (evt) {
    if (!pop || pop.hidden) return;
    switch (evt.key) {
      case 'ArrowDown': evt.preventDefault(); move(1); break;
      case 'ArrowUp': evt.preventDefault(); move(-1); break;
      case 'Home': evt.preventDefault(); setActive(ranked[0] || null); break;
      case 'End': evt.preventDefault(); setActive(ranked[ranked.length - 1] || null); break;
      case 'Enter': evt.preventDefault(); commit(active); break;
      case 'Escape': evt.preventDefault(); close(true); break;
      case 'Tab': close(false); break;
    }
  });
})();
