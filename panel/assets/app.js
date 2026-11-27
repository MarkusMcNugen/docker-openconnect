(function () {
  'use strict';

  var root = document.documentElement;
  var KEY = 'ocpanel-theme';
  var SUN = 'M120,40V16a8,8,0,0,1,16,0V40a8,8,0,0,1-16,0Zm72,88a64,64,0,1,1-64-64A64.07,64.07,0,0,1,192,128Zm-16,0a48,48,0,1,0-48,48A48.05,48.05,0,0,0,176,128ZM58.34,69.66A8,8,0,0,0,69.66,58.34l-16-16A8,8,0,0,0,42.34,53.66Zm0,116.68-16,16a8,8,0,0,0,11.32,11.32l16-16a8,8,0,0,0-11.32-11.32ZM192,72a8,8,0,0,0,5.66-2.34l16-16a8,8,0,0,0-11.32-11.32l-16,16A8,8,0,0,0,192,72Zm5.66,114.34a8,8,0,0,0-11.32,11.32l16,16a8,8,0,0,0,11.32-11.32ZM48,128a8,8,0,0,0-8-8H16a8,8,0,0,0,0,16H40A8,8,0,0,0,48,128Zm80,80a8,8,0,0,0-8,8v24a8,8,0,0,0,16,0V216A8,8,0,0,0,128,208Zm112-88H216a8,8,0,0,0,0,16h24a8,8,0,0,0,0-16Z';
  var SVG = 'http://www.w3.org/2000/svg';
  var MOON = 'M233.54,142.23a8,8,0,0,0-8-2,88.08,88.08,0,0,1-109.8-109.8,8,8,0,0,0-10-10,104.84,104.84,0,0,0-52.91,37A104,104,0,0,0,136,224a103.09,103.09,0,0,0,62.52-20.88,104.84,104.84,0,0,0,37-52.91A8,8,0,0,0,233.54,142.23ZM188.9,190.34A88,88,0,0,1,65.66,67.11a89,89,0,0,1,31.4-26A106,106,0,0,0,96,56,104.11,104.11,0,0,0,200,160a106,106,0,0,0,14.92-1.06A89,89,0,0,1,188.9,190.34Z';

  // Storage can be refused, as in a private window; the theme then lasts
  // for the page only.
  function saved() {
    try {
      return window.localStorage.getItem(KEY);
    } catch (error) {
      return null;
    }
  }

  function save(theme) {
    try {
      window.localStorage.setItem(KEY, theme);
    } catch (error) {
      return;
    }
  }

  function effective() {
    var theme = root.getAttribute('data-theme');
    if (theme === 'dark' || theme === 'light') {
      return theme;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  var chosen = saved();
  if (chosen === 'dark' || chosen === 'light') {
    root.setAttribute('data-theme', chosen);
  }

  function describe(button) {
    var dark = effective() === 'dark';
    var text = dark ? 'Switch to the light theme' : 'Switch to the dark theme';
    button.setAttribute('aria-label', text);
    button.setAttribute('title', text);
    var path = button.querySelector('path');
    if (path) {
      path.setAttribute('d', dark ? SUN : MOON);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById('theme-toggle');
    if (!button) {
      return;
    }
    describe(button);
    button.addEventListener('click', function () {
      var next = effective() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      save(next);
      describe(button);
    });
  });

  // The dashboard's charts: the history from /api/history drawn as SVG with
  // attributes and classes only, then extended every sampling interval.
  var MEGABIT = 125000;
  var CHARTS = {
    sessions: {
      integer: true,
      series: [{ name: 'Connected', key: 'sessions', css: 's1', scale: 1 }],
      format: function (value) { return String(Math.round(value)); },
      words: function (value) {
        var count = Math.round(value);
        return count + (count === 1 ? ' session' : ' sessions');
      }
    },
    throughput: {
      integer: false,
      series: [
        { name: 'To clients', key: 'to_clients', css: 's1', scale: 1 / MEGABIT },
        { name: 'From clients', key: 'from_clients', css: 's2', scale: 1 / MEGABIT }
      ],
      format: function (value) { return value.toFixed(value < 10 ? 1 : 0); },
      words: function (value) {
        return value.toFixed(value < 10 ? 1 : 0) + ' Mbps';
      }
    }
  };
  var history = null;
  var limit = 0;

  function node(name, attributes, parent) {
    var created = document.createElementNS(SVG, name);
    Object.keys(attributes).forEach(function (key) {
      created.setAttribute(key, attributes[key]);
    });
    parent.appendChild(created);
    return created;
  }

  function clockText(seconds) {
    var date = new Date(seconds * 1000);
    return String(date.getHours()).padStart(2, '0') + ':' +
      String(date.getMinutes()).padStart(2, '0');
  }

  function niceStep(max, integer) {
    var raw = max / 4;
    var power = Math.pow(10, Math.floor(Math.log10(raw)));
    var step = [1, 2, 5, 10].map(function (m) { return m * power; })
      .filter(function (s) { return s >= raw; })[0];
    return integer ? Math.max(1, Math.ceil(step)) : step;
  }

  function seriesValues(spec) {
    return spec.series.map(function (series) {
      return history[series.key].map(function (value) {
        return value === null ? null : value * series.scale;
      });
    });
  }

  function summarize(spec, values) {
    var last = history.time.length - 1;
    var main = values[0];
    var busiest = -1;
    main.forEach(function (value, index) {
      if (value !== null && (busiest < 0 || value > main[busiest])) { busiest = index; }
    });
    if (busiest < 0 || main[last] === null) {
      return 'The history fills in as the server is sampled.';
    }
    var now = spec.series.map(function (series, at) {
      var value = values[at][last];
      return value === null ? '' : (spec.series.length === 1 ? spec.words(value) :
        spec.words(value) + ' ' + series.name.toLowerCase());
    }).filter(Boolean).join(' and ');
    return 'Now ' + now + '. Busiest: ' + spec.words(main[busiest]) +
      (spec.series.length === 1 ? '' : ' ' + spec.series[0].name.toLowerCase()) +
      ' at ' + clockText(history.time[busiest]) + '.';
  }

  function draw(card) {
    var spec = CHARTS[card.getAttribute('data-chart')];
    var plot = card.querySelector('[data-plot]');
    var count = history.time.length;
    var values = seriesValues(spec);
    card.querySelector('[data-summary]').textContent = summarize(spec, values);
    plot.textContent = '';
    if (count < 2) { return; }
    var width = Math.max(plot.clientWidth, 260);
    var height = 220;
    var left = 44;
    var right = 64;
    var top = 14;
    var bottom = 26;
    var max = 0;
    values.forEach(function (list) {
      list.forEach(function (value) { if (value !== null && value > max) { max = value; } });
    });
    var step = niceStep(max || 1, spec.integer);
    var ceiling = Math.max(step, Math.ceil((max || 1) / step) * step);
    var first = history.time[0];
    var span = Math.max(history.time[count - 1] - first, 1);
    var at = function (time) { return left + (time - first) / span * (width - left - right); };
    // One point per 3 pixels, each the average of its samples, so a day of
    // samples reads as a line rather than a band.
    var buckets = Math.max(2, Math.min(count, Math.floor((width - left - right) / 3)));
    var points = [];
    for (var b = 0; b < buckets; b++) {
      var from = Math.floor(b * count / buckets);
      var to = Math.max(from + 1, Math.floor((b + 1) * count / buckets));
      points.push({
        first: from,
        last: to - 1,
        values: values.map(function (list) {
          var sum = 0;
          var seen = 0;
          for (var k = from; k < to; k++) {
            if (list[k] !== null) { sum += list[k]; seen += 1; }
          }
          return seen ? sum / seen : null;
        })
      });
    }
    var x = function (point) { return at((history.time[point.first] + history.time[point.last]) / 2); };
    var y = function (value) { return top + (1 - value / ceiling) * (height - top - bottom); };
    var svg = node('svg', { viewBox: '0 0 ' + width + ' ' + height, width: width, height: height, class: 'chart-svg', 'aria-hidden': 'true' }, plot);
    // Every tick carries the decimals its step needs, so 0 and 10 read alike.
    var decimals = Math.max(0, -Math.floor(Math.log10(step)));
    for (var tick = 0; tick <= ceiling + step / 2; tick += step) {
      node('line', { x1: left, x2: width - right, y1: y(tick), y2: y(tick), class: 'chart-grid' }, svg);
      node('text', { x: left - 8, y: y(tick) + 4, 'text-anchor': 'end', class: 'chart-axis' }, svg)
        .textContent = tick.toFixed(decimals);
    }
    [0, 0.25, 0.5, 0.75, 1].forEach(function (share, at) {
      var time = first + span * share;
      node('text', { x: left + share * (width - left - right), y: height - 6, 'text-anchor': at === 0 ? 'start' : (at === 4 ? 'end' : 'middle'), class: 'chart-axis' }, svg)
        .textContent = clockText(time);
    });
    var ends = [];
    values.forEach(function (list, which) {
      var path = '';
      var drawing = false;
      points.forEach(function (point) {
        var value = point.values[which];
        if (value === null) { drawing = false; return; }
        path += (drawing ? 'L' : 'M') + x(point).toFixed(1) + ',' + y(value).toFixed(1);
        drawing = true;
      });
      node('path', { d: path, class: 'chart-line ' + spec.series[which].css }, svg);
      var tail = points[points.length - 1].values[which];
      if (tail !== null && list[count - 1] !== null) {
        ends.push({ y: y(tail) + 4, text: spec.format(list[count - 1]) });
      }
    });
    ends.sort(function (a, b) { return a.y - b.y; });
    ends.forEach(function (end, at) {
      if (at > 0 && end.y - ends[at - 1].y < 14) { end.y = ends[at - 1].y + 14; }
      node('text', { x: width - right + 8, y: end.y, class: 'chart-end' }, svg).textContent = end.text;
    });
    var cross = node('g', { class: 'chart-cross', visibility: 'hidden' }, svg);
    var rule = node('line', { y1: top, y2: height - bottom, class: 'chart-rule' }, cross);
    var dots = spec.series.map(function (series) {
      return node('circle', { r: 4, class: 'chart-dot ' + series.css }, cross);
    });
    var tip = node('g', { class: 'chart-tip' }, cross);
    var box = node('rect', { rx: 6, height: 20 + 16 * spec.series.length, class: 'chart-tip-box' }, tip);
    var lines = [node('text', { x: 10, y: 18, class: 'chart-tip-time' }, tip)].concat(spec.series.map(function (series, at) {
      node('line', { x1: 10, x2: 22, y1: 32 + 16 * at, y2: 32 + 16 * at, class: 'chart-key ' + series.css }, tip);
      return node('text', { x: 28, y: 36 + 16 * at, class: 'chart-tip-text' }, tip);
    }));
    var live = card.querySelector('[data-live]');
    var shown = points.length - 1;
    function when(point) {
      var start = clockText(history.time[point.first]);
      var end = clockText(history.time[point.last]);
      return start === end ? start : start + ' to ' + end + ', on average';
    }
    function show(index, speak) {
      shown = Math.max(0, Math.min(points.length - 1, index));
      var point = points[shown];
      var spot = x(point);
      rule.setAttribute('x1', spot);
      rule.setAttribute('x2', spot);
      lines[0].textContent = when(point);
      spec.series.forEach(function (series, which) {
        var value = point.values[which];
        dots[which].setAttribute('visibility', value === null ? 'hidden' : 'visible');
        if (value !== null) {
          dots[which].setAttribute('cx', spot);
          dots[which].setAttribute('cy', y(value));
        }
        lines[which + 1].textContent = (value === null ? 'No rate yet' : spec.format(value)) + '  ' + series.name;
      });
      var widest = Math.max.apply(null, lines.map(function (line) { return line.getComputedTextLength(); }));
      box.setAttribute('width', widest + 38);
      var tipX = spot + 12 + widest + 38 > width - right ? spot - 12 - widest - 38 : spot + 12;
      tip.setAttribute('transform', 'translate(' + tipX + ',' + top + ')');
      cross.setAttribute('visibility', 'visible');
      if (speak) {
        live.textContent = when(point) + ': ' + spec.series.map(function (series, which) {
          var value = point.values[which];
          return (value === null ? 'no rate yet' : spec.words(value)) +
            (spec.series.length === 1 ? '' : ' ' + series.name.toLowerCase());
        }).join(', ');
      }
    }
    function nearest(clientX) {
      var bounds = svg.getBoundingClientRect();
      var share = (clientX - bounds.left - left) / (width - left - right);
      return Math.round(share * (points.length - 1));
    }
    svg.addEventListener('pointermove', function (event) { show(nearest(event.clientX), false); });
    svg.addEventListener('pointerleave', function () { cross.setAttribute('visibility', 'hidden'); });
    plot.onkeydown = function (event) {
      var moves = { ArrowLeft: shown - 1, ArrowRight: shown + 1, Home: 0, End: points.length - 1 };
      if (moves[event.key] === undefined) { return; }
      event.preventDefault();
      show(moves[event.key], true);
    };
    plot.onfocus = function () { show(shown, true); };
    plot.onblur = function () { cross.setAttribute('visibility', 'hidden'); };
    fillTable(card, spec, values);
  }

  function fillTable(card, spec, values) {
    var holder = card.querySelector('[data-table]');
    var every = Math.max(1, Math.round(900 / history.interval));
    var rows = ['<table class="t"><thead><tr><th scope="col">Time</th>'];
    spec.series.forEach(function (series) { rows.push('<th scope="col">' + series.name + '</th>'); });
    rows.push('</tr></thead><tbody>');
    for (var index = history.time.length - 1; index >= 0; index -= every) {
      rows.push('<tr><td>' + clockText(history.time[index]) + '</td>');
      values.forEach(function (list) {
        rows.push('<td>' + (list[index] === null ? 'No rate yet' : spec.format(list[index])) + '</td>');
      });
      rows.push('</tr>');
    }
    rows.push('</tbody></table>');
    holder.innerHTML = rows.join('');
  }

  function drawAll() {
    document.querySelectorAll('[data-chart]').forEach(draw);
  }

  function failed(text) {
    document.querySelectorAll('[data-chart] [data-summary]').forEach(function (summary) {
      summary.textContent = text;
    });
  }

  function load(since) {
    var url = '/api/history' + (since ? '?since=' + since : '');
    return fetch(url, { credentials: 'same-origin', cache: 'no-store' }).then(function (response) {
      if (response.status === 401) { throw new Error('Sign in again to see the history.'); }
      if (!response.ok) { throw new Error('The history could not be loaded (' + response.status + ').'); }
      return response.json();
    });
  }

  function extend(fresh) {
    ['time', 'sessions', 'to_clients', 'from_clients'].forEach(function (key) {
      history[key] = history[key].concat(fresh[key]).slice(-limit);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var cards = document.querySelectorAll('[data-chart]');
    if (!cards.length) { return; }
    cards.forEach(function (card) {
      var toggle = card.querySelector('[data-toggle-table]');
      toggle.addEventListener('click', function () {
        var table = card.querySelector('[data-table]');
        var showing = table.hidden;
        table.hidden = !showing;
        card.querySelector('[data-plot]').hidden = showing;
        toggle.textContent = showing ? 'Show the chart' : 'Show as a table';
      });
    });
    load(0).then(function (first) {
      history = first;
      limit = Math.max(first.time.length, Math.round(86400 / first.interval));
      drawAll();
      new ResizeObserver(drawAll).observe(cards[0]);
      window.setInterval(function () {
        var last = history.time.length ? history.time[history.time.length - 1] : 0;
        load(last).then(function (fresh) {
          if (fresh.time.length) { extend(fresh); drawAll(); }
        }).catch(function (error) { failed(error.message); });
      }, first.interval * 1000);
    }).catch(function (error) { failed(error.message); });
  });

  // The helper reads new events every 2 seconds, so a poll every 3 seconds
  // shows an event within 5 seconds of ocserv reporting it.
  var EVENT_POLL_MS = 3000;

  function two(number) {
    return String(number).padStart(2, '0');
  }

  function localTimes(scope) {
    scope.querySelectorAll('time[data-local-time]').forEach(function (time) {
      var date = new Date(time.getAttribute('datetime'));
      if (isNaN(date.getTime())) { return; }
      var clock = two(date.getHours()) + ':' + two(date.getMinutes()) + ':' + two(date.getSeconds());
      time.textContent = time.getAttribute('data-local-time') === 'date'
        ? date.getFullYear() + '-' + two(date.getMonth() + 1) + '-' + two(date.getDate()) + ' ' + clock
        : clock;
      time.title = date.toLocaleString();
    });
  }

  function paragraph(className, text, parent) {
    var created = document.createElement('p');
    created.className = className;
    created.textContent = text;
    parent.appendChild(created);
  }

  function eventItem(row) {
    var item = document.createElement('li');
    item.className = 'ev';
    item.dataset.kind = row.kind;
    var icon = document.createElement('span');
    icon.className = 'ev-ic ' + row.tone;
    node('path', { d: row.icon }, node('svg', { 'class': 'ic-sm', viewBox: '0 0 256 256', 'aria-hidden': 'true' }, icon));
    item.appendChild(icon);
    var body = document.createElement('div');
    body.className = 'ev-body';
    paragraph('ev-t', row.text, body);
    if (row.meta || row.place) {
      var meta = document.createElement('p');
      meta.className = 'ev-m';
      if (row.place) {
        var place = document.createElement('span');
        place.className = 'place';
        var flag = document.createElement('img');
        flag.className = 'flag';
        flag.src = row.place.flag;
        flag.alt = '';
        place.appendChild(flag);
        place.appendChild(document.createTextNode(row.place.name));
        meta.appendChild(place);
        if (row.meta) { meta.appendChild(document.createTextNode(' · ')); }
      }
      if (row.meta) { meta.appendChild(document.createTextNode(row.meta)); }
      body.appendChild(meta);
    }
    item.appendChild(body);
    var time = document.createElement('time');
    time.className = 'ev-time';
    time.setAttribute('datetime', row.stamp);
    time.setAttribute('data-local-time', '');
    time.textContent = row.clock + ' UTC';
    item.appendChild(time);
    localTimes(item);
    return item;
  }

  document.addEventListener('DOMContentLoaded', function () {
    localTimes(document);
    var list = document.querySelector('[data-events]');
    if (!list) { return; }
    var after = Number(list.dataset.after) || 0;
    var filter = list.dataset.filter;
    var empty = document.querySelector('[data-events-empty]');
    var announce = document.querySelector('[data-events-announce]');
    var pill = document.querySelector('[data-events-live-pill]');
    pill.hidden = false;
    var timer = window.setInterval(function () {
      fetch('/api/events?after=' + after, { credentials: 'same-origin', cache: 'no-store' }).then(function (response) {
        if (response.status === 401) { throw new Error('Sign in again to see new events.'); }
        if (!response.ok) { throw new Error('New events could not be loaded (' + response.status + ').'); }
        return response.json();
      }).then(function (rows) {
        var shown = 0;
        rows.forEach(function (row) {
          after = Math.max(after, row.number);
          if (filter !== 'all' && row.kind !== filter) { return; }
          list.insertBefore(eventItem(row), list.firstChild);
          shown += 1;
        });
        if (shown) {
          empty.hidden = true;
          announce.textContent = shown === 1 ? '1 new event' : shown + ' new events';
        }
      }).catch(function (error) {
        window.clearInterval(timer);
        pill.className = 'pill pill-warn';
        pill.textContent = 'Not updating';
        pill.title = error.message;
        announce.textContent = error.message;
      });
    }, EVENT_POLL_MS);
  });

  // Passkeys. The panel gives the browser's passkey prompt its options as
  // JSON with binary fields in unpadded base64url, and takes the browser's
  // answer back in the same form; the browser's API works in array buffers.
  function fromBase64url(text) {
    var base64 = text.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) { base64 += '='; }
    var binary = window.atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    return bytes.buffer;
  }

  function toBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Options the panel leaves unset arrive as null, which the browser's API
  // refuses where it expects the member to be absent.
  function withoutNulls(value) {
    if (Array.isArray(value)) { return value.map(withoutNulls); }
    if (value === null || typeof value !== 'object') { return value; }
    var kept = {};
    Object.keys(value).forEach(function (key) {
      if (value[key] !== null) { kept[key] = withoutNulls(value[key]); }
    });
    return kept;
  }

  function creationOptions(json) {
    var options = withoutNulls(json).publicKey;
    options.challenge = fromBase64url(options.challenge);
    options.user.id = fromBase64url(options.user.id);
    (options.excludeCredentials || []).forEach(function (credential) {
      credential.id = fromBase64url(credential.id);
    });
    return { publicKey: options };
  }

  function requestOptions(json) {
    var options = withoutNulls(json).publicKey;
    options.challenge = fromBase64url(options.challenge);
    (options.allowCredentials || []).forEach(function (credential) {
      credential.id = fromBase64url(credential.id);
    });
    return { publicKey: options };
  }

  function registration(credential) {
    var response = credential.response;
    return {
      id: credential.id,
      rawId: toBase64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: toBase64url(response.attestationObject),
        clientDataJSON: toBase64url(response.clientDataJSON),
        transports: typeof response.getTransports === 'function' ? response.getTransports() : []
      },
      extensions: credential.getClientExtensionResults()
    };
  }

  function assertion(credential) {
    var response = credential.response;
    return {
      id: credential.id,
      rawId: toBase64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: toBase64url(response.authenticatorData),
        clientDataJSON: toBase64url(response.clientDataJSON),
        signature: toBase64url(response.signature),
        userHandle: response.userHandle ? toBase64url(response.userHandle) : null
      },
      extensions: credential.getClientExtensionResults()
    };
  }

  // Posts form fields and reads the panel's JSON answer: the passkey
  // prompt's options, {"next": page} or {"error": message}.
  function post(url, fields) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString()
    }).then(function (response) {
      var type = response.headers.get('Content-Type') || '';
      if (type.indexOf('application/json') !== 0) {
        throw new Error('The panel could not finish this step (' + response.status + ').');
      }
      return response.json().then(function (body) {
        if (body.error) { throw new Error(body.error); }
        return body;
      });
    });
  }

  // How the browser's passkey prompt ended, in words. NotAllowedError is a
  // prompt the admin closed or let run out of time.
  function promptProblem(error) {
    if (error.name === 'NotAllowedError') {
      return 'The passkey prompt was closed or ran out of time. Try again when you are ready.';
    }
    if (error.name === 'InvalidStateError') {
      return 'This device already holds one of your passkeys. Use another device or security key.';
    }
    if (error.name === 'SecurityError') {
      return 'This browser refused a passkey for this address: ' + error.message;
    }
    return error.message;
  }

  function showProblem(box, text) {
    box.querySelector('span').textContent = text;
    box.hidden = false;
  }

  document.addEventListener('DOMContentLoaded', function () {
    var box = document.querySelector('[data-passkey-error]');
    var add = document.querySelector('[data-passkey-add]');
    var use = document.querySelector('[data-passkey-sign-in]');
    if (!box || (!add && !use)) {
      return;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      showProblem(box, 'This browser cannot use passkeys.');
      return;
    }
    if (add) {
      add.hidden = false;
      add.addEventListener('submit', function (event) {
        event.preventDefault();
        var button = add.querySelector('button[type="submit"]');
        var csrf = add.elements.namedItem('csrf').value;
        var name = add.elements.namedItem('name').value;
        box.hidden = true;
        button.disabled = true;
        post('/account/passkeys/start', { csrf: csrf, name: name }).then(function (options) {
          return navigator.credentials.create(creationOptions(options));
        }).then(function (credential) {
          return post('/account/passkeys', {
            csrf: csrf,
            credential: JSON.stringify(registration(credential))
          });
        }).then(function (answer) {
          window.location.assign(answer.next);
        }).catch(function (error) {
          button.disabled = false;
          showProblem(box, promptProblem(error));
        });
      });
    }
    if (use) {
      use.hidden = false;
      use.addEventListener('click', function () {
        box.hidden = true;
        use.disabled = true;
        post('/second-factor/passkey/start', {}).then(function (options) {
          return navigator.credentials.get(requestOptions(options));
        }).then(function (credential) {
          return post('/second-factor/passkey', {
            credential: JSON.stringify(assertion(credential))
          });
        }).then(function (answer) {
          window.location.assign(answer.next);
        }).catch(function (error) {
          use.disabled = false;
          showProblem(box, promptProblem(error));
        });
      });
    }
  });

  // The onboarding kit: Print and Copy work only with this script, so they
  // show only with it, and the client sections become tabs.
  document.addEventListener('DOMContentLoaded', function () {
    var print = document.querySelector('[data-print]');
    if (print) {
      print.hidden = false;
      print.addEventListener('click', function () {
        window.print();
      });
    }
    if (navigator.clipboard && window.isSecureContext) {
      document.querySelectorAll('[data-copy]').forEach(function (button) {
        var source = document.getElementById(button.getAttribute('data-copy'));
        var label = button.getAttribute('aria-label');
        if (!source) {
          return;
        }
        button.hidden = false;
        button.addEventListener('click', function () {
          navigator.clipboard.writeText(source.textContent).then(function () {
            button.setAttribute('aria-label', 'Copied');
            button.title = 'Copied';
            window.setTimeout(function () {
              button.setAttribute('aria-label', label);
              button.title = label;
            }, 2000);
          }, function (error) {
            button.title = 'Could not copy: ' + error.message;
          });
        });
      });
    }
    document.querySelectorAll('[data-tab-set]').forEach(function (set) {
      var tabs = set.querySelector('[data-tabs]');
      if (!tabs) {
        return;
      }
      var buttons = Array.prototype.slice.call(tabs.querySelectorAll('[role="tab"]'));
      function show(chosen) {
        buttons.forEach(function (button) {
          var on = button === chosen;
          button.classList.toggle('on', on);
          button.setAttribute('aria-selected', on ? 'true' : 'false');
          button.tabIndex = on ? 0 : -1;
          document.getElementById(button.getAttribute('aria-controls')).hidden = !on;
        });
      }
      buttons.forEach(function (button, index) {
        button.addEventListener('click', function () {
          show(button);
        });
        button.addEventListener('keydown', function (event) {
          var step = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
          if (step) {
            var next = buttons[(index + step + buttons.length) % buttons.length];
            show(next);
            next.focus();
            event.preventDefault();
          }
        });
      });
      tabs.hidden = false;
      set.classList.add('tabs-on');
      show(buttons[0]);
    });
    document.querySelectorAll('[data-password-choice]').forEach(function (set) {
      var typed = set.querySelector('[data-typed-password]');
      function update() {
        var chosen = set.querySelector('input[name="password_choice"]:checked');
        var typing = Boolean(chosen) && chosen.value === 'type';
        typed.hidden = !typing;
        typed.required = typing;
        if (!typing) {
          typed.value = '';
        }
      }
      set.addEventListener('change', update);
      update();
    });
    // A rule end's typed network shows, and is required, only while its list
    // chooses another network.
    document.querySelectorAll('select[data-other]').forEach(function (select) {
      var field = document.getElementById(select.getAttribute('data-other'));
      var typed = field && field.querySelector('input');
      if (!typed) {
        return;
      }
      function update() {
        var other = select.value === 'other';
        field.hidden = !other;
        typed.required = other;
        if (!other) {
          typed.value = '';
        }
      }
      select.addEventListener('change', update);
      update();
    });
  });

  // Row actions open in dialogs through the command attribute, which needs
  // no script; a browser without it opens and closes them here.
  if (!('command' in HTMLButtonElement.prototype)) {
    document.addEventListener('click', function (event) {
      var button = event.target.closest('button[commandfor]');
      if (!button) { return; }
      var dialog = document.getElementById(button.getAttribute('commandfor'));
      if (!dialog || typeof dialog.showModal !== 'function') { return; }
      if (button.getAttribute('command') === 'show-modal') {
        dialog.showModal();
      } else if (button.getAttribute('command') === 'close') {
        dialog.close();
      }
    });
  }
})();
