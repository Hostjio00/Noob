var fetchBtn = document.getElementById('fetchBtn');
var templateInput = document.getElementById('template');
var countSelect = document.getElementById('count');
var spinner = document.getElementById('spinner');
var output = document.getElementById('output');

fetchBtn.addEventListener('click', function() {
  var template = templateInput.value.trim();
  var numbers = parseInt(countSelect.value, 10);

  if (!template) {
    showError('Please enter a number range template.');
    return;
  }

  output.innerHTML = '';
  spinner.classList.add('active');
  fetchBtn.disabled = true;

  fetch('/api/token')
  .then(function(tokenRes) { return tokenRes.json(); })
  .then(function(tokenData) {
    if (!tokenData.token) throw new Error('Could not get session token.');
    return fetch('/api/fetch-numbers', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': tokenData.token,
      },
      body: JSON.stringify({ template: template, numbers: numbers }),
    });
  })
  .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
  .then(function(result) {
    if (!result.ok) {
      showError(result.data.error || 'Request failed.');
      return;
    }
    if (result.data.error) {
      showError('API Error: ' + JSON.stringify(result.data.error));
      return;
    }
    renderResults(result.data);
  })
  .catch(function(err) {
    showError('Network error: ' + err.message);
  })
  .finally(function() {
    spinner.classList.remove('active');
    fetchBtn.disabled = false;
  });
});

function renderResults(data) {
  var numbersData = data.numbers;
  var numbersResult = numbersData && numbersData.result;

  if (numbersData && numbersData.error) {
    showError('Number list error: ' + JSON.stringify(numbersData.error));
    return;
  }

  if (!numbersResult) {
    showError('No numbers returned.');
    return;
  }

  var list = numbersResult.trunk_number_list || (Array.isArray(numbersResult) ? numbersResult : [numbersResult]);
  var numberStrings = [];
  for (var i = 0; i < list.length; i++) {
    var item = list[i];
    var num;
    if (item && item.number) {
      num = String(item.number);
    } else if (typeof item === 'string') {
      num = item;
    } else {
      num = JSON.stringify(item);
    }
    if (num.charAt(0) !== '+') {
      num = '+' + num;
    }
    numberStrings.push(num);
  }

  var html = '<div class="results"><div class="results-list">';
  for (var j = 0; j < numberStrings.length; j++) {
    html += '<div class="number-item">' + escapeHtml(numberStrings[j]) + '</div>';
  }
  html += '</div>';
  html += '<button class="copy-all-btn" id="copyAllBtn">Copy All</button>';
  html += '</div>';

  output.innerHTML = html;
  window._allNumbers = numberStrings;

  document.getElementById('copyAllBtn').addEventListener('click', copyAllNumbers);
}

function showError(msg) {
  output.innerHTML = '<div class="error-msg">' + escapeHtml(msg) + '</div>';
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function copyAllNumbers() {
  var text = (window._allNumbers || []).join('\n');
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.getElementById('copyAllBtn');
    if (btn) {
      btn.textContent = 'Copied!';
      setTimeout(function() { btn.textContent = 'Copy All'; }, 1500);
    }
  }).catch(function() {});
}
