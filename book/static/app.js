let currentBook = null;
let currentPage = null;

const els = {
  pdfInput: document.getElementById('pdfInput'),
  uploadBtn: document.getElementById('uploadBtn'),
  bookSelect: document.getElementById('bookSelect'),
  loadBookBtn: document.getElementById('loadBookBtn'),
  pagesPanel: document.getElementById('pagesPanel'),
  pagePreview: document.getElementById('pagePreview'),
  pageTitle: document.getElementById('pageTitle'),
  planBtn: document.getElementById('planBtn'),
  lessonsBtn: document.getElementById('lessonsBtn'),
  results: document.getElementById('results'),
};

async function api(path, options = {}) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, s => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[s]));
}

async function loadBooks() {
  const books = await api('/api/books');
  els.bookSelect.innerHTML = '';
  for (const b of books) {
    const opt = document.createElement('option');
    opt.value = b.book_id;
    opt.textContent = `${b.name} (${b.pages_count} стр.)`;
    els.bookSelect.appendChild(opt);
  }
}

function renderPages(meta) {
  els.pagesPanel.innerHTML = '';
  meta.pages.forEach(p => {
    const card = document.createElement('div');
    card.className = 'page-thumb';
    card.dataset.page = p.page;
    card.innerHTML = `
      <img src="${p.image}" loading="lazy" />
      <div class="row"><b>Стр. ${p.page}</b><span id="state-${p.page}"></span></div>
    `;
    card.onclick = () => selectPage(meta.book_id, p.page, p.image, card);
    els.pagesPanel.appendChild(card);
  });
}

async function refreshPageState() {
  if (!currentBook || !currentPage) return;
  const state = await api(`/api/page-state/${currentBook}/${currentPage}`);

  let html = '';
  if (state.plan) {
    html += `<div class="doc-link"><a target="_blank" href="/api/files/${currentBook}/${currentPage}/plan">План (markdown)</a></div>`;
  }
  if (state.lessons.length) {
    html += '<details class="doc-link"><summary>Уроки</summary><ul>';
    for (const l of state.lessons) {
      html += `<li><a target="_blank" href="${l.path}">Урок ${l.lesson}</a></li>`;
    }
    html += '</ul></details>';
  }
  els.results.innerHTML = html || '<em>Для этой страницы пока ничего не создано.</em>';

  const stateEl = document.getElementById(`state-${currentPage}`);
  if (stateEl) {
    stateEl.textContent = `${state.plan ? '📘' : ''}${state.lessons.length ? ` 🎓${state.lessons.length}` : ''}`;
  }
}

async function selectPage(bookId, page, image, card) {
  currentBook = bookId;
  currentPage = page;

  document.querySelectorAll('.page-thumb').forEach(c => c.classList.remove('active'));
  card.classList.add('active');

  els.pagePreview.src = image;
  els.pageTitle.textContent = `Книга ${bookId}, страница ${page}`;
  els.planBtn.disabled = false;
  els.lessonsBtn.disabled = false;

  await refreshPageState();
}

els.uploadBtn.onclick = async () => {
  const file = els.pdfInput.files[0];
  if (!file) return alert('Выберите PDF');
  const fd = new FormData();
  fd.append('file', file);

  els.uploadBtn.disabled = true;
  try {
    const meta = await api('/api/upload', { method: 'POST', body: fd });
    await loadBooks();
    renderPages(meta);
    currentBook = meta.book_id;
    alert('Книга загружена');
  } catch (e) {
    alert('Ошибка: ' + e.message);
  } finally {
    els.uploadBtn.disabled = false;
  }
};

els.loadBookBtn.onclick = async () => {
  const id = els.bookSelect.value;
  if (!id) return;
  const meta = await api(`/api/books/${id}`);
  currentBook = id;
  renderPages(meta);
};

els.planBtn.onclick = async () => {
  if (!currentBook || !currentPage) return;
  els.planBtn.disabled = true;
  try {
    const res = await api('/api/generate-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ book_id: currentBook, page: currentPage }),
    });
    els.results.innerHTML = `<div class="doc-link"><a target="_blank" href="${res.plan_path}">План (markdown)</a></div><pre>${escapeHtml(res.preview)}</pre>`;
    await refreshPageState();
  } catch (e) {
    alert('Ошибка генерации плана: ' + e.message);
  } finally {
    els.planBtn.disabled = false;
  }
};

els.lessonsBtn.onclick = async () => {
  if (!currentBook || !currentPage) return;
  els.lessonsBtn.disabled = true;
  try {
    await api('/api/generate-lessons', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ book_id: currentBook, page: currentPage }),
    });
    await refreshPageState();
  } catch (e) {
    alert('Ошибка генерации уроков: ' + e.message);
  } finally {
    els.lessonsBtn.disabled = false;
  }
};

loadBooks().catch(console.error);
