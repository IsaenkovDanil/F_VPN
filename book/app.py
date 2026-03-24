from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

try:
    from google import genai
    from google.genai import types
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "Не найден пакет google-genai. Установите зависимости из requirements.txt"
    ) from exc

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BOOKS_DIR = DATA_DIR / "books"
BOOKS_DIR.mkdir(parents=True, exist_ok=True)

SYSTEM_PROMPT = (
    "Я изучаю английский сейчас читаю книгу метью Макконахи greenlights. "
    "Я буду отсылать тебе страницу а ты составь план уроков по разбору каждого предложения "
    "и каждой строчки и всех незнакомых слов, фразовых глаголов , идеом и того что ты считаешь "
    "нужным для максимального разбора, я буду писать тебе урок , а ты рассказывать. "
    "объясняй подробнее так как у меня низкий уровень"
)

MODEL_NAME = "gemini-3.1-flash-lite"
THINKING_BUDGET = int(os.getenv("GEMINI_THINKING_BUDGET", "24576"))

app = FastAPI(title="Book English Tutor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/assets", StaticFiles(directory=DATA_DIR), name="assets")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def get_client() -> genai.Client:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="Отсутствует GOOGLE_API_KEY в окружении",
        )
    return genai.Client(api_key=api_key)


def generation_config() -> types.GenerateContentConfig:
    return types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=THINKING_BUDGET),
    )


def book_path(book_id: str) -> Path:
    return BOOKS_DIR / book_id


def meta_path(book_id: str) -> Path:
    return book_path(book_id) / "meta.json"


def read_meta(book_id: str) -> dict[str, Any]:
    p = meta_path(book_id)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Книга не найдена")
    return json.loads(p.read_text(encoding="utf-8"))


def write_meta(book_id: str, payload: dict[str, Any]) -> None:
    meta_path(book_id).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def ensure_page_assets(book_id: str, pdf_path: Path) -> dict[str, Any]:
    pages_dir = book_path(book_id) / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)

    doc = fitz.open(pdf_path)
    pages: list[dict[str, Any]] = []

    for idx, page in enumerate(doc, start=1):
        pix = page.get_pixmap(matrix=fitz.Matrix(1.2, 1.2))
        img_rel = Path("books") / book_id / "pages" / f"page_{idx:04d}.png"
        img_abs = DATA_DIR / img_rel
        pix.save(img_abs)

        text = page.get_text("text")
        text_file = book_path(book_id) / f"page_{idx:04d}.txt"
        text_file.write_text(text, encoding="utf-8")

        pages.append(
            {
                "page": idx,
                "image": f"/assets/{img_rel.as_posix()}",
                "text_file": text_file.name,
            }
        )

    meta = {
        "book_id": book_id,
        "name": pdf_path.name,
        "pages_count": len(pages),
        "pages": pages,
    }
    write_meta(book_id, meta)
    return meta


def page_context(book_id: str, page_number: int) -> tuple[str, bytes]:
    meta = read_meta(book_id)
    if page_number < 1 or page_number > meta["pages_count"]:
        raise HTTPException(status_code=404, detail="Страница не найдена")

    text_file = book_path(book_id) / meta["pages"][page_number - 1]["text_file"]
    text = text_file.read_text(encoding="utf-8")

    image_rel = meta["pages"][page_number - 1]["image"].replace("/assets/", "")
    image_path = DATA_DIR / image_rel
    image_bytes = image_path.read_bytes()

    return text, image_bytes


class GenerateRequest(BaseModel):
    book_id: str
    page: int


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/upload")
async def upload_pdf(file: UploadFile = File(...)) -> dict[str, Any]:
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Нужен файл PDF")

    book_id = uuid.uuid4().hex[:10]
    folder = book_path(book_id)
    folder.mkdir(parents=True, exist_ok=True)

    pdf_path = folder / "source.pdf"
    pdf_path.write_bytes(await file.read())

    meta = ensure_page_assets(book_id, pdf_path)
    return meta


@app.get("/api/books/{book_id}")
def get_book(book_id: str) -> dict[str, Any]:
    return read_meta(book_id)


@app.get("/api/books")
def list_books() -> list[dict[str, Any]]:
    books: list[dict[str, Any]] = []
    for meta in BOOKS_DIR.glob("*/meta.json"):
        payload = json.loads(meta.read_text(encoding="utf-8"))
        books.append(
            {
                "book_id": payload["book_id"],
                "name": payload["name"],
                "pages_count": payload["pages_count"],
            }
        )
    return books


@app.get("/api/runtime-config")
def runtime_config() -> dict[str, Any]:
    return {
        "model": MODEL_NAME,
        "thinking_budget": THINKING_BUDGET,
    }


@app.post("/api/generate-plan")
def generate_plan(req: GenerateRequest) -> dict[str, str]:
    text, image = page_context(req.book_id, req.page)
    page_dir = book_path(req.book_id) / f"page_{req.page:04d}"
    page_dir.mkdir(parents=True, exist_ok=True)

    client = get_client()
    response = client.models.generate_content(
        model=MODEL_NAME,
        config=generation_config(),
        contents=[
            types.Part.from_bytes(data=image, mime_type="image/png"),
            f"Страница #{req.page}. Текст страницы:\n{text}\n\n{SYSTEM_PROMPT}",
        ],
    )

    plan_md = response.text or ""
    plan_file = page_dir / "plan.md"
    plan_file.write_text(plan_md, encoding="utf-8")

    return {
        "plan_path": f"/api/files/{req.book_id}/{req.page}/plan",
        "preview": plan_md[:500],
    }


@app.get("/api/files/{book_id}/{page}/plan")
def get_plan(book_id: str, page: int) -> FileResponse:
    file = book_path(book_id) / f"page_{page:04d}" / "plan.md"
    if not file.exists():
        raise HTTPException(status_code=404, detail="План не найден")
    return FileResponse(file)


@app.get("/api/files/{book_id}/{page}/lesson/{lesson}")
def get_lesson(book_id: str, page: int, lesson: int) -> FileResponse:
    file = book_path(book_id) / f"page_{page:04d}" / f"lesson_{lesson:02d}.md"
    if not file.exists():
        raise HTTPException(status_code=404, detail="Урок не найден")
    return FileResponse(file)


@app.post("/api/generate-lessons")
def generate_lessons(req: GenerateRequest) -> dict[str, Any]:
    text, _ = page_context(req.book_id, req.page)
    page_dir = book_path(req.book_id) / f"page_{req.page:04d}"
    plan_file = page_dir / "plan.md"
    if not plan_file.exists():
        raise HTTPException(status_code=400, detail="Сначала сгенерируйте план")

    plan = plan_file.read_text(encoding="utf-8")

    lesson_nums = [int(x) for x in re.findall(r"Урок\s*(\d+)", plan, flags=re.IGNORECASE)]
    lesson_count = max(lesson_nums) if lesson_nums else 5
    lesson_count = min(max(lesson_count, 1), 12)

    client = get_client()
    generated: list[dict[str, Any]] = []
    previous_lessons: list[str] = []

    for i in range(1, lesson_count + 1):
        memory = "\n\n".join(previous_lessons[-3:])
        prompt = (
            f"Контекст страницы #{req.page}:\n{text}\n\n"
            f"План:\n{plan}\n\n"
            f"Ранее сгенерированные уроки (для памяти стиля):\n{memory}\n\n"
            f"{SYSTEM_PROMPT}\n\n"
            f"Урок {i}"
        )

        resp = client.models.generate_content(
            model=MODEL_NAME,
            config=generation_config(),
            contents=prompt,
        )
        lesson_md = resp.text or ""
        previous_lessons.append(lesson_md)

        lesson_file = page_dir / f"lesson_{i:02d}.md"
        lesson_file.write_text(lesson_md, encoding="utf-8")
        generated.append(
            {
                "lesson": i,
                "path": f"/api/files/{req.book_id}/{req.page}/lesson/{i}",
            }
        )

    return {
        "count": lesson_count,
        "lessons": generated,
    }


@app.get("/api/page-state/{book_id}/{page}")
def page_state(book_id: str, page: int) -> dict[str, Any]:
    page_dir = book_path(book_id) / f"page_{page:04d}"
    state = {
        "plan": (page_dir / "plan.md").exists(),
        "lessons": [],
    }

    for lesson_file in sorted(page_dir.glob("lesson_*.md")):
        n = int(lesson_file.stem.split("_")[1])
        state["lessons"].append({"lesson": n, "path": f"/api/files/{book_id}/{page}/lesson/{n}"})

    return state
