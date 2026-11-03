"""
Free, offline headline translation into English.

Uses the open-source Argos Translate models (https://www.argosopentech.com),
run directly with CTranslate2 + SentencePiece, so nothing is sent to any
translation service and no account or key is needed.

Models (~60–100 MB per language) are downloaded once and then kept in the
GitHub Actions cache, so later runs start translating straight away.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import time
import zipfile
from pathlib import Path

INDEX_URL = "https://raw.githubusercontent.com/argosopentech/argospm-index/main/index.json"
MODEL_DIR = Path(os.environ.get("SW_MODEL_DIR", Path.home() / ".cache" / "securitywatch-models"))

# Our language codes → Argos model codes
ALIASES = {"zh-TW": "zt", "zh-Hant": "zt", "zh-HK": "zt", "zh-CN": "zh", "zh-Hans": "zh",
           "pt-BR": "pt", "pt-PT": "pt", "es-419": "es", "nb": "nb", "no": "nb"}


def argos_code(lang: str) -> str:
    return ALIASES.get(lang, lang.split("-")[0].lower())


class Translator:
    def __init__(self, session, log):
        self.session, self.log = session, log
        self._index = None
        self._models: dict[str, tuple | None] = {}
        self.status: dict[str, dict] = {}      # lang → {"ok", "count", "error"}
        self.downloaded = False                 # True if any model was fetched this run

    # ── model management ───────────────────────────────────────────────────
    def index(self):
        if self._index is None:
            cache = MODEL_DIR / "index.json"
            try:
                r = self.session.get(INDEX_URL, timeout=(8, 30))
                r.raise_for_status()
                self._index = r.json()
                MODEL_DIR.mkdir(parents=True, exist_ok=True)
                cache.write_text(r.text, encoding="utf-8")
            except Exception:
                self._index = json.loads(cache.read_text()) if cache.exists() else []
        return self._index

    def _load(self, code: str):
        if code in self._models:
            return self._models[code]
        self._models[code] = None
        import ctranslate2
        import sentencepiece as spm

        folder = MODEL_DIR / f"{code}_en"
        if not (folder / ".ready").exists():
            pkg = next((p for p in self.index()
                        if p.get("from_code") == code and p.get("to_code") == "en"
                        and p.get("type", "translate") == "translate"), None)
            if not pkg:
                raise RuntimeError("no free model for this language" if self.index()
                                   else "couldn't reach the model list")
            last = None
            links = list(pkg.get("links", [])) * 3          # up to 3 tries per mirror
            for attempt, link in enumerate(links):
                if attempt:
                    time.sleep(3)
                try:
                    r = self.session.get(link, timeout=(10, 240))
                    r.raise_for_status()
                    if folder.exists():
                        shutil.rmtree(folder)
                    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                        z.extractall(folder)
                    (folder / ".ready").write_text(str(pkg.get("package_version", "")))
                    self.log(f"  downloaded {code}→en model ({len(r.content) // 1_000_000} MB)")
                    self.downloaded = True
                    last = None
                    break
                except Exception as ex:
                    last = ex
            if last:
                raise RuntimeError(f"model download failed ({type(last).__name__})")

        model_bin = next(folder.rglob("model.bin"), None)
        if not model_bin:
            raise RuntimeError("model files not found in package")
        sp = None
        cands = sorted((p for p in folder.rglob("*")
                        if p.is_file() and p.suffix in (".model", ".spm") and "stanza" not in p.parts),
                       key=lambda p: (p.name != "sentencepiece.model", len(str(p))))
        for cand in cands:
            try:
                proc = spm.SentencePieceProcessor(model_file=str(cand))
                if proc.get_piece_size() > 100:
                    sp = proc
                    break
            except Exception:
                continue
        if sp is not None:
            encode = lambda t: sp.encode(t, out_type=str)
            decode = lambda toks: sp.decode_pieces(toks).replace("\u2581", " ")
        else:
            bpe_file = next(folder.rglob("bpe.model"), None)
            if not bpe_file:
                names = ", ".join(sorted(p.name for p in folder.rglob("*") if p.is_file()))[:300]
                raise RuntimeError(f"no usable tokenizer in package ({names})")
            # Older-style packages: Moses tokenisation + BPE (same as Argos itself does)
            from sacremoses.normalize import MosesPunctNormalizer
            from sacremoses.tokenize import MosesDetokenizer, MosesTokenizer
            from apply_bpe import BPE
            mtok, mdetok, mnorm = MosesTokenizer(code), MosesDetokenizer("en"), MosesPunctNormalizer(code)
            with open(bpe_file, encoding="utf-8") as fh:
                bpe = BPE(fh)

            def encode(t):
                toks = " ".join(mtok.tokenize(mnorm.normalize(t)))
                return bpe.segment_tokens(toks.strip().split(" "))

            def decode(toks):
                return mdetok.detokenize(" ".join(toks).replace("@@ ", "").split(" "))
        threads = max(1, (os.cpu_count() or 2))
        tr = ctranslate2.Translator(str(model_bin.parent), device="cpu",
                                    inter_threads=1, intra_threads=threads)
        self._models[code] = (tr, encode, decode)
        return self._models[code]

    # ── translation ────────────────────────────────────────────────────────
    def translate(self, lang: str, texts: list[str], deadline: float) -> dict[str, str]:
        """Translate unique texts; stops at the deadline. Returns {original: english}."""
        code = argos_code(lang)
        st = self.status.setdefault(lang, {"ok": True, "count": 0, "error": ""})
        out: dict[str, str] = {}
        if code == "en" or not texts:
            return out
        if time.time() > deadline:
            st.update(error="ran out of time — will translate next run")
            return out
        try:
            model = self._load(code)
        except Exception as ex:
            st.update(ok=False, error=str(ex)[:100])
            return out
        if model is None:
            st.update(ok=False, error=st.get("error") or "model unavailable")
            return out
        tr, encode, decode = model
        batch = 48
        for i in range(0, len(texts), batch):
            if time.time() > deadline:
                st["error"] = "ran out of time — the rest will be translated next run"
                break
            chunk = texts[i:i + batch]
            try:
                toks = [encode(t[:400]) for t in chunk]
                res = tr.translate_batch(toks, beam_size=2, max_decoding_length=160,
                                         max_batch_size=batch)
                for src, r in zip(chunk, res):
                    en = decode(r.hypotheses[0]).strip()
                    if en:
                        out[src] = en
            except Exception as ex:
                st.update(ok=False, error=f"translation error: {str(ex)[:80]}")
                break
        st["count"] += len(out)
        return out
