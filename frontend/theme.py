from pathlib import Path

import streamlit as st

STYLE_PATH = Path(__file__).resolve().parent / "style.css"


def apply_theme() -> None:
    css = STYLE_PATH.read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def page_header(title: str, description: str, eyebrow: str = "ANALYSIS WORKSPACE") -> None:
    st.markdown(
        f'<div class="page-header"><div class="eyebrow">{eyebrow}</div>'
        f'<h1>{title}</h1><p>{description}</p></div>',
        unsafe_allow_html=True,
    )
