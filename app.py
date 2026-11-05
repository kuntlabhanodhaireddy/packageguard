"""Person 3: Streamlit UI.

STEP 2: real checks, live log, overall risk badge, colour-coded table, per-package details.
"""
import time
from pathlib import Path

import streamlit as st

from checks import check_packages, overall_risk, parse_requirements

st.set_page_config(page_title="PackageGuard", layout="wide")
st.title("PackageGuard")
st.caption("Check your dependencies before you install them.")

COLORS = {"Danger": "#f8d7da", "Caution": "#fff3cd", "Safe": "#d4edda"}
demo_file = Path(__file__).parent / "demo" / "requirements.txt"

if "text" not in st.session_state:
    st.session_state.text = "reqeusts==2.31.0\nrequests==2.32.0\nsome-invented-lib==1.0.0"

c1, c2 = st.columns([3, 1])
with c2:
    if st.button("Load demo file") and demo_file.exists():
        st.session_state.text = demo_file.read_text()
    up = st.file_uploader("or upload requirements.txt", type=["txt"])
    if up is not None:
        st.session_state.text = up.getvalue().decode("utf-8", errors="ignore")
with c1:
    st.text_area("Packages to check (one per line, like requirements.txt)", key="text", height=170)

if st.button("Scan", type="primary"):
    packages = parse_requirements(st.session_state.text)
    if not packages:
        st.info("Paste at least one package above, then click Scan.")
    else:
        log = st.empty()
        lines = [f"> parse requirements.txt ............ {len(packages)} packages"]
        log.code("\n".join(lines))

        def on_result(r):
            lines.append(f"> {r.name}: {r.verdict} ({r.confidence}) - {r.reasons[0] if r.reasons else ''}")
            log.code("\n".join(lines))

        t0 = time.time()
        results = check_packages(packages, on_result=on_result)
        st.session_state.results = results
        st.session_state.elapsed = time.time() - t0

results = st.session_state.get("results")
if results:
    risk = overall_risk(results)
    st.markdown(
        f"<h3 style='background:{COLORS[risk]};padding:8px 14px;border-radius:6px'>"
        f"Overall risk: {risk.upper()}</h3>",
        unsafe_allow_html=True,
    )
    st.caption(f"{len(results)} packages scanned in {st.session_state.elapsed:.1f}s")

    rows = [
        {"Package": r.name, "Version": r.version, "Verdict": r.verdict,
         "Confidence": r.confidence, "Reason": r.reasons[0] if r.reasons else ""}
        for r in results
    ]
    import pandas as pd
    df = pd.DataFrame(rows)
    st.dataframe(df.style.map(lambda v: f"background-color:{COLORS[v]}" if v in COLORS else "", subset=["Verdict"]),
                 use_container_width=True, hide_index=True)

    st.subheader("Details")
    for r in results:
        with st.expander(f"{r.name} {r.version} - {r.verdict} ({r.confidence})"):
            for reason in r.reasons:
                st.write("- " + reason)
            if r.fix:
                st.info(f"Fix candidate: {r.fix} (verified in step 3)")
            st.json(r.evidence, expanded=False)
