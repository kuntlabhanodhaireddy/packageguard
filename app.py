"""Person 3: Streamlit UI.

STEP 1: input box, Scan button and a table of stub results.
"""
import streamlit as st

from checks import check_package, parse_requirements

st.set_page_config(page_title="PackageGuard", layout="wide")
st.title("PackageGuard")
st.caption("Check your dependencies before you install them.")

default_text = "reqeusts==2.31.0\nrequests==2.32.0\nsome-invented-lib==1.0.0"
text = st.text_area(
    "Packages to check (one per line, like requirements.txt)",
    default_text,
    height=150,
)

if st.button("Scan"):
    packages = parse_requirements(text)
    if not packages:
        st.info("Paste at least one package above, then click Scan.")
    else:
        rows = []
        for name, version in packages:
            result = check_package(name, version)
            rows.append(
                {
                    "Package": result.name,
                    "Version": result.version,
                    "Verdict": result.verdict,
                    "Confidence": result.confidence,
                    "Reason": result.reasons[0] if result.reasons else "",
                }
            )
        st.subheader("Results")
        st.dataframe(rows)
