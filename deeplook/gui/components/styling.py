"""CSS overrides and theming for DeepLook GUI."""

DARK_THEME_CSS = """
<style>
    /* Entity type colors */
    .stMarkdown code {
        background-color: #1e1e1e;
        padding: 2px 6px;
        border-radius: 4px;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #0e1117;
    }

    /* Table styling */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }

    /* Button styling */
    .stButton > button {
        border-radius: 6px;
        border: 1px solid #333;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 6px 6px 0 0;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #1e1e1e;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #333;
    }

    /* Expander styling */
    .streamlit-expanderHeader {
        font-weight: 600;
    }
</style>
"""

ENTITY_TYPE_COLORS = {
    "domain": "#3b82f6",
    "ip": "#8b5cf6",
    "email": "#22c55e",
    "username": "#eab308",
    "phone": "#f97316",
    "hash": "#ef4444",
    "btc": "#f59e0b",
    "url": "#06b6d4",
    "subdomain": "#6366f1",
    "cert": "#14b8a6",
    "asn": "#a855f7",
    "org": "#ec4899",
}

RISK_LEVEL_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#3b82f6",
}

STATUS_COLORS = {
    "pass": "#22c55e",
    "warn": "#eab308",
    "fail": "#ef4444",
    "info": "#3b82f6",
}


def inject_css() -> None:
    """Inject custom CSS into the Streamlit app."""
    import streamlit as st

    st.markdown(DARK_THEME_CSS, unsafe_allow_html=True)


def get_entity_color(entity_type: str) -> str:
    """Get the color for an entity type."""
    return ENTITY_TYPE_COLORS.get(entity_type, "#6b7280")


def get_risk_color(risk_level: str) -> str:
    """Get the color for a risk level."""
    return RISK_LEVEL_COLORS.get(risk_level, "#6b7280")
