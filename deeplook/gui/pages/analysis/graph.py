"""Interactive graph visualization page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.state import get_workspace

st.title("📊 Entity Relationship Graph")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

col1, col2 = st.columns([1, 3])
with col1:
    center = st.text_input("Center node (optional)", placeholder="example.com", key="graph_center")
    max_depth = st.slider("Max depth", 1, 5, 3, key="graph_depth")
    show_btn = st.button("Show Graph", type="primary", key="graph_show")

if show_btn or True:
    graph = ws.to_graph()
    entities = ws.all_entities()
    edges = ws.all_edges()

    if not entities:
        st.info("No entities in workspace. Run an investigation first.")
        st.stop()

    try:
        import streamlit.components.v1 as components
        from pyvis.network import Network  # type: ignore[import-untyped]

        node_colors = {
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

        net = Network(
            height="600px",
            width="100%",
            bgcolor="#0e1117",
            font_color="white",
            directed=True,
        )

        net.set_options("""
        {
            "physics": {
                "enabled": true,
                "forceAtlas2Based": {
                    "gravitationalConstant": -50,
                    "centralGravity": 0.005,
                    "springLength": 150,
                    "springConstant": 0.08
                },
                "solver": "forceAtlas2Based",
                "stabilization": {
                    "enabled": true,
                    "iterations": 100
                }
            },
            "interaction": {
                "hover": true,
                "navigationButtons": true,
                "keyboard": true
            }
        }
        """)

        entity_ids = {e.id for e in entities}

        for entity in entities:
            etype = entity.type.value if hasattr(entity.type, "value") else str(entity.type)
            color = node_colors.get(etype, "#6b7280")
            label = entity.value
            if len(label) > 30:
                label = label[:27] + "..."
            has_edge = entity.id in {e.source_id for e in edges} or entity.id in {e.target_id for e in edges}
            net.add_node(
                entity.id,
                label=label,
                title=f"{etype}: {entity.value}",
                color=color,
                size=20 if has_edge else 10,
                font={"size": 12},
            )

        for edge in edges:
            if edge.source_id not in entity_ids or edge.target_id not in entity_ids:
                continue
            rel = edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship)
            net.add_edge(
                edge.source_id,
                edge.target_id,
                label=rel[:20],
                title=rel,
                color="#555555",
                arrows="to",
            )

        html = net.generate_html()
        components.html(html, height=620, scrolling=True)

    except ImportError:
        st.error("Pyvis not installed. Run: pip install pyvis")
    except Exception as e:
        st.error(f"Graph rendering error: {e}")

    # Legend
    st.divider()
    st.subheader("Legend")

    legend_html = '<div style="display: flex; flex-wrap: wrap; gap: 12px;">'
    for etype, color in node_colors.items():
        legend_html += f"""
            <div style="display: flex; align-items: center; gap: 4px;">
                <div style="width: 12px; height: 12px; border-radius: 50%; background: {color};"></div>
                <span style="font-size: 12px;">{etype}</span>
            </div>
        """
    legend_html += "</div>"
    st.markdown(legend_html, unsafe_allow_html=True)
