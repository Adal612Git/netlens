import sys
from pathlib import Path


def _ensure_core_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    core_path = repo_root / "packages" / "core"
    if str(core_path) not in sys.path:
        sys.path.insert(0, str(core_path))


_ensure_core_on_path()

import pandas as pd  # type: ignore  # noqa: E402
import streamlit as st  # type: ignore  # noqa: E402
from db import get_session, init_db, Target, Probe, Result  # type: ignore  # noqa: E402


st.set_page_config(page_title="NetLens Dashboard", layout="wide")
st.title("NetLens Dashboard")
st.caption("Explora históricos de resoluciones y tendencias diarias")

# Asegurar que la DB y tablas existan y usar una ruta consistente (raíz del repo)
REPO_ROOT = Path(__file__).resolve().parents[1]
DB_URL = f"sqlite:///{REPO_ROOT / 'netlens.db'}"
try:
    init_db(DB_URL)
except Exception as e:  # noqa: BLE001
    st.warning(f"No se pudo inicializar la DB: {e}")


@st.cache_data(show_spinner=False)
def load_dataframe() -> pd.DataFrame:
    session = get_session(DB_URL)
    try:
        rows = (
            session.query(Target.name, Target.url, Result.ip, Result.port, Probe.timestamp)
            .join(Probe, Probe.target_id == Target.id)
            .join(Result, Result.probe_id == Probe.id)
            .order_by(Probe.timestamp.desc(), Result.id.desc())
            .all()
        )
        data = [
            {
                "nombre": r[0],
                "url": r[1],
                "ip": r[2],
                "puerto": r[3],
                "timestamp": pd.to_datetime(r[4]),
            }
            for r in rows
        ]
        return pd.DataFrame(data)
    finally:
        try:
            session.close()
        except Exception:
            pass


def main() -> None:
    with st.sidebar:
        st.header("Controles")
        refresh = st.button("Recargar datos")
        limit_days = st.number_input("Días a mostrar en gráfico", min_value=1, max_value=3650, value=30)

    if refresh:
        load_dataframe.clear()

    df = load_dataframe()

    if df.empty:
        st.info("No hay datos en la base de datos aún. Ejecuta resoluciones vía CLI o API para poblarla.")
        return

    # Métricas rápidas
    col1, col2, col3 = st.columns(3)
    with col1:
        total_targets = df[["nombre", "url"]].drop_duplicates().shape[0]
        st.metric("Targets", total_targets)
    with col2:
        st.metric("Resultados", len(df))
    with col3:
        st.metric("Último registro", df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S"))

    # Tabla completa
    st.subheader("Histórico de resultados")
    st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)

    # Gráfico por día
    st.subheader("Resoluciones por día")
    df_chart = df.copy()
    df_chart["date"] = df_chart["timestamp"].dt.date
    df_chart = df_chart[df_chart["timestamp"] >= (pd.Timestamp.utcnow().normalize() - pd.Timedelta(days=int(limit_days)))]
    series = df_chart.groupby("date").size()
    st.bar_chart(series, use_container_width=True)


if __name__ == "__main__":
    main()
