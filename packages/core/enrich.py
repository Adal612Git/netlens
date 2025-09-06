"""
Utilidades de enriquecimiento para dominios/hosts.

- get_whois(domain): usa python-whois
- get_geoip(ip): usa ipwhois (RDAP)
- get_tls_info(host, port): obtiene información básica del certificado TLS
- get_dns_records(domain): consulta registros A, AAAA, MX, TXT con dnspython

Todas las funciones capturan errores y devuelven un dict con clave
"error" en caso de fallo.
"""

from __future__ import annotations

from datetime import datetime
import socket
import ssl
from typing import Any, Dict, List


def _safe_str_date(value: Any) -> str | None:
    """Normaliza fechas de librerías (pueden ser listas o datetime) a str ISO.

    - Si es lista, toma el primer elemento no nulo.
    - Si es datetime, formatea en ISO 8601.
    - Si es str, lo devuelve tal cual.
    - Si no hay valor, devuelve None.
    """

    if value is None:
        return None
    if isinstance(value, list):
        # python-whois puede devolver listas
        value = next((v for v in value if v), None)
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def get_whois(domain: str) -> Dict[str, Any]:
    """Obtiene información WHOIS básica usando python-whois.

    Devuelve:
    {
      "registrar": str | None,
      "creation_date": str | None,
      "expiration_date": str | None
    }

    En caso de error: {"error": str}
    """

    try:
        try:
            import whois  # type: ignore
        except Exception as ie:  # ImportError u otros
            return {"error": f"Dependencia no disponible: whois: {ie}"}

        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(3.0)
            data = whois.whois(domain)
        finally:
            socket.setdefaulttimeout(prev_timeout)
        registrar = getattr(data, "registrar", None) or data.get("registrar")
        creation = getattr(data, "creation_date", None) or data.get("creation_date")
        expiration = getattr(
            data, "expiration_date", None
        ) or data.get("expiration_date")

        return {
            "registrar": str(registrar) if registrar else None,
            "creation_date": _safe_str_date(creation),
            "expiration_date": _safe_str_date(expiration),
        }
    except Exception as e:
        return {"error": f"WHOIS fallo: {e}"}


def get_geoip(ip: str) -> Dict[str, Any]:
    """Obtiene país y organización para una IP usando ipwhois (RDAP).

    Devuelve: {"country": str | None, "organization": str | None}
    En caso de error: {"error": str}
    """

    try:
        try:
            from ipwhois import IPWhois  # type: ignore
        except Exception as ie:  # ImportError u otros
            return {"error": f"Dependencia no disponible: ipwhois: {ie}"}

        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(3.0)
            obj = IPWhois(ip)
            # RDAP es suficiente y más consistente; intenta métodos comunes
            result = obj.lookup_rdap(asn_methods=["whois", "http"])  # type: ignore[arg-type]
        finally:
            socket.setdefaulttimeout(prev_timeout)

        # País: prioriza network.country, luego ASN
        country = None
        try:
            country = (result.get("network") or {}).get("country")
        except Exception:
            country = None
        if not country:
            country = result.get("asn_country_code")

        # Organización: intenta network.name, luego ASN description
        organization = None
        try:
            organization = (result.get("network") or {}).get("name")
        except Exception:
            organization = None
        if not organization:
            organization = result.get("asn_description")

        return {"country": country, "organization": organization}
    except Exception as e:
        return {"error": f"GeoIP fallo: {e}"}


def get_tls_info(host: str, port: int = 443) -> Dict[str, Any]:
    """Conecta al host:port y devuelve issuer y notAfter del certificado.

    Maneja certificados vencidos (SSLCertVerificationError) retornando un error
    descriptivo. No realiza verificación avanzada más allá de la conexión TLS
    estándar.
    """

    def _extract_cert_fields(cert_dict: Dict[str, Any]) -> Dict[str, Any]:
        issuer_rdn = cert_dict.get("issuer")
        # issuer viene como lista de tuplas ((('commonName', 'X'),), ...)
        issuer_parts: List[str] = []
        if isinstance(issuer_rdn, (list, tuple)):
            for rdn in issuer_rdn:
                # rdn es una tupla de pares (k, v)
                if isinstance(rdn, (list, tuple)) and rdn:
                    k, v = rdn[0]
                    issuer_parts.append(f"{k}={v}")
        issuer = ", ".join(issuer_parts) if issuer_parts else None
        not_after = cert_dict.get("notAfter")
        return {"issuer": issuer, "notAfter": not_after}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return _extract_cert_fields(cert)
    except ssl.SSLCertVerificationError as ve:
        # Certificado inválido o vencido; distinguir si es expirado si es posible
        msg = str(ve).lower()
        if "expired" in msg or "has expired" in msg:
            return {"error": "TLS certificado expirado"}
        return {"error": f"TLS verificación falló: {ve}"}
    except Exception as e:
        # Intento de obtener info sin verificar como fallback informativo
        try:
            unverified = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=3) as sock:
                with unverified.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info = _extract_cert_fields(cert)
                    # Marcar que no se verificó el certificado
                    info["unverified"] = True
                    return info
        except Exception:
            return {"error": f"TLS fallo: {e}"}


def get_dns_records(domain: str) -> Dict[str, Any]:
    """Consulta registros DNS A, AAAA, MX y TXT usando dnspython.

    Devuelve un dict con las claves "A", "AAAA", "MX", "TXT", cada una con
    una lista de strings. En caso de error global, devuelve {"error": str}.
    """

    try:
        try:
            import dns.resolver  # type: ignore
        except Exception as ie:
            return {"error": f"Dependencia no disponible: dnspython: {ie}"}

        records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "TXT": []}

        # Resolver con timeouts bajos para CI
        resolver = dns.resolver.Resolver()  # type: ignore[attr-defined]
        try:
            resolver.lifetime = 2.0  # type: ignore[attr-defined]
            resolver.timeout = 2.0  # type: ignore[attr-defined]
        except Exception:
            pass

        def query(qtype: str) -> List[str]:
            try:
                answers = resolver.resolve(domain, qtype)  # type: ignore[attr-defined]
                out: List[str] = []
                for rdata in answers:
                    if qtype in ("A", "AAAA"):
                        out.append(rdata.to_text())
                    elif qtype == "MX":
                        out.append(rdata.exchange.to_text())
                    elif qtype == "TXT":
                        # Normaliza a texto simple; to_text incluye comillas
                        txt = rdata.to_text()
                        if txt.startswith('"') and txt.endswith('"'):
                            txt = txt[1:-1]
                        out.append(txt)
                return out
            except Exception:
                return []

        for t in ("A", "AAAA", "MX", "TXT"):
            records[t] = query(t)

        return records
    except Exception as e:
        return {"error": f"DNS fallo: {e}"}
