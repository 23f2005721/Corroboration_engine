from flask import Flask, request, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}


def response(verdict, confidence, sources):
    return jsonify({
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sources
    })


def parse_time(ts):
    try:
        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )
    except Exception:
        return None


@app.route("/")
def home():
    return jsonify({"status": "ok"})


@app.route("/corroborate", methods=["POST"])
def corroborate():

    data = request.get_json(silent=True)

    # =================================================
    # 1 INVALID
    # =================================================

    if not isinstance(data, dict):
        return response("invalid", "low", [])

    claim = data.get("claim")

    if not isinstance(claim, dict):
        return response("invalid", "low", [])

    if not isinstance(claim.get("value"), str):
        return response("invalid", "low", [])

    as_of = parse_time(data.get("asOf"))

    if as_of is None:
        return response("invalid", "low", [])

    if not isinstance(data.get("stalenessDays"), (int, float)):
        return response("invalid", "low", [])

    if not isinstance(data.get("sources"), list):
        return response("invalid", "low", [])

    claim_value = claim["value"]
    staleness_days = data["stalenessDays"]

    valid_sources = []

    # =================================================
    # VALID SOURCE FILTER
    # =================================================

    for s in data["sources"]:

        if not isinstance(s, dict):
            continue

        if s.get("type") not in VALID_TYPES:
            continue

        if not isinstance(s.get("id"), str):
            continue

        if not isinstance(s.get("origin"), str):
            continue

        if not isinstance(s.get("value"), str):
            continue

        if not isinstance(s.get("observedAt"), str):
            continue

        observed = parse_time(s["observedAt"])

        if observed is None:
            continue

        delta_days = (as_of - observed).total_seconds() / 86400

        fresh = (
            delta_days >= 0 and
            delta_days <= staleness_days
        )

        valid_sources.append({
            **s,
            "_fresh": fresh
        })

    # =================================================
    # 2 CONTRADICTED
    # =================================================

    contradicting = []

    for s in valid_sources:

        if (
            s["_fresh"]
            and s.get("authoritative") is True
            and s["value"] != claim_value
        ):
            contradicting.append(s["id"])

    if contradicting:

        return response(
            "contradicted",
            "low",
            sorted(contradicting)
        )

    # =================================================
    # 3 SUPPORTED
    # =================================================

    matching = []

    for s in valid_sources:

        if s["_fresh"] and s["value"] == claim_value:
            matching.append(s)

    representatives = {}

    for s in matching:

        origin = s["origin"]

        if origin not in representatives:
            representatives[origin] = s
        else:
            if s["id"] < representatives[origin]["id"]:
                representatives[origin] = s

    reps = list(representatives.values())

    if len(reps) >= 2:

        ids = sorted([s["id"] for s in reps])

        types = {s["type"] for s in reps}

        confidence = (
            "high"
            if len(types) >= 2
            else "medium"
        )

        return response(
            "supported",
            confidence,
            ids
        )

    # =================================================
    # 4 UNVERIFIED
    # =================================================

    return response(
        "unverified",
        "low",
        []
    )


@app.errorhandler(Exception)
def handle_error(e):
    return response(
        "invalid",
        "low",
        []
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
