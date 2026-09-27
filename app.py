#!/usr/bin/env python3
"""
USB Unblinder web UI.  python3 app.py  ->  http://127.0.0.1:5050
Options: --port, --host, --no-notify, --poll SECONDS, --db PATH, --logs DIR
"""
import argparse
import csv
import io
import json
import os
import queue
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request

from unblinder import DEFAULT_DB, DEFAULT_LOGS, create_monitor
from unblinder.probe import libusb_status, probe


def create_app(monitor, host):
    app = Flask(__name__)
    local_names = {"127.0.0.1", "localhost", "[::1]", host}

    @app.before_request
    def guard():
        # blocks DNS-rebinding: a random website must not be able to read or trust devices
        if host not in ("0.0.0.0", "::") and request.host.rsplit(":", 1)[0] not in local_names:
            abort(403)
        # JSON-only POSTs force a CORS preflight, so other sites cannot forge them
        if request.method == "POST" and not request.is_json:
            abort(415)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status")
    def api_status():
        probe_ok, probe_msg = libusb_status()
        info = monitor.backend.info()
        return jsonify({
            **info,
            "status": monitor.status,
            "poll_interval": monitor.poll_interval,
            "capabilities": {
                "notifications": monitor.notifier.method,
                "probe": {"ok": probe_ok, "message": probe_msg},
                "screen_lock": info.get("screen_lock_detection", False),
                "logs": str(monitor.logbook.root) if monitor.logbook else None,
            },
        })

    @app.route("/api/devices")
    def api_devices():
        return jsonify(monitor.current_devices())

    @app.route("/api/known")
    def api_known():
        return jsonify(monitor.store.known_devices())

    @app.route("/api/trust", methods=["POST"])
    def api_trust():
        body = request.get_json()
        fp, trusted = body.get("fingerprint"), bool(body.get("trusted"))
        if not fp or not monitor.store.set_trusted(fp, trusted):
            return jsonify({"error": "unknown fingerprint"}), 404
        for dev in monitor.current_devices():
            if dev.get("fingerprint") == fp:
                dev["trusted"] = trusted
        monitor.emit({"type": "trust", "fingerprint": fp, "trusted": trusted}, persist=False)
        return jsonify({"ok": True})

    @app.route("/api/history")
    def api_history():
        limit = min(request.args.get("limit", 300, type=int), 5000)
        return jsonify(monitor.store.recent_events(limit, request.args.get("min_level")))

    @app.route("/api/events")
    def api_events():
        q = monitor.subscribe()

        def gen():
            try:
                yield ": connected\n\n"
                while True:
                    try:
                        ev = q.get(timeout=15)
                    except queue.Empty:
                        yield ": ping\n\n"
                        continue
                    yield f"data: {json.dumps(ev)}\n\n"
            finally:
                monitor.unsubscribe(q)

        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/probe", methods=["POST"])
    def api_probe():
        body = request.get_json()
        try:
            vid, pid = int(str(body["vid"]), 16), int(str(body["pid"]), 16)
        except (KeyError, ValueError):
            return jsonify({"error": "vid/pid must be hex, e.g. 046d"}), 400
        try:
            result = probe(vid, pid)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        if result is None:
            return jsonify({"error": "device not found through libusb"}), 404
        return jsonify(result)

    @app.route("/api/incidents")
    def api_incidents():
        return jsonify(monitor.store.incidents(min(request.args.get("limit", 200, type=int), 2000)))

    def full_report(incident_id):
        live = monitor.scanner.report(incident_id) if monitor.scanner else None
        if live:
            for _ in range(5):  # the scan thread mutates it concurrently
                try:
                    return json.loads(json.dumps(live))
                except RuntimeError:
                    continue
        summary = monitor.store.get_incident(incident_id)
        if not summary:
            abort(404)
        if summary.get("report_path") and Path(summary["report_path"]).exists():
            return json.loads(Path(summary["report_path"]).read_text(encoding="utf-8"))
        return summary

    @app.route("/api/incidents/<incident_id>")
    def api_incident(incident_id):
        return jsonify(full_report(incident_id))

    @app.route("/api/incidents/<incident_id>/report.<fmt>")
    def api_incident_file(incident_id, fmt):
        summary = monitor.store.get_incident(incident_id)
        if fmt not in ("json", "txt") or not summary or not summary.get("report_path"):
            abort(404)
        path = Path(summary["report_path"]).with_suffix("." + fmt)
        if not path.exists():
            abort(404)
        return Response(path.read_bytes(), mimetype="application/json" if fmt == "json" else "text/plain; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=usb_incident_{incident_id}.{fmt}"})

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        dev = next((d for d in monitor.current_devices() if d["id"] == request.get_json().get("device_id")), None)
        if not dev:
            return jsonify({"error": "device is not connected"}), 404
        return jsonify({"incident": monitor.scanner.start(dev, "manual")})

    @app.route("/api/export.json")
    def export_json():
        data = json.dumps(monitor.store.recent_events(100000), indent=2)
        return Response(data, mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=usb_events.json"})

    @app.route("/api/export.csv")
    def export_csv():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["time", "type", "level", "name", "vendor_id", "product_id", "serial",
                    "manufacturer", "kinds", "location", "findings"])
        for ev in monitor.store.recent_events(100000):
            d = ev["device"]
            w.writerow([ev["time"], ev["type"], ev["level"], d.get("name"), d.get("vendor_id"),
                        d.get("product_id"), d.get("serial"), d.get("manufacturer"),
                        ",".join(d.get("kinds") or []), d.get("location"),
                        " | ".join(f"{f['level']}: {f['message']}" for f in ev["findings"])])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=usb_events.csv"})

    return app


def main():
    ap = argparse.ArgumentParser(description="USB Unblinder web UI")
    ap.add_argument("--host", default="127.0.0.1")
    # 5000 is taken by macOS AirPlay Receiver
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5050)))
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--logs", default=DEFAULT_LOGS, help="log + incident report directory")
    ap.add_argument("--poll", type=float, help="poll interval in seconds")
    ap.add_argument("--no-notify", action="store_true", help="disable desktop notifications")
    a = ap.parse_args()

    monitor = create_monitor(a.db, notify=not a.no_notify, poll_interval=a.poll, logs_dir=a.logs)
    info = monitor.backend.info()
    print(f" * USB Unblinder on {info['os']} - backend: {info['backend']}")
    print(f" * Logs + incident reports: {monitor.logbook.root}")
    print(f" * Open http://{a.host}:{a.port}")
    monitor.start()
    create_app(monitor, a.host).run(host=a.host, port=a.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
