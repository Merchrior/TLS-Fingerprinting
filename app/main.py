import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import List, Optional, Set

from app.models.predictor import TLSPredictor
from app.processing.extractor import process_pcap_file
from app.utils.db_handler import DatabaseManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


class TLSFingerprintPipeline:
    """
    Tek komutla çalışan kompakt sürüm.

    Yapabildikleri:
    - İsterse TShark canlı capture başlatır
    - Ring-buffer dosyalarını izler
    - TLS ClientHello -> JA3 çıkarır
    - Predictor ile karar verir
    - SQLite'a yazar
    - Dashboard'ı aynı komutla başlatabilir
    - PCAP işleme durumlarını ve sistem loglarını veritabanında tutar
    - Kayıtlı app_config ayarlarını kullanır
    """

    def __init__(
        self,
        capture_dir: str = "data/captures",
        processed_dir: str = "data/processed",
        poll_interval: Optional[int] = None,
        stable_seconds: Optional[int] = None,
        start_capture: bool = False,
        interface: Optional[str] = None,
        capture_filter: Optional[str] = None,
        ring_duration: Optional[int] = None,
        ring_files: Optional[int] = None,
        with_dashboard: bool = False,
        dashboard_port: Optional[int] = None,
        tshark_path: Optional[str] = None,
        capture_owner: str = "backend",
    ):
        self.capture_dir = Path(capture_dir)
        self.processed_dir = Path(processed_dir)
        self.start_capture = start_capture
        self.with_dashboard = with_dashboard
        self.capture_owner = capture_owner.strip().lower()

        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager()
        self.predictor = TLSPredictor(self.db)

        # Runtime ayarlarını sırayla çöz:
        # CLI > ENV > DB config > default
        self.poll_interval = self._resolve_int_setting(
            provided=poll_interval,
            env_key="POLL_INTERVAL",
            config_key="poll_interval",
            fallback=5
        )

        self.stable_seconds = self._resolve_int_setting(
            provided=stable_seconds,
            env_key="STABLE_SECONDS",
            config_key="stable_seconds",
            fallback=3
        )

        self.interface = self._resolve_string_setting(
            provided=interface,
            env_key="CAPTURE_INTERFACE",
            config_key="capture_interface",
            fallback=""
        )

        self.capture_filter = self._resolve_string_setting(
            provided=capture_filter,
            env_key="CAPTURE_FILTER",
            config_key="capture_filter",
            fallback=""
        )

        self.ring_duration = self._resolve_int_setting(
            provided=ring_duration,
            env_key="RING_DURATION",
            config_key="ring_duration",
            fallback=30
        )

        self.ring_files = self._resolve_int_setting(
            provided=ring_files,
            env_key="RING_FILES",
            config_key="ring_files",
            fallback=10
        )

        self.dashboard_port = self._resolve_int_setting(
            provided=dashboard_port,
            env_key="DASHBOARD_PORT",
            config_key="dashboard_port",
            fallback=8501
        )

        self.tshark_path = self._resolve_tshark_path(tshark_path)

        self.processed_signatures: Set[str] = set()

        self.capture_process = None
        self.dashboard_process = None

    # ---------------------------------
    # CONFIG RESOLUTION
    # ---------------------------------

    def _resolve_string_setting(
        self,
        provided: Optional[str],
        env_key: str,
        config_key: str,
        fallback: str = ""
    ) -> str:
        if provided is not None and str(provided).strip() != "":
            return str(provided).strip()

        env_value = os.environ.get(env_key)
        if env_value is not None and str(env_value).strip() != "":
            return str(env_value).strip()

        db_value = self.db.get_config(config_key)
        if db_value is not None and str(db_value).strip() != "":
            return str(db_value).strip()

        return fallback

    def _resolve_int_setting(
        self,
        provided: Optional[int],
        env_key: str,
        config_key: str,
        fallback: int
    ) -> int:
        if provided is not None:
            return int(provided)

        env_value = os.environ.get(env_key)
        if env_value is not None and str(env_value).strip() != "":
            try:
                return int(env_value)
            except ValueError:
                pass

        db_value = self.db.get_config(config_key)
        if db_value is not None and str(db_value).strip() != "":
            try:
                return int(db_value)
            except ValueError:
                pass

        return int(fallback)

    def _resolve_tshark_path(self, provided: Optional[str]) -> str:
        if provided is not None and str(provided).strip() != "":
            return str(provided).strip()

        env_value = os.environ.get("TSHARK_PATH")
        if env_value is not None and str(env_value).strip() != "":
            return str(env_value).strip()

        db_value = self.db.get_config("tshark_path")
        if db_value is not None and str(db_value).strip() != "":
            return str(db_value).strip()

        return shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"

    # ---------------------------------
    # INTERNAL LOGGING
    # ---------------------------------

    def _log_app(self, level: str, component: str, message: str) -> None:
        level_upper = level.upper()

        if level_upper == "ERROR":
            logging.error("[%s] %s", component, message)
        elif level_upper == "WARNING":
            logging.warning("[%s] %s", component, message)
        else:
            logging.info("[%s] %s", component, message)

        try:
            self.db.log_app_event(level_upper, component, message)
        except Exception as e:
            logging.warning("DB log yazılamadı: %s", e)

    def _register_pcap_file(self, file_path: Path, status: str = "detected") -> None:
        try:
            self.db.upsert_pcap_file(
                file_name=file_path.name,
                file_path=str(file_path.resolve()),
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                status=status
            )
        except Exception as e:
            logging.warning("PCAP kayıt edilemedi (%s): %s", file_path, e)

    # ---------------------------------
    # HOT APPLY / COMMAND PROCESSING
    # ---------------------------------

    def reload_capture_settings_from_db(self) -> None:
        self.interface = self._resolve_string_setting(
            provided=None,
            env_key="CAPTURE_INTERFACE",
            config_key="capture_interface",
            fallback=""
        )

        self.capture_filter = self._resolve_string_setting(
            provided=None,
            env_key="CAPTURE_FILTER",
            config_key="capture_filter",
            fallback=""
        )

        self.ring_duration = self._resolve_int_setting(
            provided=None,
            env_key="RING_DURATION",
            config_key="ring_duration",
            fallback=30
        )

        self.ring_files = self._resolve_int_setting(
            provided=None,
            env_key="RING_FILES",
            config_key="ring_files",
            fallback=10
        )

        self.poll_interval = self._resolve_int_setting(
            provided=None,
            env_key="POLL_INTERVAL",
            config_key="poll_interval",
            fallback=5
        )

        self.stable_seconds = self._resolve_int_setting(
            provided=None,
            env_key="STABLE_SECONDS",
            config_key="stable_seconds",
            fallback=3
        )

        self.tshark_path = self._resolve_tshark_path(None)

    def process_pending_commands(self) -> None:
        if self.capture_owner != "backend":
            return

        commands = self.db.get_pending_commands(limit=10)

        for command in commands:
            command_id = command["id"]
            command_name = command["command_name"]

            try:
                if command_name == "apply_capture_settings":
                    self._log_app("INFO", "system", "Komut alındı: apply_capture_settings")
                    self.reload_capture_settings_from_db()

                    # Mevcut capture varsa durdur
                    self.stop_tshark_capture()

                    # App canlı capture modunda açılmışsa yeniden başlat
                    if self.start_capture:
                        started = self.start_tshark_capture()
                        if started:
                            result_message = f"Capture yeniden başlatıldı | interface={self.interface}"
                        else:
                            result_message = "Ayarlar yüklendi fakat capture başlatılmadı: interface ayarlı değil"
                    else:
                        result_message = "Ayarlar yüklendi. Bu backend canlı capture modu olmadan çalışıyor"

                    self.db.complete_command(
                        command_id=command_id,
                        status="done",
                        result_message=result_message
                    )
                    self._log_app("INFO", "system", f"Komut tamamlandı: {result_message}")

                else:
                    result_message = f"Bilinmeyen komut: {command_name}"
                    self.db.complete_command(
                        command_id=command_id,
                        status="failed",
                        result_message=result_message
                    )
                    self._log_app("ERROR", "system", result_message)

            except Exception as e:
                self.db.complete_command(
                    command_id=command_id,
                    status="failed",
                    result_message=str(e)
                )
                self._log_app("ERROR", "system", f"Komut işlenemedi ({command_name}): {e}")

    # ---------------------------------
    # HELPERS
    # ---------------------------------

    def build_file_signature(self, file_path: Path) -> str:
        stat = file_path.stat()
        return f"{file_path.resolve()}::{stat.st_mtime_ns}::{stat.st_size}"

    @staticmethod
    def list_interfaces(tshark_path: Optional[str] = None) -> int:
        resolved_tshark = (
            tshark_path
            or os.environ.get("TSHARK_PATH")
            or shutil.which("tshark")
            or r"C:\Program Files\Wireshark\tshark.exe"
        )

        try:
            result = subprocess.run(
                [resolved_tshark, "-D"],
                capture_output=True,
                text=True,
                encoding="utf-8"
            )
        except FileNotFoundError:
            logging.error("TShark bulunamadı. Önce Wireshark/TShark kur.")
            return 1

        if result.returncode != 0:
            logging.error("Interface listesi alınamadı:\n%s", result.stderr.strip())
            return result.returncode

        print(result.stdout)
        return 0

    # ---------------------------------
    # DASHBOARD
    # ---------------------------------

    def start_dashboard(self) -> None:
        if self.dashboard_process and self.dashboard_process.poll() is None:
            return

        cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "app/ui/dashboard.py",
            "--server.port",
            str(self.dashboard_port),
            "--server.headless",
            "true"
        ]

        self._log_app("INFO", "dashboard", f"Dashboard başlatılıyor (port={self.dashboard_port})")

        try:
            self.dashboard_process = subprocess.Popen(cmd)
            time.sleep(2)

            if self.dashboard_process.poll() is None:
                self._log_app("INFO", "dashboard", "Dashboard başarıyla başlatıldı")
                try:
                    webbrowser.open(f"http://localhost:{self.dashboard_port}")
                except Exception:
                    pass
            else:
                self._log_app("ERROR", "dashboard", "Dashboard process hemen kapandı. Port dolu olabilir.")
        except Exception as e:
            self._log_app("ERROR", "dashboard", f"Dashboard başlatılamadı: {e}")
            raise

    def stop_dashboard(self) -> None:
        if self.dashboard_process and self.dashboard_process.poll() is None:
            self._log_app("INFO", "dashboard", "Dashboard kapatılıyor")
            self.dashboard_process.terminate()
            try:
                self.dashboard_process.wait(timeout=5)
            except Exception:
                self.dashboard_process.kill()

    # ---------------------------------
    # LIVE CAPTURE
    # ---------------------------------

    def start_tshark_capture(self) -> bool:
        if not self.interface:
            self._log_app(
                "WARNING",
                "capture",
                "Canlı capture başlatılmadı: capture_interface ayarlı değil. Settings ekranından interface seç."
            )
            return False

        output_file = self.capture_dir / "live_tls_capture.pcapng"

        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-w", str(output_file),
            "-b", f"duration:{self.ring_duration}",
            "-b", f"files:{self.ring_files}",
            "-Q",
        ]

        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        self._log_app(
            "INFO",
            "capture",
            f"TShark capture başlatılıyor | interface={self.interface} | ring_duration={self.ring_duration} | ring_files={self.ring_files}"
        )

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self._log_app("INFO", "capture", f"TShark çalışıyor | path={self.tshark_path}")
            return True
        except FileNotFoundError:
            self._log_app("ERROR", "capture", "TShark bulunamadı. Önce Wireshark/TShark kur.")
            raise
        except Exception as e:
            self._log_app("ERROR", "capture", f"TShark başlatılamadı: {e}")
            raise

    def stop_tshark_capture(self) -> None:
        if self.capture_process and self.capture_process.poll() is None:
            self._log_app("INFO", "capture", "TShark capture durduruluyor")
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except Exception:
                self.capture_process.kill()

    # ---------------------------------
    # FILE DISCOVERY
    # ---------------------------------

    def discover_pcap_files(self) -> List[Path]:
        candidates: List[Path] = []

        for pattern in ("*.pcap", "*.pcapng"):
            candidates.extend(self.capture_dir.glob(pattern))

        candidates = sorted(candidates, key=lambda p: p.stat().st_mtime)

        ready_files: List[Path] = []
        now = time.time()

        for file_path in candidates:
            try:
                age = now - file_path.stat().st_mtime
                file_signature = self.build_file_signature(file_path)
            except FileNotFoundError:
                continue

            if file_signature in self.processed_signatures:
                continue

            self._register_pcap_file(file_path, status="detected")

            if age >= self.stable_seconds:
                ready_files.append(file_path)

        return ready_files

    # ---------------------------------
    # PROCESSING
    # ---------------------------------

    def process_single_pcap(self, pcap_file: Path) -> int:
        resolved_path = str(pcap_file.resolve())

        self._register_pcap_file(pcap_file, status="processing")
        self.db.update_pcap_status(resolved_path, status="processing")
        self._log_app("INFO", "watcher", f"PCAP dosyası işleme alındı: {pcap_file.name}")

        try:
            self._log_app("INFO", "extractor", f"Extractor başladı: {pcap_file.name}")
            records = process_pcap_file(str(pcap_file), tshark_path=self.tshark_path)
        except Exception as e:
            self.db.update_pcap_status(
                resolved_path,
                status="error",
                records_extracted=0,
                records_logged=0,
                error_message=str(e)
            )
            self._log_app("ERROR", "extractor", f"Extractor hatası ({pcap_file.name}): {e}")
            return 0

        if not records:
            self.processed_signatures.add(self.build_file_signature(pcap_file))
            self.db.update_pcap_status(
                resolved_path,
                status="no_tls_records",
                records_extracted=0,
                records_logged=0,
                error_message=None
            )
            self._log_app("WARNING", "extractor", f"TLS ClientHello kaydı bulunamadı: {pcap_file.name}")
            return 0

        self._log_app("INFO", "extractor", f"{pcap_file.name} içinden {len(records)} kayıt çıkarıldı")

        processed_count = 0

        for record in records:
            try:
                prediction_result = self.predictor.predict(record)

                self.db.log_event(
                    src_ip=record.get("src_ip"),
                    dst_ip=record.get("dst_ip"),
                    src_port=record.get("src_port"),
                    dst_port=record.get("dst_port"),
                    tls_version=record.get("tls_version"),
                    ja3_hash=record.get("ja3_hash"),
                    ja3_string=record.get("ja3_string"),
                    prediction=prediction_result.get("prediction", "Unknown"),
                    confidence=float(prediction_result.get("confidence", 0.0)),
                    status=prediction_result.get("status", "unknown"),
                    pcap_file=str(pcap_file),
                    raw_metadata=record.get("raw_metadata"),
                )

                processed_count += 1

            except Exception as e:
                self._log_app("ERROR", "predictor", f"Record işlenemedi ({pcap_file.name}): {e}")

        self.processed_signatures.add(self.build_file_signature(pcap_file))

        self.db.update_pcap_status(
            resolved_path,
            status="processed",
            records_extracted=len(records),
            records_logged=processed_count,
            error_message=None
        )

        self._log_app(
            "INFO",
            "watcher",
            f"PCAP işlendi: {pcap_file.name} | extracted={len(records)} | logged={processed_count}"
        )

        return processed_count

    def process_existing_files_once(self) -> int:
        files = self.discover_pcap_files()

        if not files:
            self._log_app("INFO", "watcher", f"Hazır PCAP bulunamadı: {self.capture_dir.resolve()}")
            return 0

        total = 0
        for pcap_file in files:
            total += self.process_single_pcap(pcap_file)

        return total

    # ---------------------------------
    # RUN LOOP
    # ---------------------------------

    def run_forever(self) -> None:
        self._log_app("INFO", "system", "TLS Fingerprinting backend başladı")
        self._log_app("INFO", "system", f"Capture klasörü: {self.capture_dir.resolve()}")
        self._log_app("INFO", "system", f"Resolved interface: {self.interface or '(not configured)'}")
        self._log_app("INFO", "system", f"Resolved tshark path: {self.tshark_path}")
        self._log_app("INFO", "system", f"Resolved capture filter: {self.capture_filter or '(none)'}")
        self._log_app("INFO", "system", f"Capture owner: {self.capture_owner}")

        if self.with_dashboard:
            self.start_dashboard()

        if self.start_capture:
            self.start_tshark_capture()
        else:
            self._log_app("INFO", "capture", "Canlı capture kapalı. Sadece mevcut PCAP klasörü izleniyor.")

        try:
            while True:
                self.process_pending_commands()

                files = self.discover_pcap_files()

                for pcap_file in files:
                    self.process_single_pcap(pcap_file)

                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            self._log_app("WARNING", "system", "Kullanıcı tarafından durduruldu")

        finally:
            self.stop_tshark_capture()
            self.stop_dashboard()
            self._log_app("INFO", "system", "Backend kapatıldı")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-Driven TLS Fingerprinting - Compact App")

    parser.add_argument(
        "--capture-dir",
        default=os.environ.get("CAPTURE_DIR", "data/captures"),
        help="PCAP izlenecek klasör"
    )
    parser.add_argument(
        "--capture-owner",
        default=os.environ.get("CAPTURE_OWNER", "backend"),
        choices=["backend", "host"],
        help="Capture komutlarını hangi tarafın işleyeceği: backend veya host"
    )
    parser.add_argument(
        "--processed-dir",
        default=os.environ.get("PROCESSED_DIR", "data/processed"),
        help="İleride işlenmiş çıktı klasörü için ayrılmış alan"
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=None,
        help="Klasör tarama aralığı (sn)"
    )
    parser.add_argument(
        "--stable-seconds",
        type=int,
        default=None,
        help="Bir dosyanın işlenmeden önce en az kaç saniye sakin kalacağı"
    )
    parser.add_argument(
        "--start-capture",
        action="store_true",
        help="TShark canlı capture başlat"
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="TShark interface numarası veya adı"
    )
    parser.add_argument(
        "--capture-filter",
        default=None,
        help="İsteğe bağlı BPF capture filter, örn: tcp port 443"
    )
    parser.add_argument(
        "--ring-duration",
        type=int,
        default=None,
        help="Her dosyanın kaç saniyede döneceği"
    )
    parser.add_argument(
        "--ring-files",
        type=int,
        default=None,
        help="Ring buffer içindeki toplam dosya sayısı"
    )
    parser.add_argument(
        "--with-dashboard",
        action="store_true",
        help="Dashboard'ı da aynı komutla başlat"
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Streamlit portu"
    )
    parser.add_argument(
        "--tshark-path",
        default=None,
        help="tshark.exe tam yolu"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Hazır PCAP dosyalarını bir kez işle ve çık"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="TShark arayüzlerini listele ve çık"
    )

    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    if args.list_interfaces:
        raise SystemExit(TLSFingerprintPipeline.list_interfaces(args.tshark_path or None))

    pipeline = TLSFingerprintPipeline(
        capture_dir=args.capture_dir,
        processed_dir=args.processed_dir,
        poll_interval=args.poll_interval,
        stable_seconds=args.stable_seconds,
        start_capture=args.start_capture,
        interface=args.interface,
        capture_filter=args.capture_filter,
        ring_duration=args.ring_duration,
        ring_files=args.ring_files,
        with_dashboard=args.with_dashboard,
        dashboard_port=args.dashboard_port,
        tshark_path=args.tshark_path,
        capture_owner=args.capture_owner,
    )

    if args.once:
        total = pipeline.process_existing_files_once()
        logging.info("One-shot tamamlandı. Toplam logged record: %d", total)
    else:
        pipeline.run_forever()