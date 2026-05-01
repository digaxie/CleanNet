import logging
import os
import tempfile
import unittest

from cleannet.logging_setup import DashboardLogHandler, hash_host, setup_logging


class LoggingSetupTests(unittest.TestCase):
    def test_hash_host_hides_hosts_unless_explicitly_enabled(self):
        hidden = hash_host("example.com")

        self.assertRegex(hidden, r"^<h#[0-9a-f]{8}>$")
        self.assertEqual(hash_host("example.com", log_real_hosts=True), "example.com")
        self.assertEqual(hash_host(None), "(none)")

    def test_dashboard_handler_buffers_recent_entries(self):
        handler = DashboardLogHandler(maxlen=2)
        handler.setFormatter(logging.Formatter("%(message)s"))
        record_a = logging.LogRecord("test", logging.INFO, "", 1, "first", (), None)
        record_b = logging.LogRecord("test", logging.INFO, "", 1, "second", (), None)
        record_c = logging.LogRecord("test", logging.INFO, "", 1, "third", (), None)

        handler.emit(record_a)
        handler.emit(record_b)
        handler.emit(record_c)

        self.assertEqual(handler.get_entries_after(0), [(2, "second"), (3, "third")])
        self.assertEqual(handler.get_entries_after(2), [(3, "third")])

    def test_setup_logging_can_disable_disk_handler_and_keeps_dashboard_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            setup = setup_logging(
                tmp,
                logger_name=f"cleannet-test-{id(self)}",
                env={"DPI_BYPASS_NO_DISK_LOG": "1"},
                reset_handlers=True,
            )

            setup.logger.info("hello dashboard")
            entries = setup.dashboard_handler.get_entries_after(0)

            self.assertFalse(os.path.exists(setup.log_file))
            self.assertEqual(len(setup.logger.handlers), 1)
            self.assertIn("hello dashboard", entries[0][1])


if __name__ == "__main__":
    unittest.main()
