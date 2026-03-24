import unittest

from app import summarize_events


class AppStatsTests(unittest.TestCase):
    def test_summarize_events_counts(self):
        events = [
            (1, "2026-03-15 10:00:00", "WARNING", "1.1.1.1", "failed_login", "x"),
            (2, "2026-03-15 10:01:00", "ERROR", "2.2.2.2", "admin_probe", "y"),
            (3, "2026-03-15 10:02:00", "WARNING", "1.1.1.1", "failed_login", "z"),
        ]

        stats = summarize_events(events)

        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["event_type_counts"]["failed_login"], 2)
        self.assertEqual(stats["event_type_counts"]["admin_probe"], 1)
        self.assertEqual(stats["top_source_ips"][0], ("1.1.1.1", 2))

    def test_summarize_empty_events(self):
        stats = summarize_events([])
        self.assertEqual(stats["total_events"], 0)
        self.assertEqual(stats["event_type_counts"], {})
        self.assertEqual(stats["top_source_ips"], [])


if __name__ == "__main__":
    unittest.main()
