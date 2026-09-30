"""No later success may hide a failed native regression command."""
import contextlib
import io
import subprocess
import unittest
from unittest.mock import patch

import process_embedding


class ProcessEmbeddingRunner(unittest.TestCase):
    def test_first_middle_and_last_failures_propagate_without_later_commands(self):
        for failed_at in (0, len(process_embedding.TARGETS) // 2,
                          len(process_embedding.TARGETS) - 1):
            with self.subTest(failed_at=failed_at):
                seen = []

                def run(command, *, check):
                    self.assertTrue(check)
                    seen.append(command)
                    if len(seen) == failed_at + 1:
                        raise subprocess.CalledProcessError(23, command)
                    return subprocess.CompletedProcess(command, 0)

                with patch.object(process_embedding.subprocess, "run", side_effect=run), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(process_embedding.main(), 23)
                self.assertEqual(len(seen), failed_at + 1)

    def test_success_runs_every_declared_target(self):
        with patch.object(process_embedding.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(process_embedding.main(), 0)
        self.assertEqual(run.call_count, len(process_embedding.TARGETS))
        self.assertEqual([call.args[0][-2:] for call in run.call_args_list],
                         [list(target) for target in process_embedding.TARGETS])


if __name__ == "__main__":
    unittest.main()
