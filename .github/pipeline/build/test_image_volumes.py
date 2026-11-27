"""Image checks for the Fargate /tmp mount (DLV-968).

On AWS Fargate the task definition mounts an empty bind volume at /tmp. ECS copies a
path's ownership and permissions from the image into that empty mount only when the
image declares the path with VOLUME; otherwise the mount is root-owned 0755 and Tomcat,
running as UID 10001, exits with "Unable to create tempDir ... /tmp/tomcat.8443.*". These
tests therefore require ``VOLUME ["/tmp"]`` owned by 10001:10001 (conventional sticky 1777 mode, so an
unparameterised local tmpfs that inherits the directory mode stays writable), reproduce the root-owned
mount failure with the real entrypoint, and confirm an owned mount gets past tempDir.

Opt in with GATEWAY_IMAGE_TEST_IMAGE=<image>; the class is skipped when it is unset.
"""
import json
import os
import subprocess
import time
import unittest

IMAGE = os.environ.get("GATEWAY_IMAGE_TEST_IMAGE")
HARDENING = ["--read-only", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
STARTUP_WAIT_SECONDS = 90


def docker(*args, timeout=60, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True, timeout=timeout, check=check)


@unittest.skipUnless(IMAGE, "set GATEWAY_IMAGE_TEST_IMAGE=<image> to run the container /tmp mount tests")
class ImageTmpVolumeTests(unittest.TestCase):
    def test_image_declares_tmp_volume_and_runs_as_lookahead_user(self):
        config = json.loads(docker("image", "inspect", IMAGE, "--format", "{{json .Config}}").stdout)
        self.assertEqual(config.get("Volumes"), {"/tmp": {}})
        self.assertEqual(config.get("User"), "10001:10001")

    def test_anonymous_tmp_volume_is_owned_by_lookahead_and_writable(self):
        probe = docker("run", "--rm", *HARDENING, "--entrypoint", "sh", IMAGE,
                       "-c", "stat -c %u:%g:%a /tmp && touch /tmp/probe", timeout=120, check=False)
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        self.assertEqual(probe.stdout.splitlines()[0], "10001:10001:1777")

    def test_root_owned_tmp_mount_reproduces_fargate_tempdir_failure(self):
        logs, exit_code = self.start_and_wait("--mount", "type=tmpfs,destination=/tmp,tmpfs-mode=0755")
        self.assertIsNotNone(exit_code, f"container still running after {STARTUP_WAIT_SECONDS}s:\n{logs}")
        self.assertNotEqual(exit_code, 0, logs)
        self.assertIn("tempdir", logs.lower(), logs)

    def test_owned_tmp_mount_gets_past_tempdir_creation(self):
        logs, _ = self.start_and_wait("--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=0700,uid=10001,gid=10001")
        self.assertNotIn("Unable to create tempDir", logs, logs)

    def start_and_wait(self, *mount_args):
        """Run the real entrypoint detached; return (logs, exit code or None if still running)."""
        container = docker("run", "--detach", *HARDENING, *mount_args,
                           "--env", "LOOKAHEAD_BIND_ADDRESS=127.0.0.1", IMAGE).stdout.strip()
        self.addCleanup(docker, "rm", "--force", "--volumes", container, check=False)
        deadline = time.monotonic() + STARTUP_WAIT_SECONDS
        exit_code = None
        while time.monotonic() < deadline:
            state = json.loads(docker("inspect", container, "--format", "{{json .State}}").stdout)
            if not state["Running"]:
                exit_code = state["ExitCode"]
                break
            time.sleep(2)
        logs = docker("logs", container, check=False)
        return logs.stdout + logs.stderr, exit_code


if __name__ == "__main__":
    unittest.main()
