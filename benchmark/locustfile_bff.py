import os
import urllib3
from locust import HttpUser, task, between

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USERNAME = os.getenv("BFF_TEST_USERNAME", "vinh")
PASSWORD = os.getenv("BFF_TEST_PASSWORD", "Vinh@123!")


class BffUser(HttpUser):
    """
    Mô phỏng Browser:
    - Login vào BFF bằng username/password.
    - Giữ session cookie.
    - Gọi /public và /protected qua BFF.
    - Không giữ JWT trực tiếp.
    """

    wait_time = between(0.2, 1.0)

    def on_start(self):
        self.client.verify = False

        with self.client.post(
            "/login",
            data={
                "username": USERNAME,
                "password": PASSWORD,
            },
            name="/login",
            verify=False,
            catch_response=True,
        ) as response:
            if response.status_code in (200, 302):
                response.success()
            else:
                response.failure(
                    f"Login failed: HTTP {response.status_code} {response.text[:120]}"
                )

    @task(1)
    def public_api(self):
        self.client.get(
            "/public",
            name="/public",
            verify=False,
        )

    @task(3)
    def protected_api(self):
        self.client.get(
            "/protected",
            name="/protected",
            verify=False,
        )
