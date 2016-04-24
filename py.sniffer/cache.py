try:
    from redis import Redis
except ImportError:
    raise ImportError("Redis not found! No caching!")

class Cache():
    def __init__(self, url=""):
        self.server = Redis(url)
        self.expiry_time = 86400

    def set(ip_array, url):
        if not self.server:
            return

        for ip in ip_array: self.server.setex(ip, url, self.expiry_time)

    def get(ip):
        if not self.server:
            return None

        return self.server.get(ip)
