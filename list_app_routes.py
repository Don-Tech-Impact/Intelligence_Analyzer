
from src.api.main import app
import json

def print_routes():
    routes = []
    for route in app.routes:
        methods = list(route.methods) if hasattr(route, 'methods') else []
        routes.append({
            "path": route.path,
            "name": route.name,
            "methods": methods
        })
    print(json.dumps(routes, indent=2))

if __name__ == "__main__":
    print_routes()
