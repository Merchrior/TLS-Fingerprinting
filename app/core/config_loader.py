import yaml
import os

class Config:
    """Singleton configuration loader to ensure global consistency across modules."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self):
        """Loads parameters from the root config.yaml file."""
        config_path = os.path.join(os.getcwd(), "config.yaml")
        try:
            with open(config_path, "r") as f:
                self.data = yaml.safe_load(f)
        except FileNotFoundError:
            raise RuntimeError("CRITICAL: config.yaml not found in the root directory.")