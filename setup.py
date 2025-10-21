"""
Setup script for the AI-powered IDS/IPS system.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text(encoding="utf-8").strip().split('\n')
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith('#')]

setup(
    name="ai-ids-ips",
    version="1.0.0",
    description="AI-powered Intrusion Detection and Prevention System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="AI Security Team",
    author_email="security@example.com",
    url="https://github.com/your-org/ai-ids-ips",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.1",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.4.1",
            "pre-commit>=3.3.3",
        ],
        "ml": [
            "torch>=2.0.1",
            "tensorflow>=2.13.0",
            "onnx>=1.14.0",
            "onnxruntime>=1.15.1",
        ],
        "monitoring": [
            "prometheus-client>=0.17.1",
            "grafana-api>=1.0.3",
            "influxdb-client>=1.36.1",
        ]
    },
    entry_points={
        "console_scripts": [
            "ai-ids-ips=src.main:main",
            "ai-ids-ips-train=src.training.train_models:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="security, intrusion-detection, machine-learning, network-security, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/your-org/ai-ids-ips/issues",
        "Source": "https://github.com/your-org/ai-ids-ips",
        "Documentation": "https://github.com/your-org/ai-ids-ips/docs",
    },
)
