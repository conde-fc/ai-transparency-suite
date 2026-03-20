"""AI Transparency Suite — setup configuration."""

from setuptools import setup, find_packages
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="ai-transparency-suite",
    version="0.1.0",
    author="Fernando Conde",
    author_email="fnandofc@hotmail.com",
    description="Open-source forensic toolkit for analyzing undisclosed data collection by AI chat platforms",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/conde-fc/ai-transparency-suite",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
    entry_points={
        "console_scripts": [
            "ats-validate=capture.har_validator:main",
            "ats-telemetry=analyze.har_telemetry_counter:main",
            "ats-domains=analyze.har_domain_inventory:main",
            "ats-experiments=analyze.har_experiment_detector:main",
            "ats-pii=analyze.har_pii_scanner:main",
            "ats-incognito=analyze.har_incognito_auditor:main",
            "ats-fields=analyze.har_field_classifier:main",
        ],
    },
)
