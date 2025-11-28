#!/usr/bin/env python3
"""
Setup script for ARP Poisoning Testbed
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="arp-testbed",
    version="1.0.0",
    author="Security Research Team",
    description="ARP Poisoning Testbed: Attack, Defense, and Metrics",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/arp-testbed",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "netifaces>=0.11.0",
        "cryptography>=41.0.0",
        "matplotlib>=3.7.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "pyyaml>=6.0.0",
        "colorama>=0.4.6",
        "tqdm>=4.65.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "arp-testbed=orchestration.orchestrator:main",
            "arp-demo=demo:main",
        ],
    },
)
