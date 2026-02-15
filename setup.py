from setuptools import setup, find_packages

setup(
    name="secure-supply-chain",
    version="1.0.0",
    author="Aabishkar",
    description="PKI-based cryptographic toolkit for secure supply chain management",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/aabishkar6969/Secure-Supply-Chain-Management-System",
    packages=find_packages(),
    install_requires=[
        "flask>=2.3.0",
        "cryptography>=41.0.0",
        "click>=8.1.0",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    entry_points={
        "console_scripts": [
            "supply-chain=cli.main:cli",
        ],
    },
)