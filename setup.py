import os

from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="RashlyOutlaid",
    version="0.18.0",
    author="Geir Skjotskift",
    author_email="geir@underworld.no",
    description="Perform ASN Whois against shadowserver.org",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords="asn whois shadowserver",
    url="https://github.com/bunzen/RashlyOutlaid",
    packages=[
        "RashlyOutlaid",
    ],
    install_requires=["requests", "responses", "pytest", "dataclasses"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.6",
)
