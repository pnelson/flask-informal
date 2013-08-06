"""
Flask-Informal
--------------

Adds form abstraction and helpers to your Flask application.
"""

from setuptools import setup

setup(
    name="Flask-Informal",
    version="0.1.0",
    url="https://github.com/pnelson/flask-informal",
    license="BSD",
    author="Philip Nelson",
    author_email="me@pnelson.ca",
    description="Adds form abstraction and helpers to your Flask application.",
    long_description=__doc__,
    py_modules=["flask_informal"],
    zip_safe=False,
    include_package_data=True,
    platforms="any",
    install_requires=[
        "Flask"
    ],
    test_suite="tests.suite",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
