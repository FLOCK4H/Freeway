"""
    This file installs Freeway - making it available directly from the command line:
    'sudo Freeway'

    To uninstall Freeway run:
    'sudo pip uninstall 3way'
"""

from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import shutil

class PostInstallCommand(install):
    """Post-installation for installation."""
    def run(self):
        install.run(self)
        main_dir = '/usr/local/share/3way'
        if not os.path.exists(main_dir):
            os.makedirs(main_dir)
        source = 'FreewayTools/lists/ssid_list.txt'
        destination = os.path.join(main_dir, "lists")
        if not os.path.exists(destination):
            os.makedirs(destination)
        if not os.path.exists(os.path.join(destination, "ssid_list.txt")):
            shutil.copy(source, os.path.join(destination, 'ssid_list.txt'))
        source = 'templates'
        destination = os.path.join(main_dir, source)
        if not os.path.exists(destination):
            os.makedirs(destination)
        for template in ["google", "Valentines", "mrhacker", "mcd"]:
            if not os.path.exists(os.path.join(destination, template)):
                shutil.copytree(f"{source}/{template}", f"{destination}/{template}")

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='3way',
    version='1.3.0',
    author='FLOCK4H',
    url='https://github.com/FLOCK4H/Freeway',
    description='Freeway for network pentesting',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(),
    install_requires=["scapy", "rich"],

    scripts=['Freeway'],
    cmdclass={
        'install': PostInstallCommand,
    }
)
