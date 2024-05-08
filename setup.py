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
        source = 'tools/lists/ssid_list.txt'
        destination = os.path.join(main_dir, "lists")
        if not os.path.exists(destination):
            os.makedirs(destination)
        if not os.path.exists(os.path.join(destination, "ssid_list.txt")):
            shutil.copy(source, os.path.join(destination, 'ssid_list.txt'))

setup(
    name='3way',
    version='1.0.4',
    author='FLOCK4H',
    url='github.com/FLOCK4H/Freeway',
    description='Freeway for network pentesting',
    license="MIT",
    packages=find_packages(),
    install_requires=["scapy", "rich"],
    scripts=['Freeway'],
    cmdclass={
        'install': PostInstallCommand,
    }
)
