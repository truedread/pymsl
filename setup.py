"""Setup module"""

from setuptools import setup

with open('README.md', 'r') as fh:
    LONG_DESCRIPTION = fh.read()

setup(
    name='pymsl',
    version='1.2',
    description='Python library for interacting with the Netflix MSL API',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    url='https://github.com/truedread/pymsl',
    author='truedread',
    author_email='truedread11@gmail.com',
    license='GNU GPLv3',
    packages=['pymsl'],
    install_requires=['pycryptodomex', 'requests'],
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Utilities'
    ]
)
