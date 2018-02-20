from setuptools import setup

setup(
    name='pymsl',
    version='1.0',
    description='Python library for interacting with the Netflix MSL API',
    url='https://github.com/truedread/pymsl',
    author='truedread',
    author_email='truedread11@gmail.com',
    license='GNU GPLv3',
    packages=['pymsl'],
    install_requires=['pycryptodomex', 'requests'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Utilities'
    ]
)
