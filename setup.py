from distutils.core import setup

setup(
    name='django-fulmine',
    version='0.1.0',
    packages=[
        'fulmine',
        'fulmine.tests',
    ],
    description='Django OAuth 2.0 (RFC 6749) pluggable implementation',
    author='Davide Rizzo',
    author_email='davide@metwit.com',
    url='http://github.com/sorcio/django-fulmine',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: Security',
    ]
)
