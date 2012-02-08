try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

setup(
    name='ndgoauthclient',
    version='0.1.0',
    description='OAuth 2.0 client',
    author='R. B. Wilkinson',
    #author_email='',
    #url='',
    install_requires=[
        "Pylons>=1.0",
        "Genshi>=0.4",
    ],
    setup_requires=["PasteScript>=1.6.3"],
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    test_suite='nose.collector',
    package_data={'ndgoauthclient': ['i18n/*/LC_MESSAGES/*.mo']},
    #message_extractors={'ndgoauthclient': [
    #        ('**.py', 'python', None),
    #        ('public/**', 'ignore', None)]},
    zip_safe=False,
    paster_plugins=['PasteScript', 'Pylons'],
    entry_points="""
    [paste.app_factory]
    main = ndgoauthclient.config.middleware:make_app

    [paste.app_install]
    main = pylons.util:PylonsInstaller
    """,
)