"""Build and install route53d."""

from distutils.core import setup

__author__ = 'James Raftery (james@now.ie)'
__vcs_id__ = '$Id$'


setup(
    name='route53d',
    version='0.02',
    scripts=['route53d.py'],
    packages=['libroute53d'],
    url='https://code.google.com/p/route53d/',
    license='BSD',
    author='James Raftery',
    author_email='james@now.ie',
    description='route53d is a DNS frontend to the Amazon Route 53 API',
    requires=['dnspython', 'boto']
)
