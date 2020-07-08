from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='scoutr',
    description='Generic full access control API for talking to Dynamo via API Gateway',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='dynamo api rbac',
    url='https://github.com/GESkunkworks/scoutr',
    use_scm_version=True,
    author='Michael Palmer',
    packages=find_packages(),
    setup_requires=[
        'setuptools_scm~=3.3.3'
    ],
    install_requires=[
        'boto3>=1.12.39,<1.15.0'
    ],
    extras_require={
        'flask': [
            'Flask-API~=1.1',
            'Flask~=1.1.1',
            'simplejson>=3.16,<3.18'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Development Status :: 5 - Production/Stable'
    ]
)
