from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='scoutr',
    description='Generic full access control API for talking to a NoSQL database',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='dynamo firestore mongo nosql api rbac',
    url='https://github.com/MichaelPalmer1/scoutr',
    use_scm_version=True,
    author='3ScreenZ',
    packages=find_packages(),
    setup_requires=[
        'setuptools_scm>=3.3.3,<4.2.0'
    ],
    install_requires=[],
    extras_require={
        'dev': [
            'mypy'
        ],
        'flask': [
            'Flask-API>=2.0',
            'Flask~=2.0.0',
            'simplejson>=3.17'
        ],
        'dynamo': [
            'boto3>=1.14.37,<1.17.0',
            'botocore~=1.17.37',
            'boto3-stubs[dynamodb]'
        ],
        'firestore': [
            'google~=3.0.0',
            'firebase-admin~=4.4.0',
        ],
        'mongo': [
            'pymongo~=3.11.0'
        ],
        'docs': [
            'mkdocs',
            'mkdocs-material'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Development Status :: 5 - Production/Stable'
    ]
)
